package jail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const watermark = `":"`

type Config struct {
	Root        string
	Policy      Policy
	AllowDirect bool
}

type Manager struct {
	mu          sync.RWMutex
	root        string
	policy      Policy
	jails       map[string]Jail
	lastHash    map[string]string
	bwrap       string
	proot       string
	prefix      string
	allowDirect bool
}

type Jail struct {
	ID             string    `json:"id"`
	Path           string    `json:"path"`
	RepoURL        string    `json:"repo_url,omitempty"`
	Ref            string    `json:"ref,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	AllowNetwork   bool      `json:"allow_network"`
	Isolation      string    `json:"isolation"`
	WorkspaceBytes int64     `json:"workspace_bytes"`
	Status         string    `json:"status"`
	Watermark      string    `json:"watermark"`
}

type CreateRequest struct {
	RepoURL      string `json:"repo_url"`
	Ref          string `json:"ref"`
	TTLSeconds   int    `json:"ttl_seconds"`
	AllowNetwork *bool  `json:"allow_network,omitempty"`
}

type ExecRequest struct {
	Argv           []string          `json:"argv"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	Env            map[string]string `json:"env,omitempty"`
}

type ExecResult struct {
	JailID          string        `json:"jail_id"`
	Argv            []string      `json:"argv"`
	ExitCode        int           `json:"exit_code"`
	TimedOut        bool          `json:"timed_out"`
	Duration        time.Duration `json:"duration_ns"`
	Stdout          string        `json:"stdout"`
	Stderr          string        `json:"stderr"`
	OutputTruncated bool          `json:"output_truncated"`
	Isolation       string        `json:"isolation"`
	NetworkIsolated bool          `json:"network_isolated"`
	WorkspaceBytes  int64         `json:"workspace_bytes"`
}

type Event struct {
	Time     time.Time       `json:"time"`
	JailID   string          `json:"jail_id"`
	Type     string          `json:"type"`
	Data     json.RawMessage `json:"data"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

func NewManager(cfg Config) (*Manager, error) {
	if cfg.Root == "" {
		return nil, errors.New("root is required")
	}
	if err := cfg.Policy.Validate(); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	m := &Manager{root: root, policy: cfg.Policy, jails: make(map[string]Jail), lastHash: make(map[string]string), allowDirect: cfg.AllowDirect}
	m.bwrap = detectBwrap()
	m.proot, m.prefix = detectProot()
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Root() string { return m.root }

func (m *Manager) IsolationMode() string {
	if m.bwrap != "" {
		return "bubblewrap"
	}
	if m.proot != "" && m.prefix != "" {
		return "proot-prefix"
	}
	if m.allowDirect {
		return "direct-explicit"
	}
	return "unavailable"
}

func (m *Manager) Create(ctx context.Context, req CreateRequest) (Jail, error) {
	ttl, err := m.policy.TTL(req.TTLSeconds)
	if err != nil {
		return Jail{}, err
	}
	if strings.HasPrefix(req.RepoURL, "-") || strings.ContainsAny(req.RepoURL, "\x00\r\n") {
		return Jail{}, errors.New("invalid repo_url")
	}
	if strings.HasPrefix(req.Ref, "-") || strings.ContainsAny(req.Ref, "\x00\r\n") {
		return Jail{}, errors.New("invalid ref")
	}
	id, err := randomID(12)
	if err != nil {
		return Jail{}, err
	}
	path := filepath.Join(m.root, id)
	if err := os.Mkdir(path, 0700); err != nil {
		return Jail{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(path)
		}
	}()

	allowNetwork := m.policy.NetworkDefault
	if req.AllowNetwork != nil {
		allowNetwork = *req.AllowNetwork
	}

	if req.RepoURL != "" {
		if _, err := exec.LookPath("git"); err != nil {
			return Jail{}, errors.New("git is required to clone repositories")
		}
		cloneCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		args := []string{"clone", "--no-tags", "--", req.RepoURL, path}
		out, err := exec.CommandContext(cloneCtx, "git", args...).CombinedOutput()
		if err != nil {
			return Jail{}, fmt.Errorf("git clone failed: %s: %w", trimOutput(out, 8192), err)
		}
		if req.Ref != "" {
			out, err := exec.CommandContext(cloneCtx, "git", "-C", path, "checkout", "--detach", req.Ref).CombinedOutput()
			if err != nil {
				return Jail{}, fmt.Errorf("git checkout failed: %s: %w", trimOutput(out, 8192), err)
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(path, ".repojail", "tmp"), 0700); err != nil {
		return Jail{}, err
	}
	size, err := dirSize(path)
	if err != nil {
		return Jail{}, err
	}
	if size > m.policy.MaxWorkspaceBytes {
		return Jail{}, fmt.Errorf("initial workspace exceeds quota: %d > %d bytes", size, m.policy.MaxWorkspaceBytes)
	}
	now := time.Now().UTC()
	j := Jail{
		ID: id, Path: path, RepoURL: req.RepoURL, Ref: req.Ref,
		CreatedAt: now, ExpiresAt: now.Add(ttl), AllowNetwork: allowNetwork,
		Isolation: m.IsolationMode(), WorkspaceBytes: size, Status: "ready", Watermark: watermark,
	}
	if err := m.writeMeta(j); err != nil {
		return Jail{}, err
	}
	m.mu.Lock()
	m.jails[id] = j
	m.mu.Unlock()
	if err := m.audit(id, "created", j); err != nil {
		return Jail{}, err
	}
	cleanup = false
	return j, nil
}

func (m *Manager) List() []Jail {
	m.mu.RLock()
	out := make([]Jail, 0, len(m.jails))
	for _, j := range m.jails {
		out = append(out, j)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (m *Manager) Get(id string) (Jail, bool) {
	m.mu.RLock()
	j, ok := m.jails[id]
	m.mu.RUnlock()
	return j, ok
}

func (m *Manager) Destroy(id, reason string) error {
	if !validID(id) {
		return errors.New("invalid jail id")
	}
	m.mu.Lock()
	j, ok := m.jails[id]
	if ok {
		delete(m.jails, id)
	}
	m.mu.Unlock()
	if !ok {
		return os.ErrNotExist
	}
	_ = m.audit(id, "destroyed", map[string]string{"reason": reason})
	return os.RemoveAll(j.Path)
}

func (m *Manager) Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error) {
	j, ok := m.Get(id)
	if !ok {
		return ExecResult{}, os.ErrNotExist
	}
	if time.Now().After(j.ExpiresAt) {
		_ = m.Destroy(id, "expired-before-exec")
		return ExecResult{}, errors.New("jail expired")
	}
	if len(req.Argv) == 0 {
		return ExecResult{}, errors.New("argv is required")
	}
	if len(req.Argv) > 256 {
		return ExecResult{}, errors.New("too many arguments")
	}
	for _, a := range req.Argv {
		if strings.ContainsRune(a, '\x00') {
			return ExecResult{}, errors.New("arguments may not contain NUL")
		}
	}
	program, err := m.policy.CommandAllowed(req.Argv[0], j.Path)
	if err != nil {
		return ExecResult{}, err
	}
	timeoutSec := req.TimeoutSeconds
	if timeoutSec == 0 {
		timeoutSec = 120
	}
	if timeoutSec < 1 || timeoutSec > m.policy.MaxCommandSeconds {
		return ExecResult{}, fmt.Errorf("timeout_seconds must be between 1 and %d", m.policy.MaxCommandSeconds)
	}
	if size, err := dirSize(j.Path); err == nil && size > m.policy.MaxWorkspaceBytes {
		return ExecResult{}, fmt.Errorf("workspace quota exceeded before execution: %d > %d bytes", size, m.policy.MaxWorkspaceBytes)
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmd, networkIsolated, err := m.command(runCtx, j, program, req.Argv[1:], req.Env)
	if err != nil {
		return ExecResult{}, err
	}
	stdout := &limitedBuffer{limit: m.policy.MaxOutputBytes}
	stderr := &limitedBuffer{limit: m.policy.MaxOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	start := time.Now()
	err = cmd.Start()
	if err != nil {
		return ExecResult{}, err
	}
	waitErr := cmd.Wait()
	duration := time.Since(start)
	timedOut := errors.Is(runCtx.Err(), context.DeadlineExceeded)
	if timedOut && cmd.Process != nil && runtime.GOOS != "windows" {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		} else if timedOut {
			exitCode = 124
		} else {
			return ExecResult{}, waitErr
		}
	}
	if timedOut {
		exitCode = 124
	}
	size, sizeErr := dirSize(j.Path)
	if sizeErr != nil {
		return ExecResult{}, sizeErr
	}
	if size > m.policy.MaxWorkspaceBytes {
		stderr.Write([]byte(fmt.Sprintf("\nRepoJail quota exceeded: %d > %d bytes\n", size, m.policy.MaxWorkspaceBytes)))
	}
	result := ExecResult{
		JailID: id, Argv: req.Argv, ExitCode: exitCode, TimedOut: timedOut, Duration: duration,
		Stdout: stdout.String(), Stderr: stderr.String(), OutputTruncated: stdout.truncated || stderr.truncated,
		Isolation: j.Isolation, NetworkIsolated: networkIsolated, WorkspaceBytes: size,
	}
	m.mu.Lock()
	j.WorkspaceBytes = size
	if size > m.policy.MaxWorkspaceBytes {
		j.Status = "quota-exceeded"
	}
	m.jails[id] = j
	m.mu.Unlock()
	_ = m.writeMeta(j)
	_ = m.audit(id, "exec", result)
	return result, nil
}

func (m *Manager) command(ctx context.Context, j Jail, program string, args []string, env map[string]string) (*exec.Cmd, bool, error) {
	safeEnv, err := buildEnv(j.Path, env)
	if err != nil {
		return nil, false, err
	}
	if m.bwrap != "" {
		cmdArgs := []string{
			"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
			"--ro-bind", "/", "/", "--bind", j.Path, j.Path, "--chdir", j.Path, "--proc", "/proc", "--dev", "/dev", "--clearenv",
		}
		if !j.AllowNetwork {
			cmdArgs = append(cmdArgs, "--unshare-net")
		}
		for _, kv := range safeEnv {
			k, v, _ := strings.Cut(kv, "=")
			cmdArgs = append(cmdArgs, "--setenv", k, v)
		}
		cmdArgs = append(cmdArgs, "--", program)
		cmdArgs = append(cmdArgs, args...)
		return exec.CommandContext(ctx, m.bwrap, cmdArgs...), !j.AllowNetwork, nil
	}
	if m.proot != "" && m.prefix != "" {
		insideProgram := program
		if filepath.IsAbs(program) && strings.HasPrefix(program, j.Path+string(os.PathSeparator)) {
			rel, _ := filepath.Rel(j.Path, program)
			insideProgram = filepath.ToSlash(filepath.Join("/workspace", rel))
		}
		cmdArgs := []string{"-0", "-R", m.prefix, "-b", j.Path + ":/workspace", "-w", "/workspace", insideProgram}
		cmdArgs = append(cmdArgs, args...)
		cmd := exec.CommandContext(ctx, m.proot, cmdArgs...)
		cmd.Env = safeEnv
		return cmd, false, nil
	}
	if !m.allowDirect {
		return nil, false, errors.New("no supported isolation runtime found; install bubblewrap or Termux proot, or explicitly set REPOJAIL_ALLOW_DIRECT=1")
	}
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir = j.Path
	cmd.Env = safeEnv
	return cmd, false, nil
}

func (m *Manager) SweepExpired() int {
	now := time.Now()
	var ids []string
	m.mu.RLock()
	for id, j := range m.jails {
		if now.After(j.ExpiresAt) {
			ids = append(ids, id)
		}
	}
	m.mu.RUnlock()
	for _, id := range ids {
		_ = m.Destroy(id, "ttl-expired")
	}
	return len(ids)
}

func (m *Manager) Events(id string, limit int) ([]Event, error) {
	if !validID(id) {
		return nil, errors.New("invalid jail id")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	path := filepath.Join(m.root, id, ".repojail", "audit.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []Event
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 2*1024*1024)
	for s.Scan() {
		var e Event
		if json.Unmarshal(s.Bytes(), &e) == nil {
			events = append(events, e)
			if len(events) > limit {
				events = events[len(events)-limit:]
			}
		}
	}
	return events, s.Err()
}

func (m *Manager) load() error {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		meta := filepath.Join(m.root, e.Name(), ".repojail", "meta.json")
		b, err := os.ReadFile(meta)
		if err != nil {
			continue
		}
		var j Jail
		if json.Unmarshal(b, &j) != nil || j.ID != e.Name() {
			continue
		}
		if time.Now().After(j.ExpiresAt) {
			_ = os.RemoveAll(filepath.Join(m.root, e.Name()))
			continue
		}
		j.Isolation = m.IsolationMode()
		m.jails[j.ID] = j
		m.lastHash[j.ID] = readLastHash(filepath.Join(m.root, j.ID, ".repojail", "audit.jsonl"))
	}
	return nil
}

func (m *Manager) writeMeta(j Jail) error {
	d := filepath.Join(j.Path, ".repojail")
	if err := os.MkdirAll(d, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(d, "meta.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d, "meta.json"))
}

func (m *Manager) audit(id, eventType string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	m.mu.Lock()
	prev := m.lastHash[id]
	e := Event{Time: time.Now().UTC(), JailID: id, Type: eventType, Data: b, PrevHash: prev}
	payload := e.Time.Format(time.RFC3339Nano) + "\n" + e.JailID + "\n" + e.Type + "\n" + string(e.Data) + "\n" + e.PrevHash
	sum := sha256.Sum256([]byte(payload))
	e.Hash = hex.EncodeToString(sum[:])
	m.lastHash[id] = e.Hash
	m.mu.Unlock()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	path := filepath.Join(m.root, id, ".repojail", "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func detectBwrap() string {
	p, err := exec.LookPath("bwrap")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, "--die-with-parent", "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--", "true")
	if err := cmd.Run(); err != nil {
		return ""
	}
	return p
}

func detectProot() (string, string) {
	p, err := exec.LookPath("proot")
	if err != nil {
		return "", ""
	}
	prefix := os.Getenv("PREFIX")
	if prefix == "" {
		return "", ""
	}
	st, err := os.Stat(filepath.Join(prefix, "bin"))
	if err != nil || !st.IsDir() {
		return "", ""
	}
	return p, prefix
}

func buildEnv(workspace string, extra map[string]string) ([]string, error) {
	base := map[string]string{
		"PATH":                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":                workspace,
		"TMPDIR":              filepath.Join(workspace, ".repojail", "tmp"),
		"LANG":                "C.UTF-8",
		"LC_ALL":              "C.UTF-8",
		"GIT_TERMINAL_PROMPT": "0",
		"REPOJAIL":            "1",
	}
	if prefix := os.Getenv("PREFIX"); prefix != "" {
		base["PATH"] = filepath.Join(prefix, "bin") + ":" + filepath.Join(prefix, "bin", "applets")
		base["PREFIX"] = prefix
	}
	denied := map[string]bool{
		"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "DYLD_INSERT_LIBRARIES": true,
		"BASH_ENV": true, "ENV": true, "GIT_SSH_COMMAND": true, "SSH_ASKPASS": true,
		"PYTHONSTARTUP": true, "NODE_OPTIONS": true,
	}
	for k, v := range extra {
		if denied[k] || k == "PATH" || k == "HOME" || k == "TMPDIR" || k == "PREFIX" {
			return nil, fmt.Errorf("environment key %q is not allowed", k)
		}
		if !validEnvKey(k) || strings.ContainsRune(v, '\x00') {
			return nil, fmt.Errorf("invalid environment entry %q", k)
		}
		base[k] = v
	}
	out := make([]string, 0, len(base))
	for k, v := range base {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

func validEnvKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'A' && r <= 'Z' || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validID(id string) bool {
	if len(id) != 24 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}

type limitedBuffer struct {
	b         bytes.Buffer
	limit     int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := l.limit - l.b.Len()
	if remaining <= 0 {
		l.truncated = true
		return n, nil
	}
	if len(p) > remaining {
		_, _ = l.b.Write(p[:remaining])
		l.truncated = true
		return n, nil
	}
	_, _ = l.b.Write(p)
	return n, nil
}

func (l *limitedBuffer) String() string { return l.b.String() }

func trimOutput(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}

func readLastHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var last string
	for s.Scan() {
		last = s.Text()
	}
	if last == "" {
		return ""
	}
	var e Event
	if json.Unmarshal([]byte(last), &e) == nil {
		return e.Hash
	}
	return ""
}

func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
