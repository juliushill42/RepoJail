package jail

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Policy struct {
	AllowedCommands           []string `json:"allowed_commands"`
	AllowWorkspaceExecutables bool     `json:"allow_workspace_executables"`
	DefaultTTLSeconds         int      `json:"default_ttl_seconds"`
	MaxTTLSeconds             int      `json:"max_ttl_seconds"`
	MaxCommandSeconds         int      `json:"max_command_seconds"`
	MaxOutputBytes            int      `json:"max_output_bytes"`
	MaxWorkspaceBytes         int64    `json:"max_workspace_bytes"`
	NetworkDefault            bool     `json:"network_default"`
}

func DefaultPolicy() Policy {
	return Policy{
		AllowedCommands: []string{
			"git", "go", "cargo", "rustc", "python", "python3", "node", "npm", "npx", "pnpm", "yarn",
			"make", "cmake", "ninja", "clang", "clang++", "gcc", "g++", "javac", "java", "gradle", "bash", "sh",
			"sed", "awk", "grep", "find", "xargs", "printf", "cat", "cp", "mv", "mkdir", "rm", "touch", "tar", "gzip", "unzip",
		},
		AllowWorkspaceExecutables: true,
		DefaultTTLSeconds:         1800,
		MaxTTLSeconds:             21600,
		MaxCommandSeconds:         900,
		MaxOutputBytes:            2 * 1024 * 1024,
		MaxWorkspaceBytes:         2 * 1024 * 1024 * 1024,
		NetworkDefault:            false,
	}
}

func LoadPolicy(path string) (Policy, error) {
	p := DefaultPolicy()
	if path == "" {
		return p, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return p, nil
		}
		return Policy{}, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) Validate() error {
	if p.DefaultTTLSeconds <= 0 || p.MaxTTLSeconds <= 0 || p.DefaultTTLSeconds > p.MaxTTLSeconds {
		return errors.New("invalid TTL policy")
	}
	if p.MaxCommandSeconds <= 0 {
		return errors.New("max_command_seconds must be positive")
	}
	if p.MaxOutputBytes < 4096 {
		return errors.New("max_output_bytes must be at least 4096")
	}
	if p.MaxWorkspaceBytes < 1024*1024 {
		return errors.New("max_workspace_bytes must be at least 1 MiB")
	}
	if len(p.AllowedCommands) == 0 && !p.AllowWorkspaceExecutables {
		return errors.New("policy allows no commands")
	}
	return nil
}

func (p Policy) TTL(seconds int) (time.Duration, error) {
	if seconds == 0 {
		seconds = p.DefaultTTLSeconds
	}
	if seconds < 1 || seconds > p.MaxTTLSeconds {
		return 0, fmt.Errorf("ttl_seconds must be between 1 and %d", p.MaxTTLSeconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

func (p Policy) CommandAllowed(program, workspace string) (string, error) {
	if program == "" || strings.ContainsRune(program, '\x00') {
		return "", errors.New("invalid command")
	}
	if strings.Contains(program, "/") {
		if !p.AllowWorkspaceExecutables {
			return "", errors.New("workspace executables are disabled")
		}
		if filepath.IsAbs(program) {
			return "", errors.New("absolute executable paths are not allowed")
		}
		clean := filepath.Clean(program)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return "", errors.New("executable escapes workspace")
		}
		candidate := filepath.Join(workspace, clean)
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", fmt.Errorf("resolve executable: %w", err)
		}
		rel, err := filepath.Rel(workspace, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", errors.New("executable escapes workspace")
		}
		st, err := os.Stat(resolved)
		if err != nil {
			return "", err
		}
		if st.IsDir() || st.Mode()&0111 == 0 {
			return "", errors.New("workspace executable is not executable")
		}
		return resolved, nil
	}
	for _, allowed := range p.AllowedCommands {
		if program == allowed {
			return program, nil
		}
	}
	return "", fmt.Errorf("command %q is not allowed by policy", program)
}
