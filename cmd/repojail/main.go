package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/juliushill42/RepoJail/internal/api"
	"github.com/juliushill42/RepoJail/internal/jail"
)

func main() {
	logger := log.New(os.Stderr, "repojail ", log.LstdFlags|log.LUTC)
	m, err := managerFromEnv()
	if err != nil {
		logger.Fatal(err)
	}
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		serve(logger, m)
	case "doctor":
		printJSON(map[string]any{"ok": m.IsolationMode() != "unavailable", "isolation": m.IsolationMode(), "root": m.Root()})
		if m.IsolationMode() == "unavailable" {
			os.Exit(2)
		}
	case "list":
		printJSON(m.List())
	case "create":
		create(m, os.Args[2:])
	case "destroy":
		if len(os.Args) != 3 {
			fatal("usage: repojail destroy ID")
		}
		if err := m.Destroy(os.Args[2], "cli-delete"); err != nil {
			fatal(err.Error())
		}
	case "exec":
		execJail(m, os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func managerFromEnv() (*jail.Manager, error) {
	home, _ := os.UserHomeDir()
	root := env("REPOJAIL_ROOT", filepath.Join(home, ".local", "share", "repojail", "jails"))
	policyPath := os.Getenv("REPOJAIL_POLICY")
	if policyPath == "" {
		if _, err := os.Stat("config/policy.json"); err == nil {
			policyPath = "config/policy.json"
		}
	}
	p, err := jail.LoadPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	allowDirect := os.Getenv("REPOJAIL_ALLOW_DIRECT") == "1"
	return jail.NewManager(jail.Config{Root: root, Policy: p, AllowDirect: allowDirect})
}

func serve(logger *log.Logger, m *jail.Manager) {
	addr := env("REPOJAIL_ADDR", "127.0.0.1:8791")
	token := os.Getenv("REPOJAIL_TOKEN")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := m.SweepExpired(); n > 0 {
					logger.Printf("expired=%d", n)
				}
			}
		}
	}()
	if err := api.Run(ctx, addr, api.New(m, token, logger).Handler(), logger); err != nil {
		logger.Fatal(err)
	}
}

func create(m *jail.Manager, args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	repo := fs.String("repo", "", "repository URL or local path")
	ref := fs.String("ref", "", "git ref")
	ttl := fs.Int("ttl", 1800, "TTL seconds")
	network := fs.Bool("network", false, "allow network")
	_ = fs.Parse(args)
	j, err := m.Create(context.Background(), jail.CreateRequest{RepoURL: *repo, Ref: *ref, TTLSeconds: *ttl, AllowNetwork: network})
	if err != nil {
		fatal(err.Error())
	}
	printJSON(j)
}

func execJail(m *jail.Manager, args []string) {
	if len(args) < 3 || args[1] != "--" {
		fatal("usage: repojail exec ID -- COMMAND [ARGS...]")
	}
	id := args[0]
	timeout := 300
	if v := os.Getenv("REPOJAIL_EXEC_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			timeout = n
		}
	}
	r, err := m.Exec(context.Background(), id, jail.ExecRequest{Argv: args[2:], TimeoutSeconds: timeout})
	if err != nil {
		fatal(err.Error())
	}
	printJSON(r)
	if r.ExitCode != 0 {
		os.Exit(r.ExitCode)
	}
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err.Error())
	}
	fmt.Println(string(b))
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func fatal(s string) { fmt.Fprintln(os.Stderr, "repojail:", s); os.Exit(1) }
func usage() {
	fmt.Print(strings.TrimSpace(`RepoJail

Usage:
  repojail serve
  repojail doctor
  repojail list
  repojail create [--repo URL] [--ref REF] [--ttl SEC] [--network]
  repojail exec ID -- COMMAND [ARGS...]
  repojail destroy ID
`) + "\n")
}
