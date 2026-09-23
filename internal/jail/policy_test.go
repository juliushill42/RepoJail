package jail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyTTL(t *testing.T) {
	p := DefaultPolicy()
	if _, err := p.TTL(p.MaxTTLSeconds + 1); err == nil {
		t.Fatal("expected TTL rejection")
	}
	if d, err := p.TTL(0); err != nil || d.Seconds() != float64(p.DefaultTTLSeconds) {
		t.Fatalf("default ttl: %v %v", d, err)
	}
}

func TestCommandPolicy(t *testing.T) {
	p := DefaultPolicy()
	dir := t.TempDir()
	if _, err := p.CommandAllowed("git", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CommandAllowed("curl", dir); err == nil {
		t.Fatal("curl should not be allowed")
	}
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := p.CommandAllowed("./run.sh", dir); err != nil || got != script {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestEnvRejectsDangerousKeys(t *testing.T) {
	if _, err := buildEnv(t.TempDir(), map[string]string{"LD_PRELOAD": "x"}); err == nil {
		t.Fatal("expected rejection")
	}
}
