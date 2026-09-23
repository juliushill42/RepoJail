package jail

import (
	"context"
	"os"
	"testing"
)

func TestCreateDestroyEmptyWorkspace(t *testing.T) {
	p := DefaultPolicy()
	m, err := NewManager(Config{Root: t.TempDir(), Policy: p, AllowDirect: true})
	if err != nil {
		t.Fatal(err)
	}
	j, err := m.Create(context.Background(), CreateRequest{TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(j.Path); err != nil {
		t.Fatal(err)
	}
	if err := m.Destroy(j.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(j.Path); !os.IsNotExist(err) {
		t.Fatalf("expected removal, got %v", err)
	}
}

func TestExecAllowlisted(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedCommands = append(p.AllowedCommands, "true")
	m, err := NewManager(Config{Root: t.TempDir(), Policy: p, AllowDirect: true})
	if err != nil {
		t.Fatal(err)
	}
	j, err := m.Create(context.Background(), CreateRequest{TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Exec(context.Background(), j.ID, ExecRequest{Argv: []string{"true"}, TimeoutSeconds: 5})
	if err != nil {
		t.Fatal(err)
	}
	if r.ExitCode != 0 {
		t.Fatalf("exit=%d", r.ExitCode)
	}
}
