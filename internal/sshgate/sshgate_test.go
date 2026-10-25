package sshgate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func appsRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, app := range []string{"todo", "my-app.v2"} {
		if err := os.Mkdir(filepath.Join(root, app), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	return root
}

func envOf(vars map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := vars[key]
		return value, ok
	}
}

func TestIsInvocation(t *testing.T) {
	for argv0, want := range map[string]bool{
		"rb-ssh":                        true,
		"-rb-ssh":                       true,
		"/usr/lib/reverse-bin/rb-ssh":   true,
		"reverse-bin-detector":          false,
		"/usr/lib/reverse-bin/rb-ssh-x": false,
	} {
		if got := IsInvocation(argv0); got != want {
			t.Errorf("IsInvocation(%q) = %v, want %v", argv0, got, want)
		}
	}
}

func TestParseAcceptsKeyCommandForms(t *testing.T) {
	root := appsRoot(t)
	for _, argv := range [][]string{
		{"rb-ssh", "todo"},
		{"/usr/lib/reverse-bin/rb-ssh", "todo"},
		{"rb-ssh", "-c", "/usr/lib/reverse-bin/rb-ssh todo"},
		{"rb-ssh", "-c", "rb-ssh todo"},
	} {
		got, err := Parse(argv, envOf(nil), root)
		if err != nil {
			t.Fatalf("Parse(%q): %v", argv, err)
		}
		want := Request{AppDir: filepath.Join(root, "todo"), Command: []string{"bash", "-i"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Parse(%q) = %#v, want %#v", argv, got, want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	root := appsRoot(t)
	for name, argv := range map[string][]string{
		"login shell":         {"-rb-ssh"},
		"no app":              {"rb-ssh"},
		"too many args":       {"rb-ssh", "todo", "extra"},
		"client command in c": {"rb-ssh", "-c", "bash"},
		"extra words in c":    {"rb-ssh", "-c", "rb-ssh todo; bash"},
		"other binary in c":   {"rb-ssh", "-c", "/bin/sh todo"},
		"dot dot":             {"rb-ssh", ".."},
		"dot":                 {"rb-ssh", "."},
		"hidden":              {"rb-ssh", ".ssh"},
		"slash":               {"rb-ssh", "todo/data"},
		"missing app":         {"rb-ssh", "nope"},
		"not a directory":     {"rb-ssh", "file"},
		"symlink outside":     {"rb-ssh", "escape"},
	} {
		if got, err := Parse(argv, envOf(nil), root); err == nil {
			t.Errorf("%s: Parse(%q) = %#v, want error", name, argv, got)
		}
	}
}

func TestParseCommand(t *testing.T) {
	root := appsRoot(t)
	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"interactive", nil, []string{"bash", "-i"}},
		{"empty command is interactive", map[string]string{"SSH_ORIGINAL_COMMAND": ""}, []string{"bash", "-i"}},
		{"one-shot", map[string]string{"SSH_ORIGINAL_COMMAND": "deno task migrate"}, []string{"sh", "-c", "deno task migrate"}},
		{
			"terminal env passthrough",
			map[string]string{"TERM": "xterm-256color", "LANG": "C.UTF-8", "SSH_ORIGINAL_COMMAND": "ls", "HOME": "/ignored"},
			[]string{"/usr/bin/env", "TERM=xterm-256color", "LANG=C.UTF-8", "sh", "-c", "ls"},
		},
	}
	for _, tt := range tests {
		got, err := Parse([]string{"rb-ssh", "my-app.v2"}, envOf(tt.env), root)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if !reflect.DeepEqual(got.Command, tt.want) {
			t.Fatalf("%s: command = %q, want %q", tt.name, got.Command, tt.want)
		}
	}
}

func TestParseRefusesFileTransferSubsystems(t *testing.T) {
	root := appsRoot(t)
	for _, cmd := range []string{"/usr/lib/openssh/sftp-server", "internal-sftp", "/usr/lib/sftp-server -l INFO", "scp -t /app/data/x", "scp -f data/x"} {
		_, err := Parse([]string{"rb-ssh", "todo"}, envOf(map[string]string{"SSH_ORIGINAL_COMMAND": cmd}), root)
		if err == nil || !strings.Contains(err.Error(), "sftp/scp") {
			t.Fatalf("Parse with %q: error = %v, want sftp/scp refusal", cmd, err)
		}
	}
}
