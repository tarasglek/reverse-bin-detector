package detector

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestParsePublicHost(t *testing.T) {
	for in, want := range map[string]string{
		"post.example.com":    "post.example.com",
		"Post.Example.COM":    "post.example.com",
		"demo.localhost:9443": "demo.localhost:9443",
	} {
		got, err := parsePublicHost(in)
		if err != nil {
			t.Fatalf("parsePublicHost(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("parsePublicHost(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"https://post.example.com",
		"post.example.com/app",
		"post.example.com?x=1",
		"user@post.example.com",
		":9443",
		"post example.com",
	} {
		if _, err := parsePublicHost(bad); err == nil {
			t.Fatalf("parsePublicHost(%q) succeeded, want error", bad)
		}
	}
}

func TestApplyPublicHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		host string
		want map[string]string
	}{
		{"injects host", map[string]string{}, "post.example.com", map[string]string{KeyReverseBinPublicHost: "post.example.com"}},
		{"unset flag injects nothing", map[string]string{}, "", map[string]string{}},
		{"app host wins", map[string]string{KeyReverseBinPublicHost: "vanity.example.org"}, "post.example.com", map[string]string{KeyReverseBinPublicHost: "vanity.example.org"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := applyPublicHost(tc.env, tc.host); err != nil {
				t.Fatalf("applyPublicHost: %v", err)
			}
			if !reflect.DeepEqual(tc.env, tc.want) {
				t.Fatalf("env = %#v, want %#v", tc.env, tc.want)
			}
		})
	}
}

func TestApplyPublicHostRejectsInvalidAppHost(t *testing.T) {
	env := map[string]string{KeyReverseBinPublicHost: "https://post.example.com"}
	if err := applyPublicHost(env, ""); err == nil {
		t.Fatal("applyPublicHost accepted a URL as app REVERSE_BIN_PUBLIC_HOST")
	}
}

func TestParseCLIPublicHost(t *testing.T) {
	appDir := t.TempDir()
	opts, err := parseCLIArgs([]string{"--public-host=post.example.com", appDir})
	if err != nil {
		t.Fatalf("parseCLIArgs: %v", err)
	}
	if opts.publicHost != "post.example.com" || opts.appDir != filepath.Clean(appDir) {
		t.Fatalf("opts = %#v", opts)
	}
	opts, err = parseCLIArgs([]string{"--public-host=post.example.com", "--as-app", appDir, "--", "true"})
	if err != nil {
		t.Fatalf("parseCLIArgs as-app: %v", err)
	}
	if opts.publicHost != "post.example.com" || !opts.asApp {
		t.Fatalf("as-app opts = %#v", opts)
	}
	if _, err := parseCLIArgs([]string{"--public-url=https://post.example.com", appDir}); err == nil {
		t.Fatal("parseCLIArgs accepted removed --public-url flag")
	}
}
