package detector

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestParsePublicURL(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantURL  string
		wantHost string
	}{
		{"https://post.example.com", "https://post.example.com", "post.example.com"},
		{"https://post.example.com/", "https://post.example.com", "post.example.com"},
		{"http://localhost:9081", "http://localhost:9081", "localhost"},
		{"https://Example.COM", "https://example.com", "example.com"},
	} {
		gotURL, gotHost, err := parsePublicURL(tc.in)
		if err != nil {
			t.Fatalf("parsePublicURL(%q): %v", tc.in, err)
		}
		if gotURL != tc.wantURL || gotHost != tc.wantHost {
			t.Fatalf("parsePublicURL(%q) = %q, %q; want %q, %q", tc.in, gotURL, gotHost, tc.wantURL, tc.wantHost)
		}
	}
	for _, bad := range []string{
		"post.example.com",
		"ftp://post.example.com",
		"https://",
		"https://post.example.com/app",
		"https://post.example.com?x=1",
		"https://post.example.com#frag",
		"https://user:pass@post.example.com",
	} {
		if _, _, err := parsePublicURL(bad); err == nil {
			t.Fatalf("parsePublicURL(%q) succeeded, want error", bad)
		}
	}
}

func TestApplyPublicURL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		env       map[string]string
		publicURL string
		want      map[string]string
	}{
		{
			name:      "injects url and host",
			env:       map[string]string{},
			publicURL: "https://post.example.com",
			want:      map[string]string{KeyReverseBinPublicURL: "https://post.example.com", KeyReverseBinPublicHost: "post.example.com"},
		},
		{
			name:      "unset flag injects nothing",
			env:       map[string]string{},
			publicURL: "",
			want:      map[string]string{},
		},
		{
			name:      "app url wins and drives host",
			env:       map[string]string{KeyReverseBinPublicURL: "https://vanity.example.org"},
			publicURL: "https://post.example.com",
			want:      map[string]string{KeyReverseBinPublicURL: "https://vanity.example.org", KeyReverseBinPublicHost: "vanity.example.org"},
		},
		{
			name:      "app host wins",
			env:       map[string]string{KeyReverseBinPublicHost: "alias.example.org"},
			publicURL: "https://post.example.com",
			want:      map[string]string{KeyReverseBinPublicURL: "https://post.example.com", KeyReverseBinPublicHost: "alias.example.org"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := applyPublicURL(tc.env, tc.publicURL); err != nil {
				t.Fatalf("applyPublicURL: %v", err)
			}
			if !reflect.DeepEqual(tc.env, tc.want) {
				t.Fatalf("env = %#v, want %#v", tc.env, tc.want)
			}
		})
	}
}

func TestApplyPublicURLRejectsInvalidAppURL(t *testing.T) {
	env := map[string]string{KeyReverseBinPublicURL: "not a url"}
	if err := applyPublicURL(env, ""); err == nil {
		t.Fatal("applyPublicURL accepted invalid app REVERSE_BIN_PUBLIC_URL")
	}
}

func TestParseCLIPublicURL(t *testing.T) {
	appDir := t.TempDir()
	opts, err := parseCLIArgs([]string{"--public-url=https://post.example.com", appDir})
	if err != nil {
		t.Fatalf("parseCLIArgs: %v", err)
	}
	if opts.publicURL != "https://post.example.com" || opts.appDir != filepath.Clean(appDir) {
		t.Fatalf("opts = %#v", opts)
	}
	opts, err = parseCLIArgs([]string{"--public-url=https://post.example.com", "--as-app", appDir, "--", "true"})
	if err != nil {
		t.Fatalf("parseCLIArgs as-app: %v", err)
	}
	if opts.publicURL != "https://post.example.com" || !opts.asApp {
		t.Fatalf("as-app opts = %#v", opts)
	}
}
