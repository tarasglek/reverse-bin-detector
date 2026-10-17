package detector

import (
	"fmt"
	"net/url"
	"strings"
)

// parsePublicURL validates an origin such as https://app.example.com and
// returns it without a trailing slash, plus its hostname without the port.
func parsePublicURL(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	invalid := err != nil ||
		(u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" ||
		u.User != nil ||
		(u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != ""
	if invalid {
		return "", "", fmt.Errorf("public URL must be an origin like https://app.example.com: %q", raw)
	}
	host := strings.ToLower(u.Host)
	return u.Scheme + "://" + host, strings.ToLower(u.Hostname()), nil
}

// applyPublicURL adds REVERSE_BIN_PUBLIC_URL and REVERSE_BIN_PUBLIC_HOST to env
// from the operator-supplied publicURL. Values the app already sets win.
func applyPublicURL(env map[string]string, publicURL string) error {
	if appURL, ok := env[KeyReverseBinPublicURL]; ok {
		publicURL = appURL
	}
	if publicURL == "" {
		return nil
	}
	origin, host, err := parsePublicURL(publicURL)
	if err != nil {
		return err
	}
	if _, ok := env[KeyReverseBinPublicURL]; !ok {
		env[KeyReverseBinPublicURL] = origin
	}
	if _, ok := env[KeyReverseBinPublicHost]; !ok {
		env[KeyReverseBinPublicHost] = host
	}
	return nil
}
