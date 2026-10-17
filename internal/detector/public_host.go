package detector

import (
	"fmt"
	"net/url"
	"strings"
)

// parsePublicHost validates a host such as app.example.com or
// app.localhost:9443 and returns it lowercased. Apps serve it as https://host.
func parsePublicHost(raw string) (string, error) {
	host := strings.ToLower(raw)
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("public host must be host[:port] like app.example.com: %q", raw)
	}
	return host, nil
}

// applyPublicHost adds REVERSE_BIN_PUBLIC_HOST to env from the
// operator-supplied publicHost. A value the app already sets wins.
func applyPublicHost(env map[string]string, publicHost string) error {
	if appHost, ok := env[KeyReverseBinPublicHost]; ok {
		_, err := parsePublicHost(appHost)
		return err
	}
	if publicHost == "" {
		return nil
	}
	host, err := parsePublicHost(publicHost)
	if err != nil {
		return err
	}
	env[KeyReverseBinPublicHost] = host
	return nil
}
