package sokol_traefik_plugin

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureDefaultsAndLocalAgentEndpointValidation(t *testing.T) {
	config := CreateConfig()
	if config.RequestBody.Enabled || config.FailureMode.ExplicitLocalDeny != "deny" ||
		config.Responses.AllowSymlinks || config.Agent.RequestTimeout != "500ms" {
		t.Fatalf("unexpected defaults: %#v", config)
	}
	for _, endpoint := range []string{
		"https://sokol.example",
		"http://agent.example.internal:8080",
		"http://8.8.8.8:8080",
		"http://user:password@localhost:8080",
		"http://localhost:8080/path",
	} {
		if err := validateAgentEndpoint(endpoint); err == nil {
			t.Fatalf("accepted non-local or malformed endpoint %q", endpoint)
		}
	}
	for _, endpoint := range []string{
		"http://sokol-edge-agent:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"unix:///run/sokol-edge/agent.sock",
	} {
		if err := validateAgentEndpoint(endpoint); err != nil {
			t.Fatalf("rejected local endpoint %q: %v", endpoint, err)
		}
	}
}

func TestDialGuardRejectsResolvedPublicAddress(t *testing.T) {
	if _, err := dialLocalAgent(
		context.Background(), &net.Dialer{}, "tcp", "8.8.8.8:80",
	); err == nil {
		t.Fatal("public resolved Agent address was accepted")
	}
}

func TestTokenFileRejectsWorldReadableAndShortValues(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 40)), 0o604); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(path); err == nil {
		t.Fatal("world-readable token was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(path); err == nil {
		t.Fatal("short token was accepted")
	}
}

func TestSensitiveHeadersCannotBeSelected(t *testing.T) {
	config := CreateConfig()
	config.Request.Headers = append(config.Request.Headers, "Authorization")
	if _, err := validateConfig(config); err == nil {
		t.Fatal("sensitive header selection was accepted")
	}
}

func TestConfigurationCollectionsAndBodyAreBounded(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{
			name: "trusted proxies",
			change: func(config *Config) {
				config.TrustedProxies = make([]string, 129)
				for index := range config.TrustedProxies {
					config.TrustedProxies[index] = "127.0.0.1/32"
				}
			},
		},
		{
			name: "request headers",
			change: func(config *Config) {
				config.Request.Headers = make([]string, 65)
				for index := range config.Request.Headers {
					config.Request.Headers[index] = "X-Sokol-Test"
				}
			},
		},
		{
			name: "request cookies",
			change: func(config *Config) {
				config.Request.Cookies = make([]string, 65)
				for index := range config.Request.Cookies {
					config.Request.Cookies[index] = "sokol_test"
				}
			},
		},
		{
			name: "body content types",
			change: func(config *Config) {
				config.RequestBody.ContentTypes = make([]string, 33)
				for index := range config.RequestBody.ContentTypes {
					config.RequestBody.ContentTypes[index] = "application/json"
				}
			},
		},
		{
			name: "body bypass paths",
			change: func(config *Config) {
				config.RequestBody.BypassPathPrefix = make([]string, 33)
				for index := range config.RequestBody.BypassPathPrefix {
					config.RequestBody.BypassPathPrefix[index] = "/upload"
				}
			},
		},
		{
			name: "body size",
			change: func(config *Config) {
				config.RequestBody.MaximumBytes = maximumBodyBytes + 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := CreateConfig()
			test.change(config)
			if _, err := validateConfig(config); err == nil {
				t.Fatal("unbounded configuration was accepted")
			}
		})
	}
}

func TestShippedSokolPagesAreBoundedAndSelfContained(t *testing.T) {
	for _, name := range []string{
		"block.html",
		"challenge.html",
		"rate-limit.html",
		"unavailable.html",
	} {
		content, err := os.ReadFile(filepath.Join("pages", name))
		if err != nil {
			t.Fatalf("read shipped page %s: %v", name, err)
		}
		if len(content) == 0 || len(content) > 512<<10 {
			t.Fatalf("shipped page %s has invalid size %d", name, len(content))
		}
		for _, expected := range [][]byte{
			[]byte("Sokol"),
			[]byte("{{SOKOL_REQUEST_ID}}"),
			[]byte("{{SOKOL_HOST}}"),
			[]byte("{{SOKOL_PATH}}"),
			[]byte("{{SOKOL_TIMESTAMP}}"),
		} {
			if !bytes.Contains(content, expected) {
				t.Fatalf("shipped page %s is missing %q", name, expected)
			}
		}
		if bytes.Contains(content, []byte("http://")) ||
			bytes.Contains(content, []byte("https://")) ||
			bytes.Contains(content, []byte("<script")) {
			t.Fatalf("shipped page %s contains an external dependency or script", name)
		}
	}
	challenge, err := os.ReadFile(filepath.Join("pages", "challenge.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(challenge, []byte("{{SOKOL_CHALLENGE_URL}}")) {
		t.Fatal("shipped challenge page is missing the challenge URL placeholder")
	}
}
