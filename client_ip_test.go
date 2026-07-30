package sokol_traefik_plugin

import (
	"net"
	"net/http/httptest"
	"testing"
)

func mustNetworks(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()
	var result []*net.IPNet
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, network)
	}
	return result
}

func TestForwardedClientIPWalksRightToLeft(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.7, 192.0.2.9, 10.0.0.4")
	ip, err := extractClientIP(request, ClientIPConfig{Strategy: "forwarded"}, mustNetworks(t, "10.0.0.0/8"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "192.0.2.9" {
		t.Fatalf("client IP = %s", got)
	}
}

func TestForwardedClientIPIgnoresSpoofedUntrustedPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "198.51.100.4:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.7")
	ip, err := extractClientIP(request, ClientIPConfig{Strategy: "forwarded"}, mustNetworks(t, "10.0.0.0/8"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "198.51.100.4" {
		t.Fatalf("client IP = %s", got)
	}
}

func TestMalformedForwardedChainFallsBackToDirectPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "[2001:db8::5]:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.7, not-an-ip")
	ip, err := extractClientIP(request, ClientIPConfig{Strategy: "forwarded"}, mustNetworks(t, "2001:db8::/32"), nil, nil)
	if err == nil {
		t.Fatal("expected malformed chain error")
	}
	if got := ip.String(); got != "2001:db8::5" {
		t.Fatalf("fallback IP = %s", got)
	}
}

func TestCloudflareAndBunnyHeadersRequireTrustedPeer(t *testing.T) {
	tests := []struct {
		name     string
		strategy ClientIPConfig
		header   string
	}{
		{
			name: "cloudflare",
			strategy: ClientIPConfig{
				Strategy: "cloudflare", CloudflareHeader: "CF-Connecting-IP",
			},
			header: "CF-Connecting-IP",
		},
		{
			name: "bunny",
			strategy: ClientIPConfig{
				Strategy: "bunny", BunnyHeader: "CDN-Real-IP",
			},
			header: "CDN-Real-IP",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "http://example.test/", nil)
			request.RemoteAddr = "10.0.0.5:1234"
			request.Header.Set(test.header, "2001:db8::9")
			provider := mustNetworks(t, "10.0.0.0/8")
			var cloudflare, bunny []*net.IPNet
			if test.strategy.Strategy == "cloudflare" {
				cloudflare = provider
			} else {
				bunny = provider
			}
			request.Header.Set("X-Forwarded-For", "192.0.2.200")
			ip, err := extractClientIP(request, test.strategy, nil, cloudflare, bunny)
			if err != nil {
				t.Fatal(err)
			}
			if got := ip.String(); got != "2001:db8::9" {
				t.Fatalf("provider IP = %s", got)
			}
			request.RemoteAddr = "198.51.100.4:1234"
			ip, err = extractClientIP(request, test.strategy, nil, cloudflare, bunny)
			if err != nil {
				t.Fatal(err)
			}
			if got := ip.String(); got != "198.51.100.4" {
				t.Fatalf("untrusted fallback IP = %s", got)
			}
		})
	}
}

func TestProviderModeWinsWhenXFFDisagreesAndNormalizesMappedIPv6(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("CF-Connecting-IP", "::ffff:203.0.113.9")
	request.Header.Set("X-Forwarded-For", "198.51.100.77")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{Strategy: "cloudflare", CloudflareHeader: "CF-Connecting-IP"},
		nil,
		mustNetworks(t, "10.0.0.0/8"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "203.0.113.9" {
		t.Fatalf("provider precedence or address normalization failed: %s", got)
	}
}

func TestMalformedProviderHeaderFallsBackToDirectPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("CDN-Real-IP", "203.0.113.1, 203.0.113.2")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{Strategy: "bunny", BunnyHeader: "CDN-Real-IP"},
		nil,
		nil,
		mustNetworks(t, "10.0.0.0/8"),
	)
	if err == nil {
		t.Fatal("expected malformed provider header error")
	}
	if got := ip.String(); got != "10.0.0.5" {
		t.Fatalf("fallback IP = %s", got)
	}
}
