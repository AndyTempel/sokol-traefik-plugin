package sokol_traefik_plugin

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"
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
	ip, err := extractClientIP(
		request, ClientIPConfig{Strategy: "forwarded"},
		mustNetworks(t, "10.0.0.0/8"), nil,
	)
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
	ip, err := extractClientIP(
		request, ClientIPConfig{Strategy: "forwarded"},
		mustNetworks(t, "10.0.0.0/8"), nil,
	)
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
	ip, err := extractClientIP(
		request, ClientIPConfig{Strategy: "forwarded"},
		mustNetworks(t, "2001:db8::/32"), nil,
	)
	if err == nil {
		t.Fatal("expected malformed chain error")
	}
	if got := ip.String(); got != "2001:db8::5" {
		t.Fatalf("fallback IP = %s", got)
	}
}

func testProviderStore(t *testing.T, cloudflare, bunny []string) *providerRangeStore {
	t.Helper()
	store := newProviderRangeStore(providerMaximumStaleAge)
	now := time.Now()
	if len(cloudflare) != 0 {
		store.replace("cloudflare-test", providerCloudflare, mustNetworks(t, cloudflare...), now)
	}
	if len(bunny) != 0 {
		store.replace("bunny-test", providerBunny, mustNetworks(t, bunny...), now)
	}
	return store
}

func TestSmartProviderDetectionSupportsMixedSites(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		header     string
	}{
		{
			name: "cloudflare", remoteAddr: "104.16.1.5:1234",
			header: "CF-Connecting-IP",
		},
		{
			name: "bunny", remoteAddr: "185.93.1.5:1234",
			header: "X-Real-IP",
		},
	}
	store := testProviderStore(t, []string{"104.16.0.0/13"}, []string{"185.93.0.0/16"})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "http://example.test/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set(test.header, "2001:db8::9")
			request.Header.Set("X-Forwarded-For", "192.0.2.200")
			ip, err := extractClientIP(
				request,
				ClientIPConfig{
					Strategy: "forwarded", CloudflareHeader: "CF-Connecting-IP",
					BunnyHeader: "X-Real-IP",
				},
				nil,
				store,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := ip.String(); got != "2001:db8::9" {
				t.Fatalf("provider IP = %s", got)
			}
		})
	}

	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.8")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{
			Strategy: "forwarded", CloudflareHeader: "CF-Connecting-IP",
			BunnyHeader: "X-Real-IP",
		},
		mustNetworks(t, "10.0.0.0/8"),
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "203.0.113.8" {
		t.Fatalf("ordinary forwarded site client IP = %s", got)
	}
}

func TestDetectedProviderWinsWhenXFFDisagreesAndNormalizesMappedIPv6(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "104.16.1.5:1234"
	request.Header.Set("CF-Connecting-IP", "::ffff:203.0.113.9")
	request.Header.Set("X-Forwarded-For", "198.51.100.77")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{Strategy: "forwarded", CloudflareHeader: "CF-Connecting-IP"},
		nil,
		testProviderStore(t, []string{"104.16.0.0/13"}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "203.0.113.9" {
		t.Fatalf("provider precedence or address normalization failed: %s", got)
	}
}

func TestSmartProviderDetectionBehindTrustedPangolinProxy(t *testing.T) {
	tests := []struct {
		name         string
		providerPeer string
		header       string
	}{
		{
			name: "cloudflare", providerPeer: "104.16.1.5",
			header: "CF-Connecting-IP",
		},
		{
			name: "bunny", providerPeer: "185.93.1.5",
			header: "X-Real-IP",
		},
	}
	store := testProviderStore(t, []string{"104.16.0.0/13"}, []string{"185.93.0.0/16"})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "http://example.test/", nil)
			request.RemoteAddr = "10.0.0.5:1234"
			request.Header.Set(
				"X-Forwarded-For",
				"203.0.113.200, "+test.providerPeer+", 10.0.0.4",
			)
			request.Header.Set(test.header, "203.0.113.9")
			ip, err := extractClientIP(
				request,
				ClientIPConfig{
					Strategy: "forwarded", CloudflareHeader: "CF-Connecting-IP",
					BunnyHeader: "X-Real-IP",
				},
				mustNetworks(t, "10.0.0.0/8"),
				store,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := ip.String(); got != "203.0.113.9" {
				t.Fatalf("provider client IP behind trusted proxy = %s", got)
			}
		})
	}
}

func TestBunnySourceBehindTrustedPangolinProxyIsReported(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.200, 185.93.1.5, 10.0.0.4")
	request.Header.Set("X-Real-IP", "203.0.113.9")
	ip, source, err := extractClientIPWithSource(
		request,
		ClientIPConfig{Strategy: "forwarded", BunnyHeader: "X-Real-IP"},
		mustNetworks(t, "10.0.0.0/8"),
		testProviderStore(t, nil, []string{"185.93.0.0/16"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "203.0.113.9" || source != "bunny" {
		t.Fatalf("client=%s source=%s", got, source)
	}
}

func TestProviderHeaderBehindUntrustedProxyRemainsUntrusted(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "198.51.100.4:1234"
	request.Header.Set("X-Forwarded-For", "104.16.1.5")
	request.Header.Set("CF-Connecting-IP", "203.0.113.9")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{
			Strategy: "forwarded", CloudflareHeader: "CF-Connecting-IP",
		},
		mustNetworks(t, "10.0.0.0/8"),
		testProviderStore(t, []string{"104.16.0.0/13"}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "198.51.100.4" {
		t.Fatalf("untrusted proxy granted provider-header trust to %s", got)
	}
}

func TestMalformedProviderHeaderFallsBackToDirectPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "185.93.1.5:1234"
	request.Header.Set("X-Real-IP", "203.0.113.1, 203.0.113.2")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{Strategy: "forwarded", BunnyHeader: "X-Real-IP"},
		nil,
		testProviderStore(t, nil, []string{"185.93.0.0/16"}),
	)
	if err == nil {
		t.Fatal("expected malformed provider header error")
	}
	if got := ip.String(); got != "185.93.1.5" {
		t.Fatalf("fallback IP = %s", got)
	}
}

func TestSpoofedProviderHeadersFromUnrecognizedPeerAreIgnored(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "198.51.100.4:1234"
	request.Header.Set("CF-Connecting-IP", "203.0.113.7")
	request.Header.Set("X-Real-IP", "203.0.113.8")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{
			Strategy: "forwarded", CloudflareHeader: "CF-Connecting-IP",
			BunnyHeader: "X-Real-IP",
		},
		nil,
		testProviderStore(t, []string{"104.16.0.0/13"}, []string{"185.93.0.0/16"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "198.51.100.4" {
		t.Fatalf("spoofed provider header selected %s", got)
	}
}

func TestOverlappingProviderListsFailSafelyToDirectPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "104.16.1.5:1234"
	request.Header.Set("CF-Connecting-IP", "203.0.113.7")
	request.Header.Set("X-Real-IP", "203.0.113.8")
	store := testProviderStore(t, []string{"104.16.0.0/13"}, []string{"104.16.1.5/32"})
	ip, err := extractClientIP(
		request,
		ClientIPConfig{
			Strategy: "forwarded", CloudflareHeader: "CF-Connecting-IP",
			BunnyHeader: "X-Real-IP",
		},
		nil,
		store,
	)
	if err == nil {
		t.Fatal("expected ambiguous provider error")
	}
	if got := ip.String(); got != "104.16.1.5" {
		t.Fatalf("ambiguous provider fallback IP = %s", got)
	}
}

func TestDeprecatedManualCIDRsDoNotGrantHeaderTrust(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "198.51.100.4:1234"
	request.Header.Set("CF-Connecting-IP", "203.0.113.7")
	ip, err := extractClientIP(
		request,
		ClientIPConfig{
			Strategy: "cloudflare", CloudflareHeader: "CF-Connecting-IP",
			CloudflareCIDRs: []string{"0.0.0.0/0"},
		},
		nil,
		newProviderRangeStore(providerMaximumStaleAge),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "198.51.100.4" {
		t.Fatalf("deprecated manual CIDR granted trust to %s", got)
	}
}
