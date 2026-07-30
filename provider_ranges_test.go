package sokol_traefik_plugin

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProviderSourceParsersAcceptOfficialShapes(t *testing.T) {
	plain, err := parsePlainProviderValues([]byte("104.16.0.0/13\n2606:4700::/32\n"))
	if err != nil {
		t.Fatal(err)
	}
	networks, err := parseProviderNetworks(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 ||
		!networks[0].Contains(net.ParseIP("104.16.1.1")) ||
		!networks[1].Contains(net.ParseIP("2606:4700::1")) {
		t.Fatalf("plain networks = %#v", networks)
	}

	xmlValues, err := parseXMLProviderValues([]byte(
		`<ArrayOfstring xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">` +
			`<string>185.93.1.1</string><string>2a02:fe80::1</string></ArrayOfstring>`,
	))
	if err != nil {
		t.Fatal(err)
	}
	networks, err = parseProviderNetworks(xmlValues)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 ||
		!networks[0].Contains(net.ParseIP("185.93.1.1")) ||
		!networks[1].Contains(net.ParseIP("2a02:fe80::1")) {
		t.Fatalf("XML networks = %#v", networks)
	}
}

func TestProviderSourceValidationRejectsUnsafeContent(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{name: "empty"},
		{name: "malformed", values: []string{"not-an-address"}},
		{name: "private", values: []string{"10.0.0.0/8"}},
		{name: "loopback", values: []string{"127.0.0.1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseProviderNetworks(test.values); err == nil {
				t.Fatalf("accepted unsafe values %#v", test.values)
			}
		})
	}
	if _, err := parseXMLProviderValues([]byte(
		`<html><string>104.16.1.1</string></html>`,
	)); err == nil {
		t.Fatal("accepted unexpected XML document")
	}
	tooMany := make([]string, providerMaximumRanges+1)
	for index := range tooMany {
		tooMany[index] = "104.16.1.1"
	}
	if _, err := parseProviderNetworks(tooMany); err == nil {
		t.Fatal("accepted an oversized provider list")
	}
}

func TestProviderRefreshReplacesRangesAndRetainsLastKnownGood(t *testing.T) {
	var mu sync.RWMutex
	responses := map[string]string{
		"/cloudflare": "104.16.0.0/13\n",
		"/bunny": `<ArrayOfstring xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">` +
			`<string>185.93.1.1</string></ArrayOfstring>`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.RLock()
		value := responses[request.URL.Path]
		mu.RUnlock()
		_, _ = writer.Write([]byte(value))
	}))
	defer server.Close()

	store := newProviderRangeStore(providerMaximumStaleAge)
	updater := &providerRangeUpdater{
		client: server.Client(),
		store:  store,
		sources: []providerSource{
			{
				name: "cloudflare", provider: providerCloudflare,
				url: server.URL + "/cloudflare", format: providerSourcePlain,
			},
			{
				name: "bunny", provider: providerBunny,
				url: server.URL + "/bunny", format: providerSourceXML,
			},
		},
	}
	startedAt := time.Now()
	updater.refresh(context.Background(), startedAt)
	if provider, ambiguous := store.providerFor(net.ParseIP("104.16.1.1"), startedAt); provider != providerCloudflare || ambiguous {
		t.Fatalf("Cloudflare match = %d, ambiguous=%v", provider, ambiguous)
	}
	if provider, ambiguous := store.providerFor(net.ParseIP("185.93.1.1"), startedAt); provider != providerBunny || ambiguous {
		t.Fatalf("Bunny match = %d, ambiguous=%v", provider, ambiguous)
	}

	mu.Lock()
	responses["/cloudflare"] = "invalid\n"
	mu.Unlock()
	updater.refresh(context.Background(), startedAt.Add(time.Hour))
	if provider, _ := store.providerFor(net.ParseIP("104.16.1.1"), startedAt.Add(time.Hour)); provider != providerCloudflare {
		t.Fatal("failed refresh discarded the last-known-good Cloudflare ranges")
	}
	if provider, _ := store.providerFor(
		net.ParseIP("104.16.1.1"),
		startedAt.Add(providerMaximumStaleAge+time.Second),
	); provider != providerNone {
		t.Fatal("stale Cloudflare source remained trusted")
	}

	mu.Lock()
	responses["/cloudflare"] = "172.64.0.0/13\n"
	mu.Unlock()
	replacedAt := startedAt.Add(2 * time.Hour)
	updater.refresh(context.Background(), replacedAt)
	if provider, _ := store.providerFor(net.ParseIP("104.16.1.1"), replacedAt); provider != providerNone {
		t.Fatal("removed Cloudflare range remained trusted after successful replacement")
	}
	if provider, _ := store.providerFor(net.ParseIP("172.64.1.1"), replacedAt); provider != providerCloudflare {
		t.Fatal("replacement Cloudflare range was not trusted")
	}
}

func TestProviderFetchResponseIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("1", providerMaximumBytes+1)))
	}))
	defer server.Close()
	updater := &providerRangeUpdater{
		client: server.Client(),
		store:  newProviderRangeStore(providerMaximumStaleAge),
	}
	if _, err := updater.fetch(context.Background(), providerSource{
		name: "oversized", provider: providerCloudflare,
		url: server.URL, format: providerSourcePlain,
	}); err == nil {
		t.Fatal("accepted oversized provider response")
	}
}

func TestOfficialProviderSources(t *testing.T) {
	if os.Getenv("SOKOL_PLUGIN_RUN_PROVIDER_LIVE_TEST") != "1" {
		t.Skip("set SOKOL_PLUGIN_RUN_PROVIDER_LIVE_TEST=1 to check official sources")
	}
	updater := newDefaultProviderRangeUpdater(
		newProviderRangeStore(providerMaximumStaleAge),
	)
	for _, source := range defaultProviderSources {
		t.Run(source.name, func(t *testing.T) {
			networks, err := updater.fetch(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			if len(networks) == 0 {
				t.Fatal("official source returned no ranges")
			}
			t.Logf("validated %d ranges", len(networks))
		})
	}
}
