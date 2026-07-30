package sokol_traefik_plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	providerRefreshInterval = 6 * time.Hour
	providerMaximumStaleAge = 48 * time.Hour
	providerFetchTimeout    = 10 * time.Second
	providerMaximumBytes    = 2 << 20
	providerMaximumRanges   = 8192
)

type providerKind uint8

const (
	providerNone providerKind = iota
	providerCloudflare
	providerBunny
)

type providerSourceFormat uint8

const (
	providerSourcePlain providerSourceFormat = iota
	providerSourceXML
)

type providerSource struct {
	name     string
	provider providerKind
	url      string
	format   providerSourceFormat
}

var defaultProviderSources = []providerSource{
	{
		name: "cloudflare-ipv4", provider: providerCloudflare,
		url: "https://www.cloudflare.com/ips-v4", format: providerSourcePlain,
	},
	{
		name: "cloudflare-ipv6", provider: providerCloudflare,
		url: "https://www.cloudflare.com/ips-v6", format: providerSourcePlain,
	},
	{
		name: "bunny-edges", provider: providerBunny,
		url: "https://bunnycdn.com/api/system/edgeserverlist", format: providerSourceXML,
	},
	{
		name: "bunny-nodes", provider: providerBunny,
		url: "https://api.bunny.net/mc/nodes/plain", format: providerSourcePlain,
	},
}

type providerSourceState struct {
	provider  providerKind
	networks  []*net.IPNet
	updatedAt time.Time
}

// providerRangeStore keeps immutable, last-known-good source snapshots.
// Network reads are local and bounded; refresh I/O never runs on a request.
type providerRangeStore struct {
	mu              sync.RWMutex
	maximumStaleAge time.Duration
	sources         map[string]providerSourceState
}

func newProviderRangeStore(maximumStaleAge time.Duration) *providerRangeStore {
	return &providerRangeStore{
		maximumStaleAge: maximumStaleAge,
		sources:         make(map[string]providerSourceState),
	}
}

func (store *providerRangeStore) replace(
	name string,
	provider providerKind,
	networks []*net.IPNet,
	updatedAt time.Time,
) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.sources[name] = providerSourceState{
		provider: provider, networks: networks, updatedAt: updatedAt,
	}
}

func (store *providerRangeStore) providerFor(ip net.IP, now time.Time) (providerKind, bool) {
	if store == nil {
		return providerNone, false
	}
	ip = normalizeIP(ip)
	store.mu.RLock()
	defer store.mu.RUnlock()
	var cloudflare, bunny bool
	for _, source := range store.sources {
		if now.Sub(source.updatedAt) > store.maximumStaleAge {
			continue
		}
		for _, network := range source.networks {
			if !network.Contains(ip) {
				continue
			}
			if source.provider == providerCloudflare {
				cloudflare = true
			}
			if source.provider == providerBunny {
				bunny = true
			}
			break
		}
	}
	if cloudflare && bunny {
		return providerNone, true
	}
	if cloudflare {
		return providerCloudflare, false
	}
	if bunny {
		return providerBunny, false
	}
	return providerNone, false
}

type providerRangeUpdater struct {
	client  *http.Client
	store   *providerRangeStore
	sources []providerSource
}

func newDefaultProviderRangeUpdater(store *providerRangeStore) *providerRangeUpdater {
	return &providerRangeUpdater{
		client: &http.Client{
			Timeout: providerFetchTimeout,
			Transport: &http.Transport{
				Proxy:                 nil,
				ForceAttemptHTTP2:     true,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				IdleConnTimeout:       30 * time.Second,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("provider source redirects are disabled")
			},
		},
		store:   store,
		sources: defaultProviderSources,
	}
}

func (updater *providerRangeUpdater) run(ctx context.Context) {
	updater.refresh(ctx, time.Now())
	ticker := time.NewTicker(providerRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			updater.refresh(ctx, now)
		case <-ctx.Done():
			return
		}
	}
}

func (updater *providerRangeUpdater) refresh(ctx context.Context, now time.Time) {
	for _, source := range updater.sources {
		networks, err := updater.fetch(ctx, source)
		if err != nil {
			log.Printf("sokol provider range refresh %q failed: %v", source.name, err)
			continue
		}
		updater.store.replace(source.name, source.provider, networks, now)
	}
}

func (updater *providerRangeUpdater) fetch(
	ctx context.Context,
	source providerSource,
) ([]*net.IPNet, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "text/plain, application/xml, text/xml")
	request.Header.Set("User-Agent", "sokol-traefik-plugin/provider-ranges")
	response, err := updater.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, providerMaximumBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) > providerMaximumBytes {
		return nil, errors.New("response exceeds 2 MiB")
	}
	var values []string
	switch source.format {
	case providerSourcePlain:
		values, err = parsePlainProviderValues(data)
	case providerSourceXML:
		values, err = parseXMLProviderValues(data)
	default:
		err = errors.New("unknown provider source format")
	}
	if err != nil {
		return nil, err
	}
	return parseProviderNetworks(values)
}

func parsePlainProviderValues(data []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 64<<10)
	var values []string
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse plain list: %w", err)
	}
	return values, nil
}

func parseXMLProviderValues(data []byte) ([]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var document struct {
		XMLName xml.Name
		Values  []string `xml:"string"`
	}
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse XML list: %w", err)
	}
	if document.XMLName.Local != "ArrayOfstring" {
		return nil, errors.New("XML provider list has an unexpected root element")
	}
	for index := range document.Values {
		document.Values[index] = strings.TrimSpace(document.Values[index])
	}
	return document.Values, nil
}

func parseProviderNetworks(values []string) ([]*net.IPNet, error) {
	if len(values) == 0 {
		return nil, errors.New("provider list is empty")
	}
	if len(values) > providerMaximumRanges {
		return nil, fmt.Errorf("provider list exceeds %d entries", providerMaximumRanges)
	}
	networks := make([]*net.IPNet, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			ip = net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("provider list contains invalid address %q", value)
			}
			ip = normalizeIP(ip)
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		} else {
			network.IP = normalizeIP(ip.Mask(network.Mask))
		}
		if !publicProviderIP(network.IP) {
			return nil, fmt.Errorf("provider list contains non-public address %q", value)
		}
		key := network.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil, errors.New("provider list has no unique addresses")
	}
	return networks, nil
}

func publicProviderIP(ip net.IP) bool {
	return ip != nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast()
}

var (
	defaultProviderStore       = newProviderRangeStore(providerMaximumStaleAge)
	defaultProviderRefreshOnce sync.Once
)

func startDefaultProviderRefresh(ctx context.Context) {
	if ctx != nil && ctx.Err() != nil {
		return
	}
	defaultProviderRefreshOnce.Do(func() {
		updater := newDefaultProviderRangeUpdater(defaultProviderStore)
		go updater.run(context.Background())
	})
}
