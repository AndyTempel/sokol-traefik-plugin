package sokol_traefik_plugin

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

const maximumForwardedHops = 32

func extractClientIP(
	request *http.Request,
	strategy ClientIPConfig,
	trusted []*net.IPNet,
	providers *providerRangeStore,
) (net.IP, error) {
	client, _, err := extractClientIPWithSource(request, strategy, trusted, providers)
	return client, err
}

func extractClientIPWithSource(
	request *http.Request,
	strategy ClientIPConfig,
	trusted []*net.IPNet,
	providers *providerRangeStore,
) (net.IP, string, error) {
	direct, err := parseRemoteIP(request.RemoteAddr)
	if err != nil {
		return nil, "fallback_error", err
	}
	now := time.Now()
	if client, recognized, err := extractRecognizedProviderIP(
		request, direct, strategy, providers, now,
	); recognized {
		return client, recognizedProviderSource(direct, providers, now, err), err
	}
	switch strategy.Strategy {
	case "direct":
		return direct, "direct", nil
	case "forwarded":
		forwarded, err := extractForwardedIP(request, direct, trusted)
		if err != nil {
			return forwarded, "fallback_error", err
		}
		// Pangolin and similar trusted intermediaries place the actual CDN
		// peer in XFF. Verify that resolved hop against the official ranges
		// before accepting the provider-specific client address.
		if client, recognized, err := extractRecognizedProviderIP(
			request, forwarded, strategy, providers, now,
		); recognized {
			return client, recognizedProviderSource(forwarded, providers, now, err), err
		}
		if forwarded.Equal(direct) {
			return forwarded, "direct", nil
		}
		return forwarded, "forwarded", nil
	case "cloudflare", "bunny":
		// Legacy explicit provider modes remain accepted. With no verified
		// provider peer they fail safely to the direct address.
		return direct, "direct", nil
	default:
		return direct, "direct", nil
	}
}

func recognizedProviderSource(peer net.IP, providers *providerRangeStore, now time.Time, err error) string {
	if err != nil {
		return "fallback_error"
	}
	provider, ambiguous := providers.providerFor(peer, now)
	if ambiguous {
		return "fallback_error"
	}
	if provider == providerCloudflare {
		return "cloudflare"
	}
	if provider == providerBunny {
		return "bunny"
	}
	return "fallback_error"
}

func extractRecognizedProviderIP(
	request *http.Request,
	peer net.IP,
	strategy ClientIPConfig,
	providers *providerRangeStore,
	now time.Time,
) (net.IP, bool, error) {
	provider, ambiguous := providers.providerFor(peer, now)
	if ambiguous {
		return peer, true, errors.New("peer belongs to multiple CDN provider lists")
	}
	switch provider {
	case providerCloudflare:
		client, err := extractProviderIP(request, peer, strategy.CloudflareHeader)
		return client, true, err
	case providerBunny:
		client, err := extractProviderIP(request, peer, strategy.BunnyHeader)
		return client, true, err
	default:
		return peer, false, nil
	}
}

func parseRemoteIP(value string) (net.IP, error) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("direct peer address is invalid")
	}
	return normalizeIP(ip), nil
}

func extractProviderIP(request *http.Request, direct net.IP, header string) (net.IP, error) {
	value := strings.TrimSpace(request.Header.Get(header))
	if value == "" {
		return direct, nil
	}
	if strings.Contains(value, ",") {
		return direct, errors.New("provider client IP header must contain one address")
	}
	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil {
		return direct, errors.New("provider client IP header is malformed")
	}
	return normalizeIP(ip), nil
}

func extractForwardedIP(request *http.Request, direct net.IP, trusted []*net.IPNet) (net.IP, error) {
	value := request.Header.Get("X-Forwarded-For")
	if value == "" || !ipIsTrusted(direct, trusted) {
		return direct, nil
	}
	raw := strings.Split(value, ",")
	if len(raw) > maximumForwardedHops {
		return direct, errors.New("forwarded chain is too long")
	}
	hops := make([]net.IP, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			return direct, errors.New("forwarded chain contains an empty address")
		}
		ip := net.ParseIP(strings.Trim(item, "[]"))
		if ip == nil {
			return direct, errors.New("forwarded chain contains an invalid address")
		}
		hops = append(hops, normalizeIP(ip))
	}
	current := direct
	for index := len(hops) - 1; index >= 0; index-- {
		if !ipIsTrusted(current, trusted) {
			return current, nil
		}
		current = hops[index]
	}
	return current, nil
}

func ipIsTrusted(ip net.IP, trusted []*net.IPNet) bool {
	ip = normalizeIP(ip)
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeIP(ip net.IP) net.IP {
	if ipv4 := ip.To4(); ipv4 != nil {
		return net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3]).To4()
	}
	return ip.To16()
}
