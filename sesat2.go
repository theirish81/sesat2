package sesat2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrBlockedHost   = errors.New("destination host is blocked")
	ErrBlockedIP     = errors.New("destination IP is blocked")
	ErrInvalidScheme = errors.New("invalid URL scheme")

	DefaultBlockedHosts = []string{
		"metadata.google.internal",
		"instance-data",
		"metadata",
	}
	DefaultBlockedIPs = []net.IP{
		net.ParseIP("169.254.169.254"), // AWS, GCP, Azure, Oracle, DigitalOcean
		net.ParseIP("100.100.100.200"), // Alibaba
	}

	LoopbackBlockedHosts = []string{
		"localhost",
	}
	LoopbackBlockedIPs = []net.IP{
		net.ParseIP("127.0.0.1"),
		net.IPv6loopback,
	}

	PrivateBlockedIPs = []*net.IPNet{
		// RFC 1918
		mustParseCIDR("10.0.0.0/8"),
		mustParseCIDR("172.16.0.0/12"),
		mustParseCIDR("192.168.0.0/16"),
		// RFC 6598 (Carrier-grade NAT)
		mustParseCIDR("100.64.0.0/10"),
		// RFC 3927 (Link-local)
		mustParseCIDR("169.254.0.0/16"),
		// RFC 4193 (IPv6 Unique Local Address)
		mustParseCIDR("fc00::/7"),
		// RFC 4291 (IPv6 Link-local Address)
		mustParseCIDR("fe80::/10"),
	}
)

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func AllBlockedHosts() []string {
	var hosts []string
	hosts = append(hosts, DefaultBlockedHosts...)
	hosts = append(hosts, LoopbackBlockedHosts...)
	return hosts
}

func AllBlockedIPRanges() []*net.IPNet {
	var ranges []*net.IPNet
	ranges = append(ranges, PrivateBlockedIPs...)

	for _, ip := range DefaultBlockedIPs {
		ranges = append(ranges, ipToNet(ip))
	}
	for _, ip := range LoopbackBlockedIPs {
		ranges = append(ranges, ipToNet(ip))
	}

	return ranges
}

func ipToNet(ip net.IP) *net.IPNet {
	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

type Interceptor func(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type Builder struct {
	mu sync.Mutex

	timeout               time.Duration
	dialTimeout           time.Duration
	keepAlive             time.Duration
	idleConnTimeout       time.Duration
	responseHeaderTimeout time.Duration
	tlsHandshakeTimeout   time.Duration

	defaultHeaders http.Header

	blockedHosts    map[string]struct{}
	blockedIPs      map[string]struct{}
	blockedIPRanges []*net.IPNet

	baseTransport *http.Transport
	resolver      *net.Resolver

	interceptors []Interceptor
}

func New() *Builder {
	return &Builder{
		defaultHeaders:  make(http.Header),
		blockedHosts:    make(map[string]struct{}),
		blockedIPs:      make(map[string]struct{}),
		blockedIPRanges: make([]*net.IPNet, 0),
		resolver:        net.DefaultResolver,
	}
}

func (b *Builder) WithTimeout(d time.Duration) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.timeout = d
	return b
}

func (b *Builder) WithDialTimeout(d time.Duration) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dialTimeout = d
	return b
}

func (b *Builder) WithKeepAlive(d time.Duration) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keepAlive = d
	return b
}

func (b *Builder) WithIdleConnTimeout(d time.Duration) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.idleConnTimeout = d
	return b
}

func (b *Builder) WithResponseHeaderTimeout(d time.Duration) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.responseHeaderTimeout = d
	return b
}

func (b *Builder) WithTLSHandshakeTimeout(d time.Duration) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tlsHandshakeTimeout = d
	return b
}

func (b *Builder) WithHeaders(h http.Header) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()

	for k, vals := range h {
		for _, v := range vals {
			b.defaultHeaders.Add(k, v)
		}
	}
	return b
}

func (b *Builder) WithBlockedHosts(hosts ...string) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, h := range hosts {
		h = normalizeHost(h)
		if h != "" {
			b.blockedHosts[h] = struct{}{}
		}
	}
	return b
}

func (b *Builder) WithBlockedIPs(ips ...net.IP) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, ip := range ips {
		if s := normalizeIP(ip); s != "" {
			b.blockedIPs[s] = struct{}{}
		}
	}
	return b
}

func (b *Builder) WithBlockedIPRanges(ranges ...*net.IPNet) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, r := range ranges {
		if r != nil {
			b.blockedIPRanges = append(b.blockedIPRanges, r)
		}
	}
	return b
}

func (b *Builder) WithDefaultBlockedDestinations() *Builder {
	b.WithBlockedHosts(DefaultBlockedHosts...)
	b.WithBlockedHosts(LoopbackBlockedHosts...)
	b.WithBlockedIPs(DefaultBlockedIPs...)
	b.WithBlockedIPRanges(PrivateBlockedIPs...)
	b.WithBlockedIPs(LoopbackBlockedIPs...)
	return b
}

func (b *Builder) WithTransport(t *http.Transport) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.baseTransport = t
	return b
}

func (b *Builder) WithResolver(r *net.Resolver) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r != nil {
		b.resolver = r
	}
	return b
}

func (b *Builder) WithInterceptor(i Interceptor) *Builder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.interceptors = append(b.interceptors, i)
	return b
}

func (b *Builder) Build() (*http.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// clone state
	headers := cloneHeader(b.defaultHeaders)
	blockedHosts := cloneStringSet(b.blockedHosts)
	blockedIPs := cloneStringSet(b.blockedIPs)
	blockedIPRanges := cloneIPNetSlice(b.blockedIPRanges)

	base := b.baseTransport
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		base = base.Clone()
	}

	dialTimeout := orDefault(b.dialTimeout, 30*time.Second)
	keepAlive := orDefault(b.keepAlive, 30*time.Second)
	idleConnTimeout := orDefault(b.idleConnTimeout, 90*time.Second)
	responseHeaderTimeout := orDefault(b.responseHeaderTimeout, 30*time.Second)
	tlsHandshakeTimeout := orDefault(b.tlsHandshakeTimeout, 10*time.Second)

	base.DialContext = (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}).DialContext
	base.IdleConnTimeout = idleConnTimeout
	base.ResponseHeaderTimeout = responseHeaderTimeout
	base.TLSHandshakeTimeout = tlsHandshakeTimeout

	base.Proxy = nil

	interceptors := append([]Interceptor(nil), b.interceptors...)
	var rt http.RoundTripper = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		var invoke func(i int, req *http.Request) (*http.Response, error)
		invoke = func(i int, req *http.Request) (*http.Response, error) {
			if i == len(interceptors) {
				return base.RoundTrip(req)
			}
			return interceptors[i](req, func(r *http.Request) (*http.Response, error) {
				return invoke(i+1, r)
			})
		}
		return invoke(0, req)
	})

	rt = &secureTransport{
		next:            rt,
		headers:         headers,
		blockedHosts:    blockedHosts,
		blockedIPs:      blockedIPs,
		blockedIPRanges: blockedIPRanges,
		resolver:        b.resolver,
	}

	client := &http.Client{
		Timeout:   b.timeout,
		Transport: rt,
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		st := rt.(*secureTransport)
		if err := st.checkDestination(req.Context(), req.URL); err != nil {
			return err
		}
		return nil
	}

	return client, nil
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

type secureTransport struct {
	next http.RoundTripper

	headers         http.Header
	blockedHosts    map[string]struct{}
	blockedIPs      map[string]struct{}
	blockedIPRanges []*net.IPNet
	resolver        *net.Resolver
}

func (t *secureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}

	req2 := req.Clone(req.Context())

	mergeHeaders(req2.Header, t.headers)

	if err := t.checkDestination(req2.Context(), req2.URL); err != nil {
		return nil, err
	}

	return t.next.RoundTrip(req2)
}

func (t *secureTransport) checkDestination(ctx context.Context, u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%w: %s", ErrInvalidScheme, u.Scheme)
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return fmt.Errorf("invalid host")
	}

	if _, ok := t.blockedHosts[host]; ok {
		return fmt.Errorf("%w: %s", ErrBlockedHost, host)
	}

	if ip := net.ParseIP(host); ip != nil {
		if t.isIPBlocked(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedIP, ip)
		}
		return nil
	}

	ips, err := t.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IPs for host %s", host)
	}

	for _, ip := range ips {
		if t.isIPBlocked(ip.IP) {
			return fmt.Errorf("%w: %s", ErrBlockedIP, ip.IP)
		}
	}

	return nil
}

func (t *secureTransport) isIPBlocked(ip net.IP) bool {
	if _, ok := t.blockedIPs[normalizeIP(ip)]; ok {
		return true
	}
	for _, ipNet := range t.blockedIPRanges {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	return strings.TrimSuffix(h, ".")
}

func normalizeIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.To16().String()
}

func mergeHeaders(dst, defaults http.Header) {
	for k, vals := range defaults {
		if dst.Get(k) != "" {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func cloneIPNetSlice(in []*net.IPNet) []*net.IPNet {
	out := make([]*net.IPNet, len(in))
	copy(out, in)
	return out
}
