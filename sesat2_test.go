package sesat2

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDestinationBlocker(t *testing.T) {
	t.Run("basic client with custom header", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "foobar", r.Header.Get("X-Foobar"))
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		client, err := New().WithHeaders(http.Header{
			"X-Foobar": []string{"foobar"},
		}).Build()
		assert.NoError(t, err)
		_, err = client.Get(ts.URL)
		assert.NoError(t, err)
	})
	t.Run("basic client with forbidden host", func(t *testing.T) {
		client, err := New().WithBlockedHosts("example.com").Build()
		assert.NoError(t, err)
		_, err = client.Get("https://example.com")
		assert.Error(t, err)
		_, err = client.Get("http://example.com")
		assert.Error(t, err)
	})
	t.Run("basic client with forbidden IP address", func(t *testing.T) {
		client, err := New().WithBlockedIPs(net.ParseIP("127.0.0.1")).Build()
		assert.NoError(t, err)
		_, err = client.Get("http://127.0.0.1")
		assert.Error(t, err)
	})
	t.Run("basic client with forbidden resolved IP address", func(t *testing.T) {
		client, err := New().WithBlockedIPs(net.ParseIP("127.0.0.1")).Build()
		assert.NoError(t, err)
		_, err = client.Get("https://localhost")
		assert.Error(t, err)
		_, err = client.Get("http://127.0.0.1")
		assert.Error(t, err)
	})
	t.Run("client with default blocked destinations", func(t *testing.T) {
		client, err := New().WithDefaultBlockedDestinations().Build()
		assert.NoError(t, err)

		// Check IPs
		for _, ip := range DefaultBlockedIPs {
			_, err = client.Get("http://" + ip.String())
			assert.Error(t, err, "should block default IP %s", ip.String())
			assert.ErrorIs(t, err, ErrBlockedIP)
		}

		// Check Hosts
		for _, host := range DefaultBlockedHosts {
			_, err = client.Get("http://" + host)
			assert.Error(t, err, "should block default host %s", host)
			// It might be ErrBlockedHost or ErrBlockedIP if it resolves to a blocked IP
			// But for these specific hosts, they should be blocked by host name first in checkDestination
		}
	})
}

func TestAllBlockedFunctions(t *testing.T) {
	t.Run("AllBlockedHosts", func(t *testing.T) {
		hosts := AllBlockedHosts()
		assert.Contains(t, hosts, "localhost")
		assert.Contains(t, hosts, "metadata.google.internal")
		assert.Equal(t, len(DefaultBlockedHosts)+len(LoopbackBlockedHosts), len(hosts))
	})

	t.Run("AllBlockedIPRanges", func(t *testing.T) {
		ranges := AllBlockedIPRanges()
		// Check for one from each category
		foundRFC1918 := false
		foundMetadata := false
		foundLoopback := false

		for _, r := range ranges {
			if r.String() == "10.0.0.0/8" {
				foundRFC1918 = true
			}
			if r.IP.String() == "169.254.169.254" {
				foundMetadata = true
			}
			if r.IP.String() == "127.0.0.1" {
				foundLoopback = true
			}
		}

		assert.True(t, foundRFC1918, "RFC 1918 range should be present")
		assert.True(t, foundMetadata, "Metadata IP should be present")
		assert.True(t, foundLoopback, "Loopback IP should be present")
	})
}

func TestTransportWrapping(t *testing.T) {
	t.Run("default RoundTripper", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "foobar", r.Header.Get("X-Foobar"))
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		client, err := New().WithHeaders(http.Header{
			"X-Foobar": []string{"foobar"},
		}).WithMiddleware(func(next http.RoundTripper) http.RoundTripper {
			return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return next.RoundTrip(req)

			})
		}).Build()
		assert.NoError(t, err)
		_, err = client.Get(ts.URL)
		assert.NoError(t, err)
	})
	t.Run("custom RoundTripper", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "foobar", r.Header.Get("X-Foobar"))
			assert.Equal(t, "baloni", r.Header.Get("X-Baloni"))
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		client, err := New().WithHeaders(http.Header{
			"X-Foobar": []string{"foobar"},
		}).WithMiddleware(func(next http.RoundTripper) http.RoundTripper {
			return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				req.Header.Set("X-Baloni", "baloni")
				return next.RoundTrip(req)
			})
		}).Build()
		assert.NoError(t, err)
		_, err = client.Get(ts.URL)
		assert.NoError(t, err)
	})
	t.Run("Reverse custom transport", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "foobar", r.Header.Get("X-Foobar"))
			assert.Equal(t, "baloni", r.Header.Get("X-Baloni"))
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		client, err := New().WithHeaders(http.Header{
			"X-Foobar": []string{"foobar"},
		}).Build()
		client.Transport = extraRoundTripper{client.Transport}
		assert.NoError(t, err)
		_, err = client.Get(ts.URL)
		assert.NoError(t, err)
	})
}

type extraRoundTripper struct {
	rt http.RoundTripper
}

func (e extraRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("X-Baloni", "baloni")
	return e.rt.RoundTrip(r)
}
