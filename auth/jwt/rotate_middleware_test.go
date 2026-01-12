package jwt

import (
	"net/http/httptest"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestClientIPForRateLimit_UntrustedHeaders(t *testing.T) {
	p := &Plugin{
		ctx: plugin.Context{},
	}

	req := httptest.NewRequest("POST", "/keys/rotate", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")

	ip := p.clientIPForRateLimit(req)
	if ip != "192.0.2.10" {
		t.Errorf("IP = %s, want 192.0.2.10", ip)
	}
}

func TestClientIPForRateLimit_TrustedXForwardedFor(t *testing.T) {
	p := &Plugin{
		ctx: plugin.Context{
			TrustedProxies: []string{"192.0.2.10"},
		},
	}

	req := httptest.NewRequest("POST", "/keys/rotate", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")

	ip := p.clientIPForRateLimit(req)
	if ip != "203.0.113.50" {
		t.Errorf("IP = %s, want 203.0.113.50", ip)
	}
}
