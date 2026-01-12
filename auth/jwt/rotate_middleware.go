package jwt

import (
	"net/http"
	"strings"
	"time"
)

func (p *Plugin) keyRotateAuthoriser() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetJWTUser(r.Context())
			if !ok || user == nil {
				http.Error(w, "unauthorised", http.StatusUnauthorized)
				return
			}

			if !roleAllowed(user.Role, p.keyRotationRoles) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (p *Plugin) keyRotateRateLimiter() func(http.Handler) http.Handler {
	if p.rotateKeyLimiter == nil || p.rotateKeyRateLimitMax <= 0 || p.rotateKeyRateLimitWindow <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := "jwt:rotate:" + p.clientIPForRateLimit(r)
			result, err := p.rotateKeyLimiter.Allow(r.Context(), key, p.rotateKeyRateLimitMax, p.rotateKeyRateLimitWindow, 1)
			if err != nil {
				http.Error(w, "rate limit error", http.StatusTooManyRequests)
				return
			}
			if !result.Allowed {
				w.Header().Set("Retry-After", result.ResetAt.Format(time.RFC1123))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func roleAllowed(userRole string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	roles := strings.Split(userRole, ",")
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		for _, allowedRole := range allowed {
			if role == allowedRole {
				return true
			}
		}
	}
	return false
}

func (p *Plugin) clientIPForRateLimit(r *http.Request) string {
	remoteIP := stripPort(r.RemoteAddr)
	if len(p.ctx.TrustedProxies) == 0 {
		return remoteIP
	}

	trusted := make(map[string]bool, len(p.ctx.TrustedProxies))
	for _, ip := range p.ctx.TrustedProxies {
		trusted[ip] = true
	}

	if trusted[remoteIP] {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return strings.TrimSpace(xff[:i])
				}
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	return remoteIP
}

func stripPort(addr string) string {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
