package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
)

// basicAuth lets only requests with the configured user and password through.
// Both are compared as SHA-256 hashes in constant time, so neither the
// comparison time nor its length reveals how much of a guess was right.
func basicAuth(user, password string, logger *slog.Logger, next http.Handler) http.Handler {
	wantUser, wantPassword := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		gotUser, gotPassword := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
		match := subtle.ConstantTimeCompare(gotUser[:], wantUser[:]) & subtle.ConstantTimeCompare(gotPassword[:], wantPassword[:])
		if !ok || match != 1 {
			if ok { // a browser's first request carries no credentials; only wrong ones are worth a log line
				logger.WarnContext(r.Context(), "web UI login failed",
					slog.String("remote_addr", r.RemoteAddr), slog.String("user", u))
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Security Monitor", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// contentSecurityPolicy allows only the UI's own script and stylesheet: no
// inline code, no eval, no foreign origins. Events contain attacker-written
// strings (XSS payloads in paths and user agents are the point of storing
// them); if one ever escaped the template's encoding, the browser would still
// refuse to run it.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// securityHeaders sets headers every UI response gets.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
