package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// APIKeyAuth protects handlers with static API keys. Clients send the key as
// "Authorization: Bearer <key>" or "X-API-Key: <key>".
type APIKeyAuth struct {
	// Keys are stored hashed so that comparison time does not depend on key length.
	keys [][sha256.Size]byte
}

// NewAPIKeyAuth creates an APIKeyAuth. Empty keys are ignored; with no keys at
// all, authentication is disabled and every request is allowed.
func NewAPIKeyAuth(keys []string) *APIKeyAuth {
	a := &APIKeyAuth{}
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			a.keys = append(a.keys, sha256.Sum256([]byte(k)))
		}
	}
	return a
}

// Enabled reports whether at least one key is configured.
func (a *APIKeyAuth) Enabled() bool { return len(a.keys) > 0 }

// Require wraps next so that it only runs for requests with a valid key.
func (a *APIKeyAuth) Require(next http.HandlerFunc) http.HandlerFunc {
	if !a.Enabled() {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.valid(requestKey(r)) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="security-monitor"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next(w, r)
	}
}

func (a *APIKeyAuth) valid(key string) bool {
	if key == "" {
		return false
	}
	sum := sha256.Sum256([]byte(key))
	match := 0
	// Compare against every key so timing does not reveal which one matched.
	for _, k := range a.keys {
		match |= subtle.ConstantTimeCompare(sum[:], k[:])
	}
	return match == 1
}

func requestKey(r *http.Request) string {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(token)
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}
