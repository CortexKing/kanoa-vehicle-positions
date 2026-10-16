package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSaeivIngestionAuthentication(t *testing.T) {
	key := []byte("synthetic-integration-test-key-32-bytes")
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, key, 0600); err != nil { t.Fatal(err) }
	t.Setenv("SAEIV_INGEST_SECRET_FILE", path)
	body := `{"vehicle_id":"VEH-TEST"}`
	sum := sha256.Sum256([]byte(body))
	now := time.Now().Unix()
	claims := func() jwt.MapClaims {
		return jwt.MapClaims{"iss":"kanoa-saeiv", "aud":"vehicle-positions-ingest", "sub":"DRV-TEST", "iat":now, "exp":now+30, "jti":"synthetic-unique-nonce", "body_sha256":hex.EncodeToString(sum[:])}
	}
	sign := func(c jwt.MapClaims) string {
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(key)
		if err != nil { t.Fatal(err) }
		return token
	}
	calls := 0
	handler := requireSaeivIngestion()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		got, ok := r.Context().Value(claimsKey).(jwt.MapClaims)
		if !ok || got["sub"] != "DRV-TEST" { t.Error("driver identity was not preserved") }
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func(token, data string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/saeiv/locations", strings.NewReader(data))
		r.Header.Set("Authorization", "Bearer " + token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	token := sign(claims())
	if got := request(token, body+" "); got != 401 { t.Fatalf("tampered body: %d", got) }
	if got := request(token, body); got != 204 { t.Fatalf("valid token: %d", got) }
	if got := request(token, body); got != 401 { t.Fatalf("replay: %d", got) }
	for _, field := range []string{"iss", "aud"} {
		c := claims(); c[field] = "legacy"; c["jti"] = "different-unique-nonce"
		if got := request(sign(c), body); got != 401 { t.Errorf("wrong %s: %d", field, got) }
	}
	c := claims(); c["exp"] = now+3600
	if got := request(sign(c), body); got != 401 { t.Errorf("long-lived token: %d", got) }
	c = claims(); c["iat"] = now-60; c["exp"] = now-30
	if got := request(sign(c), body); got != 401 { t.Errorf("expired token: %d", got) }
	t.Setenv("SAEIV_INGEST_SECRET_FILE", "")
	if got := request(token, body); got != 503 { t.Errorf("missing key: %d", got) }
	if calls != 1 { t.Errorf("unauthorized calls reached handler: %d", calls) }
}
