package main

import (
    "bytes"
    "context"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "io"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

// This key is independent of JWT_SECRET and is never sent to driver clients.
// The endpoint accepts only SAEIV-signed, body-bound, single-use tokens.
func requireSaeivIngestion() func(http.Handler) http.Handler {
    var mutex sync.Mutex
    used := make(map[string]int64)
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            path := os.Getenv("SAEIV_INGEST_SECRET_FILE")
            key, err := os.ReadFile(path)
            key = bytes.TrimSpace(key)
            if path == "" || err != nil || len(key) < 32 {
                writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "SAEIV ingestion is not configured"})
                return
            }
            auth := r.Header.Get("Authorization")
            if !strings.HasPrefix(auth, "Bearer ") {
                writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "service authentication required"})
                return
            }
            claims := jwt.MapClaims{}
            token, err := jwt.ParseWithClaims(strings.TrimPrefix(auth, "Bearer "), claims,
                func(t *jwt.Token) (interface{}, error) { return key, nil },
                jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("kanoa-saeiv"),
                jwt.WithAudience("vehicle-positions-ingest"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
            if err != nil || !token.Valid {
                writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid service token"})
                return
            }
            subject, _ := claims.GetSubject()
            issued, issuedErr := claims.GetIssuedAt()
            expires, expiresErr := claims.GetExpirationTime()
            nonce, _ := claims["jti"].(string)
            digest, _ := claims["body_sha256"].(string)
            now := time.Now().Unix()
            if subject == "" || len(subject) > 128 || issuedErr != nil || expiresErr != nil ||
                issued == nil || expires == nil || expires.Unix() <= issued.Unix() ||
                expires.Unix()-issued.Unix() > 30 || now-issued.Unix() > 30 ||
                len(nonce) < 16 || len(nonce) > 128 || len(digest) != 64 {
                writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid service claims"})
                return
            }
            r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
            body, err := io.ReadAll(r.Body)
            if err != nil {
                writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "invalid location body"})
                return
            }
            sum := sha256.Sum256(body)
            actual := hex.EncodeToString(sum[:])
            if subtle.ConstantTimeCompare([]byte(digest), []byte(actual)) != 1 {
                writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "location body does not match service token"})
                return
            }
            mutex.Lock()
            for id, expiry := range used {
                if expiry <= now { delete(used, id) }
            }
            _, replay := used[nonce]
            full := len(used) >= 10000
            if !replay && !full { used[nonce] = expires.Unix() }
            mutex.Unlock()
            if replay {
                writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "service token already used"})
                return
            }
            if full {
                writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "service ingestion capacity exceeded"})
                return
            }
            r.Body = io.NopCloser(bytes.NewReader(body))
            ctx := context.WithValue(r.Context(), claimsKey, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
