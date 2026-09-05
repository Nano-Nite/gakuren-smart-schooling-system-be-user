package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"gakuren-system.com/pkg/model"
	"github.com/golang-jwt/jwt/v5"
)

func TestTokenLifetimeBounds(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"", 5}, {"bad", 5}, {"0", 5}, {"-1", 5}, {"10", 10}, {"999", 15},
	} {
		t.Setenv("ACCESS_TOKEN_DURATION", tc.value)
		if got := lifetime("ACCESS_TOKEN_DURATION", 5, 15); got != tc.want {
			t.Fatalf("%q: got %v", tc.value, got)
		}
	}
}

func TestRejectInvalidJWTBeforeSessionLookup(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RSA_PUBLIC_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	t.Setenv("JWT_ISSUER", "test-issuer")
	t.Setenv("JWT_AUDIENCE", "test-audience")
	for _, name := range []string{"expired", "missing expiry", "wrong issuer", "wrong audience", "missing session", "wrong algorithm"} {
		t.Run(name, func(t *testing.T) {
			claims := model.AccessTokenClaims{SessionID: "session", TenantUUID: "tenant", SchoolUUID: "school",
				RegisteredClaims: jwt.RegisteredClaims{Subject: "user", Issuer: "test-issuer", Audience: jwt.ClaimStrings{"test-audience"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}}
			method := jwt.SigningMethodRS256
			switch name {
			case "expired":
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			case "missing expiry":
				claims.ExpiresAt = nil
			case "wrong issuer":
				claims.Issuer = "other"
			case "wrong audience":
				claims.Audience = jwt.ClaimStrings{"other"}
			case "missing session":
				claims.SessionID = ""
			case "wrong algorithm":
				method = jwt.SigningMethodRS512
			}
			raw, err := jwt.NewWithClaims(method, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			// db.Conn is nil: any database access on these invalid tokens is a failure.
			if _, err = ValidateAccessToken(raw); err == nil {
				t.Fatal("accepted invalid JWT")
			}
		})
	}
}
