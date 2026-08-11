package auth

import (
	"errors"
	"os"
	"strings"
)

func AuthenticateBearerToken(authHeader string) (string, error) {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("authorization header must be in format: Bearer <token>")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("bearer token is required")
	}

	expectedToken := strings.TrimSpace(os.Getenv("BEARER_TOKEN"))
	if expectedToken == "" {
		expectedToken = "dev-token"
	}

	if token != expectedToken {
		return "", errors.New("invalid bearer token")
	}

	return token, nil
}
