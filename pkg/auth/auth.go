package auth

import (
	"encoding/base64"
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

func GetPublicKey() (string, error) {
	publicKeyEnv := strings.TrimSpace(os.Getenv("RSA_PUBLIC_KEY"))
	if publicKeyEnv == "" {
		return "", errors.New("public key is not set in environment variables")
	}

	publicKeyPem, err := decodeMaybeBase64(publicKeyEnv)
	if err != nil {
		publicKeyPem = publicKeyEnv
	}

	publicKeyPem = strings.TrimSpace(publicKeyPem)
	publicKeyPem = strings.ReplaceAll(publicKeyPem, `\n`, "\n")

	if !strings.Contains(publicKeyPem, "-----BEGIN PUBLIC KEY-----") && !strings.Contains(publicKeyPem, "-----BEGIN RSA PUBLIC KEY-----") {
		return "", errors.New("RSA_PUBLIC_KEY does not contain a valid PEM public key")
	}

	return publicKeyPem, nil
}

func decodeMaybeBase64(src string) (string, error) {
	tmp := strings.TrimSpace(src)
	if tmp == "" {
		return "", errors.New("empty base64 input")
	}

	decoded, err := base64.StdEncoding.DecodeString(tmp)
	if err == nil {
		return string(decoded), nil
	}

	decoded, err = base64.URLEncoding.DecodeString(tmp)
	if err == nil {
		return string(decoded), nil
	}

	decoded, err = base64.RawStdEncoding.DecodeString(tmp)
	if err == nil {
		return string(decoded), nil
	}

	decoded, err = base64.RawURLEncoding.DecodeString(tmp)
	if err == nil {
		return string(decoded), nil
	}

	return "", err
}
