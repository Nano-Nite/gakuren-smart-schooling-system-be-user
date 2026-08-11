package helper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/youmark/pkcs8"
)

func DecodeRSA(data string) ([]byte, error) {
	// Decode Base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid RSA ciphertext Base64: %w",
			err,
		)
	}

	// Load private key
	rsaPrivateKey, err := parsePrivateKey(
		os.Getenv("RSA_PRIVATE_KEY"),
	)
	if err != nil {
		return nil, err
	}

	// fmt.Println("ciphertext length:", len(ciphertext))
	// fmt.Println("RSA key size:", rsaPrivateKey.Size())
	// fmt.Println("RSA bits:", rsaPrivateKey.N.BitLen())

	// RSA-2048 / OAEP / SHA-256
	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPrivateKey,
		ciphertext,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"RSA OAEP SHA-256 decrypt failed: %w",
			err,
		)
	}

	return plaintext, nil
}

func EncodeRSA(data string) (string, error) {
	// Load RSA public key
	publicKey, err := parsePublicKey(
		os.Getenv("RSA_PUBLIC_KEY"),
	)
	if err != nil {
		return "", fmt.Errorf(
			"failed to parse RSA public key: %w",
			err,
		)
	}

	// UTF-8 bytes
	plaintext := []byte(data)

	// RSA-OAEP SHA-256
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		plaintext,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf(
			"RSA encryption failed: %w",
			err,
		)
	}

	// Ciphertext → Base64
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return encoded, nil
}

func parsePublicKey(base64Key string) (*rsa.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}

	return rsaPublicKey, nil
}

func parsePrivateKey(base64Key string) (*rsa.PrivateKey, error) {
	// Base64 decode
	pemBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// PEM decode
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	if len(rest) > 0 {
		fmt.Println("warning: extra data after PEM")
	}

	// fmt.Println("PEM Type:", block.Type)

	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf(
			"unexpected PEM type: %s",
			block.Type,
		)
	}

	// Decrypt PKCS#8
	privateKey, err := pkcs8.ParsePKCS8PrivateKey(
		block.Bytes,
		[]byte(os.Getenv("RSA_PASSPHARSE")),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"PKCS#8 decrypt failed: %w",
			err,
		)
	}

	// Assert RSA
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(
			"expected RSA private key, got %T",
			privateKey,
		)
	}

	// Validate
	if err := rsaPrivateKey.Validate(); err != nil {
		return nil, fmt.Errorf(
			"RSA validation failed: %w",
			err,
		)
	}

	// fmt.Println("RSA key successfully decrypted")
	// fmt.Println("Bits:", rsaPrivateKey.N.BitLen())
	// fmt.Println("Public exponent:", rsaPrivateKey.E)

	// Validate public/private pair
	publicRSA, err := parsePublicKey(
		os.Getenv("RSA_PUBLIC_KEY"),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse public key: %w",
			err,
		)
	}

	if rsaPrivateKey.N.Cmp(publicRSA.N) != 0 {
		return nil, fmt.Errorf(
			"public/private key pair does not match",
		)
	}

	log.Println("Public/private key pair: MATCH")

	return rsaPrivateKey, nil
}
