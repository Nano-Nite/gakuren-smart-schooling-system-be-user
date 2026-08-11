package model

type LoginPayload struct {
	Email string `json:"email,omitempty"`
}

type PublicKeyResponse struct {
	PublicKey string `json:"public_key,omitempty"`
}
