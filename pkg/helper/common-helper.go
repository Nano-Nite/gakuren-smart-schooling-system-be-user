package helper

import (
	"encoding/base64"
	"errors"
	"log"
	"strings"

	"github.com/gofiber/fiber/v3"
)

func ReturnResponse(c fiber.Ctx, statusCode int, message string, data interface{}, err error) error {
	response := make(map[string]interface{})
	response["message"] = message
	response["data"] = nil
	response["error"] = statusCode >= 400

	if data != nil {
		response["data"] = data
	}
	if err != nil {
		log.Println(err)
	}
	return c.Status(statusCode).JSON(response)
}

func DecodeB64String(src string) (string, error) {
	decodedByte, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	}

	return string(decodedByte), nil
}

func DecodeB64Bytes(src string) ([]byte, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, errors.New("empty base64 input")
	}

	b, err := base64.StdEncoding.DecodeString(src)
	if err == nil {
		return b, nil
	}

	b, err = base64.URLEncoding.DecodeString(src)
	if err == nil {
		return b, nil
	}

	return nil, err
}
