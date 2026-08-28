package v1

import (
	"log"
	"os"
	"strings"

	"gakuren-system.com/pkg/auth"
	"gakuren-system.com/pkg/helper"
	"gakuren-system.com/pkg/model"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
)

func SetupRoutes() {
	app := fiber.New()

	app.Use(cors.New())

	app.Use(func(c fiber.Ctx) error {
		log.Printf("API hit : %s %s <> IP Address : %s <> User Agent : %s\n", c.Method(), c.OriginalURL(), c.IP(), c.UserAgent())
		log.Println("Authorization : ", c.Get("Authorization"))
		log.Println("Body : ", string(c.Req().Body()))
		return c.Next()
	})

	app.Get(helper.API_VERSION+"/auth/test", func(c fiber.Ctx) error {
		return c.SendString("ready to go !!!!!!!!!!")
	})

	app.Post(helper.API_VERSION+"/auth/public-key", func(c fiber.Ctx) error {
		publicKey, err := auth.GetPublicKey()
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusInternalServerError, "failed to get public key", nil, err)
		}

		return helper.ReturnResponse(c, fiber.StatusOK, "public key retrieved successfully", model.PublicKeyResponse{
			PublicKey: publicKey,
		}, nil)
	})

	app.Post(helper.API_VERSION+"/auth/generate-pubkey", func(c fiber.Ctx) error {
		publicKey, err := auth.GetPublicKey()
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusInternalServerError, "failed to get public key", nil, err)
		}

		original := "admin@yopmail.com|44a44b44-d001-4798-be63-d5c9905e25b9|passwordnyaini"

		// Encrypt
		encrypted, err := helper.EncodeRSA(original)
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusInternalServerError, "failed to get public key", nil, err)
		}

		log.Println("Encrypted:")
		log.Println(encrypted)

		// Decrypt
		decrypted, err := helper.DecodeRSA(encrypted)
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusInternalServerError, "failed to get public key", nil, err)
		}

		log.Println("Decrypted:")
		log.Println(string(decrypted))

		if string(decrypted) != original {
			if err != nil {
				return helper.ReturnResponse(c, fiber.StatusInternalServerError, "failed to get public key", nil, err)
			}
		}

		return helper.ReturnResponse(c, fiber.StatusOK, "public key retrieved successfully", model.PublicKeyResponse{
			PublicKey: publicKey,
		}, nil)
	})

	// child route setup
	SetupUserManagementRoutes(app, helper.API_VERSION)

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(app.Listen(":" + port))
}
