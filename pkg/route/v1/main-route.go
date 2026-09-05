package v1

import (
	"log"
	"os"
	"strings"

	"gakuren-system.com/pkg/auth"
	"gakuren-system.com/pkg/helper"
	"gakuren-system.com/pkg/model"
	"github.com/gofiber/fiber/v3"
)

func SetupRoutes() {
	app := fiber.New()

	installSessionSecurity(app)

	app.Use(func(c fiber.Ctx) error {
		log.Printf("API hit : %s %s <> IP Address : %s <> User Agent : %s\n", c.Method(), c.OriginalURL(), c.IP(), c.UserAgent())

		return c.Next()
	})

	app.Get("/"+strings.Trim(helper.API_VERSION, "/")+"/auth/test", func(c fiber.Ctx) error {
		return c.SendString("ready to go !!!!!!!!!!")
	})

	app.Post("/"+strings.Trim(helper.API_VERSION, "/")+"/auth/public-key", func(c fiber.Ctx) error {
		publicKey, err := auth.GetPublicKey()
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusInternalServerError, "failed to get public key", nil, err)
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
