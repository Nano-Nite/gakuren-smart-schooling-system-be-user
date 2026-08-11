package v1

import (
	"log"
	"os"

	"gakuren-system.com/pkg/helper"
	"github.com/gofiber/fiber/v3"
)

func SetupRoutes() {
	app := fiber.New()

	app.Use(func(c fiber.Ctx) error {
		log.Printf("API hit: %s %s", c.Method(), c.OriginalURL())
		return c.Next()
	})

	app.Get("/", func(c fiber.Ctx) error {
		return c.SendString("ready to go !!!!!!!!!!")
	})

	// child route setup
	SetupUserManagementRoutes(app, helper.API_VERSION)

	log.Fatal(app.Listen(":" + os.Getenv("PORT")))
}
