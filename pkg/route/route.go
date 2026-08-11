package route

import (
	"log"
	"os"

	"gakuren-system.com/pkg/auth"
	"gakuren-system.com/pkg/model"
	"github.com/gofiber/fiber/v3"
)

func SetupRoutes() {
	app := fiber.New()

	app.Get("/", func(c fiber.Ctx) error {
		return c.SendString("ready to go !!!!!!!!!!")
	})

	app.Post("/login", func(c fiber.Ctx) error {
		token, err := auth.AuthenticateBearerToken(c.Get("Authorization"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": err.Error(),
			})
		}

		return c.Status(fiber.StatusOK).JSON(model.LoginResponse{
			Message: "login successful",
			Token:   token,
		})
	})

	log.Fatal(app.Listen(":" + os.Getenv("PORT")))
}
