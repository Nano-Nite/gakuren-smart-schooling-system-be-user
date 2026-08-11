package v1

import (
	"log"
	"strings"

	"gakuren-system.com/pkg/auth"
	"gakuren-system.com/pkg/db"
	"gakuren-system.com/pkg/helper"
	"gakuren-system.com/pkg/model"
	"github.com/gofiber/fiber/v3"
)

func SetupUserManagementRoutes(app *fiber.App, API_VERSION string) {
	app.Post(API_VERSION+"/auth/public-key", func(c fiber.Ctx) error {
		publicKey, err := auth.GetPublicKey()
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusInternalServerError, "failed to get public key", nil, err)
		}

		return helper.ReturnResponse(c, fiber.StatusOK, "public key retrieved successfully", model.PublicKeyResponse{
			PublicKey: publicKey,
		}, nil)
	})

	app.Post(API_VERSION+"/auth/generate-pubkey", func(c fiber.Ctx) error {
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

	app.Post(API_VERSION+"/auth/login", func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		payload := new(model.LoginPayload)

		//* validate header
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return helper.ReturnResponse(c, fiber.StatusUnauthorized, "Missing or invalid token", nil, nil)
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		//* validate body
		if err := c.Bind().Body(payload); err != nil {
			return helper.ReturnResponse(c, fiber.StatusUnauthorized, "Missing or invalid token", nil, err)
		}

		//* decode RSA
		pwd, err := helper.DecodeRSA(tokenString)
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusNotFound, "Fail to parse token", nil, err)
		}

		//* get user by email
		selectedUser, err := db.GetSingleDataByQuery[model.UserModel]("select * from public.user where email = $1", payload.Email)
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusNotFound, "Fail to get data", nil, nil)
		}

		//* get user login by username
		selectedUserLogin, err := db.GetSingleDataByQuery[model.UserLoginModel]("select * from public.user_login where username = $1", payload.Email)
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusNotFound, "Fail to get data", nil, nil)
		}

		// log.Println(selectedUser)
		// log.Println(selectedUserLogin)

		userPassword := selectedUser.Email + "|" + selectedUser.TenantUUID.String() + "|" + string(pwd)

		// hashPwd, err := auth.HashPassword(userPassword)
		// if err != nil {
		// 	return helper.ReturnResponse(c, fiber.StatusNotFound, "Fail to parse token", nil, err)
		// }

		// log.Println(string(pwd))
		// log.Println(hashPwd)

		_, err = auth.VerifyPassword(userPassword, selectedUserLogin.Password)
		if err != nil {
			return helper.ReturnResponse(c, fiber.StatusNotFound, "Fail to parse token", nil, err)
		}

		// log.Println(ok)

		return helper.ReturnResponse(c, fiber.StatusOK, "Login Success", selectedUser, nil)
	})
}
