package v1

import (
	"errors"
	"strings"

	"gakuren-system.com/pkg/auth"
	"gakuren-system.com/pkg/db"
	"gakuren-system.com/pkg/helper"
	"gakuren-system.com/pkg/model"
	"github.com/gofiber/fiber/v3"
)

func SetupUserManagementRoutes(app *fiber.App, version string) {
	prefix := "/" + strings.Trim(version, "/") + "/auth"
	app.Post(prefix+"/login", sessionGuard, func(c fiber.Ctx) error {
		payload := new(model.LoginPayload)
		if err := c.Bind().Body(payload); err != nil || strings.TrimSpace(payload.Email) == "" {
			return helper.ReturnResponse(c, 400, "Invalid request body", nil, nil)
		}
		encrypted := auth.BearerValue(c.Get("Authorization"))
		if encrypted == "" {
			return helper.ReturnResponse(c, 401, "Missing credentials", nil, nil)
		}
		password, err := helper.DecodeRSA(encrypted)
		if err != nil {
			return helper.ReturnResponse(c, 401, "Invalid credentials", nil, nil)
		}
		user, err := db.GetSingleDataByQuery[model.UserModel]("SELECT * FROM user_sch.user WHERE email=$1", payload.Email)
		if err != nil {
			return helper.ReturnResponse(c, 401, "Invalid credentials", nil, nil)
		}
		login, err := db.GetSingleDataByQuery[model.UserLoginModel]("SELECT * FROM user_sch.user_login WHERE username=$1", payload.Email)
		if err != nil {
			return helper.ReturnResponse(c, 401, "Invalid credentials", nil, nil)
		}
		valid, err := auth.VerifyPassword(user.Email+"|"+user.TenantUUID.String()+"|"+string(password), login.Password)
		if err != nil || !valid {
			return helper.ReturnResponse(c, 401, "Invalid credentials", nil, nil)
		}
		return issueSession(c, user.Email, "")
	})
	app.Post(prefix+"/refresh", sessionGuard, func(c fiber.Ctx) error {
		raw := c.Cookies("refresh_token")
		if raw == "" {
			return helper.ReturnResponse(c, 401, "Session required", nil, nil)
		}
		return issueSession(c, "", raw)
	})
	app.Post(prefix+"/logout", sessionGuard, func(c fiber.Ctx) error {
		if err := auth.RevokeSession(c.Context(), c.Cookies("refresh_token")); err != nil {
			return helper.ReturnResponse(c, 500, "Unable to revoke session; retry logout", nil, err)
		}
		clearRefreshCookie(c)
		return helper.ReturnResponse(c, 200, "Logout successful", nil, nil)
	})
	app.Post(prefix+"/validate-token", RequirePermission(""), func(c fiber.Ctx) error {
		return helper.ReturnResponse(c, 200, "Token valid", c.Locals("claims"), nil)
	})
}

func issueSession(c fiber.Ctx, email, raw string) error {
	data, refresh, expires, err := auth.IssueSession(c.Context(), email, raw)
	if errors.Is(err, auth.ErrRotated) {
		// Do not delete or replace the winning tab's cookie.
		return helper.ReturnResponse(c, 409, "Refresh already rotated; retry with current cookie", nil, nil)
	}
	if errors.Is(err, auth.ErrSession) {
		return helper.ReturnResponse(c, 401, "Invalid or expired session", nil, nil)
	}
	if err != nil {
		return helper.ReturnResponse(c, 500, "Unable to create session", nil, err)
	}
	setRefreshCookie(c, refresh, expires)
	return helper.ReturnResponse(c, 200, "Session ready", data, nil)
}
