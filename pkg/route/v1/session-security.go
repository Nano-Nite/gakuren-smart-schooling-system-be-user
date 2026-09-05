package v1

import (
	"mime"
	"net/url"
	"os"
	"strings"
	"time"

	"gakuren-system.com/pkg/auth"
	"gakuren-system.com/pkg/helper"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
)

func allowedOrigins() []string {
	origins := []string{}
	for _, value := range strings.Split(os.Getenv("FE_ALLOWED_ORIGINS"), ",") {
		value = strings.TrimSpace(value)
		parsed, err := url.Parse(value)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" &&
			parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && !strings.Contains(value, "*") {
			origins = append(origins, value)
		}
	}
	return origins
}

func installSessionSecurity(app *fiber.App) {
	app.Use(func(c fiber.Ctx) error {
		c.Set("Cache-Control", "no-store")
		return c.Next()
	})
	origins := allowedOrigins()
	// An empty CORS allowlist must fail closed, never fall back to wildcard.
	if len(origins) > 0 {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     origins,
			AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Content-Type", "Authorization", "X-Requested-With", "tenant_uuid", "school_uuid"},
			AllowCredentials: true, MaxAge: 3600,
		}))
	}
}

func sessionGuard(c fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	permitted := false
	for _, origin := range allowedOrigins() {
		if c.Get("Origin") == origin {
			permitted = true
			break
		}
	}
	if !permitted || c.Get("X-Requested-With") != "XMLHttpRequest" {
		return helper.ReturnResponse(c, 403, "Origin or CSRF header rejected", nil, nil)
	}
	mediaType, _, err := mime.ParseMediaType(c.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return helper.ReturnResponse(c, 415, "Content-Type must be application/json", nil, nil)
	}
	return c.Next()
}

func refreshCookie() *fiber.Cookie {
	sameSite := fiber.CookieSameSiteLaxMode
	if strings.EqualFold(os.Getenv("REFRESH_COOKIE_SAME_SITE"), "none") {
		sameSite = fiber.CookieSameSiteNoneMode
	}
	return &fiber.Cookie{Name: "refresh_token", Path: "/" + strings.Trim(helper.API_VERSION, "/") + "/auth",
		HTTPOnly: true, Secure: true, SameSite: sameSite}
}

func setRefreshCookie(c fiber.Ctx, raw string, expires time.Time) {
	cookie := refreshCookie()
	cookie.Value = raw
	cookie.Expires = expires
	cookie.MaxAge = int(time.Until(expires).Seconds())
	if cookie.MaxAge < 1 {
		cookie.MaxAge = 1
	}
	c.Cookie(cookie)
}

func clearRefreshCookie(c fiber.Ctx) {
	cookie := refreshCookie()
	cookie.MaxAge = -1 // net/http serializes this as Max-Age=0.
	cookie.Expires = time.Unix(1, 0)
	c.Cookie(cookie)
}

// Apply before every feature handler, passing its required permission code.
// The validation endpoint uses an empty permission but still requires scope.
func RequirePermission(permission string) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("Cache-Control", "no-store")
		raw := auth.BearerValue(c.Get("Authorization"))
		if raw == "" {
			return helper.ReturnResponse(c, 401, "Access token required", nil, nil)
		}
		claims, err := auth.ValidateAccessToken(raw)
		if err != nil {
			return helper.ReturnResponse(c, 401, "Invalid or expired access token", nil, nil)
		}
		if c.Get("tenant_uuid") != claims.TenantUUID || c.Get("school_uuid") != claims.SchoolUUID {
			return helper.ReturnResponse(c, 403, "Session scope mismatch", nil, nil)
		}
		if permission != "" {
			// Read current grants so a permission removal takes effect immediately.
			permissions, err := helper.GetUserRolePermissionCodeList(claims.Subject)
			if err != nil {
				return helper.ReturnResponse(c, 500, "Unable to verify permissions", nil, err)
			}
			permitted := false
			for _, code := range *permissions {
				if code == permission {
					permitted = true
					break
				}
			}
			if !permitted {
				return helper.ReturnResponse(c, 403, "Permission denied", nil, nil)
			}
		}
		c.Locals("claims", claims)
		return c.Next()
	}
}
