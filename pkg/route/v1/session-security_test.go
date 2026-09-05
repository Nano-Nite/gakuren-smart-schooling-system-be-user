package v1

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gakuren-system.com/pkg/helper"
	"github.com/gofiber/fiber/v3"
)

func TestSessionGuard(t *testing.T) {
	t.Setenv("FE_ALLOWED_ORIGINS", "https://app.example.com")
	for _, tc := range []struct {
		name, origin, header, content string
		status                        int
	}{
		{"valid", "https://app.example.com", "XMLHttpRequest", "application/json; charset=utf-8", 200},
		{"missing origin", "", "XMLHttpRequest", "application/json", 403},
		{"foreign origin", "https://evil.example.com", "XMLHttpRequest", "application/json", 403},
		{"suffix origin", "https://app.example.com.evil.test", "XMLHttpRequest", "application/json", 403},
		{"missing header", "https://app.example.com", "", "application/json", 403},
		{"simple content", "https://app.example.com", "XMLHttpRequest", "text/plain", 415},
		{"form content", "https://app.example.com", "XMLHttpRequest", "application/x-www-form-urlencoded", 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			called := false
			app.Post("/v1/auth/refresh", sessionGuard, func(c fiber.Ctx) error { called = true; return c.SendStatus(200) })
			req := httptest.NewRequest("POST", "/v1/auth/refresh", strings.NewReader("{}"))
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("X-Requested-With", tc.header)
			req.Header.Set("Content-Type", tc.content)
			res, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.status || called != (tc.status == 200) {
				t.Fatalf("status=%d handler called=%v", res.StatusCode, called)
			}
			if res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

func TestCORS(t *testing.T) {
	t.Setenv("FE_ALLOWED_ORIGINS", "https://app.example.com")
	app := fiber.New()
	installSessionSecurity(app)
	for _, origin := range []string{"https://app.example.com", "https://evil.example.com"} {
		req := httptest.NewRequest("OPTIONS", "/v1/auth/refresh", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type,authorization,x-requested-with,tenant_uuid,school_uuid")
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if origin == "https://app.example.com" {
			if res.Header.Get("Access-Control-Allow-Origin") != origin || res.Header.Get("Access-Control-Allow-Credentials") != "true" {
				t.Fatal(res.Header)
			}
			for _, h := range []string{"content-type", "authorization", "x-requested-with", "tenant_uuid", "school_uuid"} {
				if !strings.Contains(strings.ToLower(res.Header.Get("Access-Control-Allow-Headers")), h) {
					t.Fatalf("missing %s", h)
				}
			}
		} else if res.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("untrusted origin allowed")
		}
	}
}

func TestOriginConfigurationFailsClosed(t *testing.T) {
	t.Setenv("FE_ALLOWED_ORIGINS", "*,https://*.example.com,null,https://app.example.com/path")
	if len(allowedOrigins()) != 0 {
		t.Fatal(allowedOrigins())
	}
	app := fiber.New()
	installSessionSecurity(app)
	app.Post("/", sessionGuard, func(c fiber.Ctx) error { return c.SendStatus(200) })
	req := httptest.NewRequest("POST", "/", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	res, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 403 || res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal(res.StatusCode, res.Header)
	}
}

func TestRefreshCookieAndLogout(t *testing.T) {
	t.Setenv("FE_ALLOWED_ORIGINS", "https://app.example.com")
	for _, sameSite := range []string{"lax", "none"} {
		t.Run(sameSite, func(t *testing.T) {
			t.Setenv("REFRESH_COOKIE_SAME_SITE", sameSite)
			app := fiber.New()
			app.Post("/cookie", func(c fiber.Ctx) error {
				setRefreshCookie(c, "opaque", time.Now().Add(time.Hour))
				return c.SendStatus(200)
			})
			SetupUserManagementRoutes(app, helper.API_VERSION)
			res, err := app.Test(httptest.NewRequest("POST", "/cookie", nil))
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			cookies := res.Cookies()
			if len(cookies) != 1 {
				t.Fatal(cookies)
			}
			cookie := cookies[0]
			if !cookie.HttpOnly || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/"+strings.Trim(helper.API_VERSION, "/")+"/auth" || cookie.MaxAge <= 0 {
				t.Fatal(cookie)
			}
			want := http.SameSiteLaxMode
			if sameSite == "none" {
				want = http.SameSiteNoneMode
			}
			if cookie.SameSite != want {
				t.Fatal(cookie)
			}
			// No email, bearer token, scope, or cookie is needed for idempotent logout.
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest("POST", "/"+strings.Trim(helper.API_VERSION, "/")+"/auth/logout", strings.NewReader("{}"))
				req.Header.Set("Origin", "https://app.example.com")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
				res, err = app.Test(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatal(string(body))
				}
				var envelope map[string]interface{}
				if err = json.Unmarshal(body, &envelope); err != nil || envelope["error"] != false {
					t.Fatal(string(body), err)
				}
				deleted := res.Cookies()[0]
				if deleted.Path != cookie.Path || deleted.Domain != cookie.Domain || !deleted.HttpOnly || !deleted.Secure || deleted.MaxAge != -1 {
					t.Fatal(deleted)
				}
			}
		})
	}
}

func TestMissingTokensNeverReachDatabase(t *testing.T) {
	t.Setenv("FE_ALLOWED_ORIGINS", "https://app.example.com")
	app := fiber.New()
	SetupUserManagementRoutes(app, "v1")
	for _, path := range []string{"refresh", "validate-token"} {
		req := httptest.NewRequest("POST", "/v1/auth/"+path, strings.NewReader("{}"))
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Fatal(path, res.StatusCode)
		}
	}
}
