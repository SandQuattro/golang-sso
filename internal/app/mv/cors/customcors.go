package customcors

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

func CORS() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			allowedOrigins := []string{"http://localhost:3000"}
			for _, origin := range allowedOrigins {
				if ctx.Request().Header.Get("Origin") == origin {
					ctx.Response().Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
			ctx.Response().Header().Set("Access-Control-Allow-Credentials", "true")
			ctx.Response().Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			ctx.Response().Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

			if ctx.Request().Method == "OPTIONS" {
				return echo.NewHTTPError(http.StatusNoContent, nil)
			}

			err := next(ctx)
			if err != nil {
				return err
			}

			return nil
		}
	}
}
