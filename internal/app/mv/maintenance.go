package mv

import (
	"context"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"net/http"
	"sso/internal/app/endpoint"
	"sso/internal/app/errs"
)

func Maintenance(rdb *redis.Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// игнорим маршрут maintenance
			if c.Request().URL.Path == "/maintenance" {
				return next(c)
			}

			logger := logdoc.GetLogger()

			ctx := context.Background()
			maintenance, err := rdb.Get(ctx, "maintenance").Bool()

			if err == nil && maintenance {
				logger.Warn("system in maintenance mode")

				return endpoint.APIErrorSilent(http.StatusServiceUnavailable, errs.MaintenanceMode)
			}

			return next(c)
		}
	}
}
