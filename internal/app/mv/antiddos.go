package mv

import (
	"context"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"net/http"
	"sso/internal/app/endpoint"
	"sso/internal/app/errs"
)

func AntiDDOSProtection(rdb *redis.Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger := logdoc.GetLogger()

			ip := c.RealIP()

			ctx := context.Background()
			isBlocked, err := rdb.Get(ctx, "blocked:"+ip).Bool()

			if err == nil && isBlocked {
				// IP заблокирован
				logger.Error(fmt.Sprintf("user with ip %s temporarily blocked", ip))

				return endpoint.APIErrorSilent(http.StatusForbidden, errs.TemporaryBlocked)
			}

			return next(c)
		}
	}
}
