package mv

import (
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	jwtverification "github.com/SandQuattro/jwt-verification"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go/log"
	"github.com/redis/go-redis/v9"
	"net/http"
	"strings"
)

const AUTHORIZATION = "Authorization"

func HeaderPrinter() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			if strings.Compare(ctx.Request().RequestURI, "/sso/metrics") == 0 {
				return next(ctx)
			}

			logger := logdoc.GetLogger()

			for key, val := range ctx.Request().Header {
				logger.Debug("header ", key, ":", val)
			}

			return next(ctx)
		}
	}
}

func HeaderCheck(config func() *hocon.Config, rdb *redis.Client, jwt *jwtverification.JwtService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			span := jaegertracing.CreateChildSpan(ctx, "header checker middleware")
			defer span.Finish()

			logger := logdoc.GetLogger()
			logger.Debug(">> Header check Middleware started...")

			r := rdb
			if !config().GetBoolean("jwt.redis") {
				r = nil
			}

			token := ctx.Request().Header.Get(AUTHORIZATION)
			if token == "" {
				cookie, err := ctx.Cookie("token")
				if (cookie != nil || err == nil) && cookie.Name == "token" {
					token = cookie.Value
				} else {
					span.LogFields(log.String("auth cookie", "not available"))
				}
			}
			if token != "" {
				claims, isValid, err := jwt.ValidateToken(token, config().GetString("jwt.pem.public"), r)
				if !isValid && err != nil {
					logger.Errorf("token validation error: %s", err.Error())
					return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
				}

				// Кладем нужные нам данные в контекст и используем далее в хендлерах
				ctx.Set("claims", claims)

				err = next(ctx)
				if err != nil {
					logger.Error("error executing handler from mv")
					return err
				}

				logger.Debug("<< Header check Middleware done")
				return nil
			}
			return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
		}
	}
}

func AdminHeaderCheck(config func() *hocon.Config, rdb *redis.Client, jwt *jwtverification.JwtService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			span := jaegertracing.CreateChildSpan(ctx, "header checker middleware")
			defer span.Finish()

			logger := logdoc.GetLogger()
			logger.Debug(">> Header check Middleware started...")

			r := rdb
			if !config().GetBoolean("jwt.redis") {
				r = nil
			}

			token := ctx.Request().Header.Get(AUTHORIZATION)
			if token == "" {
				cookie, err := ctx.Cookie("token")
				if cookie != nil || err == nil {
					token = cookie.Value
				} else {
					span.LogFields(log.String("auth cookie", "not available"))
				}
			}

			if token != "" {
				claims, isValid, err := jwt.ValidateToken(token, config().GetString("jwt.pem.public"), r)
				if !isValid && err != nil {
					logger.Errorf("token validation error: %s", err.Error())
					return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
				}

				if claims["rol"] != "admin" {
					return echo.NewHTTPError(http.StatusUnauthorized, "Please provide admin credentials")
				}

				// Кладем нужные нам данные в контекст и используем далее в хендлерах
				ctx.Set("claims", claims)

				err = next(ctx)
				if err != nil {
					logger.Error("error executing handler from mv")
					return err
				}

				logger.Debug("<< Header check Middleware done")
				return nil
			}
			return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
		}
	}
}
