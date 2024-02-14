package headerchecker

import (
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/labstack/echo/v4"
	"net/http"
	"sso/internal/app/service/jwtservice"
	"strings"
)

const AUTHORIZATION = "Authorization"

func HeaderCheck(service *jwtservice.JwtService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			logger := logdoc.GetLogger()
			logger.Debug(">> Header check Middleware started...")

			token := ctx.Request().Header.Get(AUTHORIZATION)
			if token != "" {
				claims, isValid, err := service.ValidateToken(token)
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
