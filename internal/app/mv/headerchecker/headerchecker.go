package headerchecker

import (
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/labstack/echo/v4"
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
