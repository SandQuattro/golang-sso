package refresh

import (
	"errors"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"net/http"
	"sso/internal/app/interfaces"
	"sso/internal/app/service/jwtservice"
	"sso/internal/app/structs"
)

const AUTHORIZATION = "Authorization"

type Endpoint struct {
	jwt interfaces.JwtService
}

func New(jwt interfaces.JwtService) *Endpoint {
	// Создаем endpoint и возвращаем
	return &Endpoint{jwt}
}

func (refresh *Endpoint) RefreshHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> RefreshHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "refresh handler")
	defer span.Finish()

	// Доп проверки не делаем, в middleware уже проверили наличие заголовка
	tokenHeader := ctx.Request().Header.Get(AUTHORIZATION)

	token, err := refresh.jwt.RefreshJwtToken(ctx, tokenHeader)
	if err != nil {
		var subscriptionInvalidatedError jwtservice.SubscriptionInvalidatedError
		switch {
		case errors.As(err, &subscriptionInvalidatedError):
			logger.Error(fmt.Errorf("refresh failed, subscription invalidated"))
			logger.Info("<< RefreshHandler done.")
			return ctx.JSON(http.StatusForbidden, structs.ErrorResponse{Code: 4, Error: err.Error()})
		default:
			logger.Error(fmt.Errorf("refresh failed, reason: %s", err.Error()))
			logger.Info("<< RefreshHandler done.")
			return ctx.JSON(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
		}
	}

	result := &structs.Token{
		Token: token,
	}
	logger.Info("<< RefreshHandler done.")
	return ctx.JSON(http.StatusOK, result)
}
