package create

import (
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"net/http"
	"sso/internal/app/interfaces"
	"sso/internal/app/structs"
	"sso/internal/app/utils"
	"strings"
)

type Endpoint struct {
	config *hocon.Config
	jwt    interfaces.JwtService
	us     interfaces.UserService
}

func New(config *hocon.Config, jwt interfaces.JwtService, us interfaces.UserService) *Endpoint {
	return &Endpoint{config: config, us: us, jwt: jwt}
}

func (e *Endpoint) CreateHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> CreateHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "create handler")
	defer span.Finish()

	var user structs.CreateUser
	if err := ctx.Bind(&user); err != nil {
		return err
	}

	span.LogKV("login", user.Email)
	span.SetTag("handler", "create")

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	var userID int
	dbuser, err := e.us.FindUserByLogin(c, user.Email)
	if err != nil {
		logger.Error(fmt.Errorf("user getting error, reason: %s", err.Error()))
		return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
	}

	if dbuser == nil {
		// Пользователь создается как неактивированный
		newuser, err := e.us.CreateUser(c, &user)
		if err != nil {
			logger.Error("<< CreateHandler error", err)
			return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
		}
		userID = int(newuser.ID)
	} else {
		// userID = dbuser.ID
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Code: 10, Error: "пользователь уже существует, подтвердите почту или сбросьте пароль"})
	}

	code := utils.GenerateCode(20)
	err = utils.CreateTask(e.config, span, utils.TypeEmailVerification, user.First+" "+user.Last, user.Email, -1, fmt.Sprintf("Перейди по ссылке %s%s", strings.ReplaceAll(e.config.GetString("verification.email.address"), "\"", ""), code))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
	}

	// записываем в БД код для подтверждения почты и user_id
	// после верификации почты меняется статус на активированный
	err = e.us.CreateUserNotification(c, userID, "email_verification", code)
	if err != nil {
		logger.Error("<< CreateHandler error, creating user notification", err)
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	//u, err := e.us.FindUserByLogin(c, newuser.Email)
	//if err != nil {
	//	logger.Error(fmt.Errorf("user not found, reason: %s", err.Error()))
	//	logger.Info("<< LoginHandler done.")
	//	return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
	//}
	//
	//t, _, err := e.jwt.CreateJwtToken(u)
	//if err != nil || t == "" {
	//	logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
	//	logger.Info("<< LoginHandler done.")
	//	return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
	//}
	//
	//res := &structs.AuthRes{
	//	Token: t,
	//}

	logger.Info("<< CreateHandler done")
	return ctx.JSON(http.StatusOK, map[string]string{"message": "на указанную вами почту направлено письмо для подтверждения регистрации"})
}

func (e *Endpoint) EmailVerifyHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> EmailVerifyHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "email verify handler")
	defer span.Finish()

	code := ctx.QueryParam("code")

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	notification, err := e.us.GetUserNotificationByTypeAndCode(c, "email_verification", code)
	if err != nil {
		logger.Error("<< EmailVerifyHandler error", err)
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	if notification == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, structs.ErrorResponse{Error: "неверный код подтверждения"})
	}

	user, err := e.us.ConfirmEmail(c, code, notification.UserID)
	if err != nil {
		logger.Error("<< EmailVerifyHandler error", err)
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	t, err := e.jwt.CreateJwtToken(user)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("creation jwt failed, reason: %s", err.Error()))
		logger.Info("<< EmailVerifyHandler done.")
		return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
	}

	res := &structs.AuthRes{
		Token: t["access_token"].(string),
	}

	logger.Info("<< EmailVerifyHandler done")
	return ctx.JSON(http.StatusOK, res)
}
