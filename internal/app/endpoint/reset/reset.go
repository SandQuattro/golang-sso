package reset

import (
	"crypto/rand"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"net/http"
	"sso/internal/app/crypto"
	"sso/internal/app/interfaces"
	"sso/internal/app/structs"
	"sso/internal/app/utils"
	"strings"
)

const AUTHORIZATION = "Authorization"

type Endpoint struct {
	config *hocon.Config
	users  interfaces.UserService
}

func New(config *hocon.Config, users interfaces.UserService) *Endpoint {
	// Создаем endpoint и возвращаем
	return &Endpoint{config, users}
}

func (e *Endpoint) ResetHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> ResetHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "password reset handler")
	defer span.Finish()

	email := make(map[string]string)
	err := ctx.Bind(&email)
	if err != nil {
		return err
	}
	if _, ok := email["email"]; !ok {
		logger.Error("<< ResetHandler error, email parameter required")
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: "email parameter required"})
	}

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)
	// проверяем наличие пользователя с такой почтой
	user, err := e.users.FindUserByLogin(c, email["email"])
	if err != nil {
		logger.Error(fmt.Errorf("user searching error, reason: %s", err.Error()))
		logger.Info("<< ResetHandler done.")
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	if user == nil {
		logger.Error(fmt.Errorf("user not found"))
		logger.Info("<< ResetHandler done.")
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Code: 9, Error: "пользователь отсутствует в БД"})
	}

	code := utils.GenerateCode(20)
	err = utils.CreateTask(e.config, span, utils.TypePasswordReset, user.Name, user.Email, -1, fmt.Sprintf("Перейди по ссылке для сброса пароля: %s%s", strings.ReplaceAll(e.config.GetString("verification.reset.address"), "\"", ""), code))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
	}

	// записываем в БД код для подтверждения почты и user_id
	// после верификации почты меняется статус на активированный
	err = e.users.CreateUserNotification(c, user.ID, "password_reset", code)
	if err != nil {
		logger.Error("<< CreateHandler error, creating user notification", err)
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	logger.Info("<< ResetHandler done.")
	return ctx.JSON(http.StatusOK, map[string]string{"message": "на указанную вами почту направлено письмо для сброса пароля"})
}

func (e *Endpoint) PasswordResetValidateHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> PasswordResetHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "password reset handler")
	defer span.Finish()

	pwdReset := make(map[string]string)
	err := ctx.Bind(&pwdReset)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: "некорректный запрос"})
	}
	code, ok := pwdReset["code"]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: "не указан код"})
	}
	pwd1, ok := pwdReset["pwd1"]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: "не указан пароль"})
	}
	pwd2, ok := pwdReset["pwd2"]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: "не указан пароль"})
	}
	if pwd1 != pwd2 {
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: "пароли не совпадают"})
	}

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	notification, err := e.users.GetUserNotificationByTypeAndCode(c, "password_reset", code)
	if err != nil {
		logger.Error("<< PasswordResetHandler error", err)
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	if notification == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, structs.ErrorResponse{Error: "неверный код подтверждения"})
	}

	user, err := e.users.FindUserById(c, notification.UserID)
	if err != nil {
		logger.Error(fmt.Errorf("user searching error, reason: %s", err.Error()))
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	if user == nil {
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: "пользователь не найден"})
	}

	salt := make([]byte, 8)
	_, err = rand.Read(salt)
	if err != nil {
		logger.Error("Ошибка заполнения salt slice, ", err.Error())
		span.SetTag("error", true)
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	hashedPwd := crypto.HashArgon2(salt, pwd1, 32)

	err = e.users.UpdateUserPassword(c, code, notification.UserID, hashedPwd)
	if err != nil {
		logger.Error("<< PasswordResetHandler error", err)
		return echo.NewHTTPError(http.StatusBadRequest, structs.ErrorResponse{Error: err.Error()})
	}

	logger.Info("<< PasswordResetHandler done")
	return ctx.JSON(http.StatusOK, map[string]string{"message": "пароль успешно изменен"})
}
