package endpoint

import (
	"fmt"
	"net/http"
	"regexp"
	"sso/internal/app/crypto"
	"sso/internal/app/errs"
	"sso/internal/app/interfaces"
	"sso/internal/app/structs"
	"sso/internal/app/utils"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"

	"strings"
)

type CreateEndpoint struct {
	config func() *hocon.Config
	jwt    interfaces.JwtService
	us     interfaces.UserService
}

func NewCreateEndpoint(config func() *hocon.Config, jwt interfaces.JwtService, us interfaces.UserService) *CreateEndpoint {
	return &CreateEndpoint{config: config, us: us, jwt: jwt}
}

func (e *CreateEndpoint) CreateHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> CreateHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "create handler")
	defer span.Finish()

	var user structs.CreateUser
	if err := ctx.Bind(&user); err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	if user.Email == "" || user.Password == "" {
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	// проверяем корректность почты
	re := regexp.MustCompile(`\+`)
	if re.MatchString(user.Email) {
		logger.Error(fmt.Sprintf("<< CreateHandler error, invalid email address %s", user.Email))
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	span.LogKV("login", user.Email)
	span.SetTag("handler", "create")

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	var userID int
	dbuser, err := e.us.FindUserByLogin(c, user.Email)
	if err != nil {
		logger.Error(fmt.Errorf("user getting error, reason: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.UserGettingError)
	}

	if dbuser == nil {
		// Пользователь создается как неактивированный
		newuser, err := e.us.CreateUser(c, &user)
		if err != nil {
			logger.Error("<< CreateHandler error", err)
			return APIErrorSilent(http.StatusBadRequest, errs.CreateUserError)
		}
		userID = int(newuser.ID)
	} else {
		// userID = dbuser.ID
		return APIErrorSilent(http.StatusBadRequest, errs.UserAlreadyExists)
	}

	code := crypto.GenerateCode(20)
	err = utils.CreateTask(e.config, span, utils.TypeEmailVerification, user.First+" "+user.Last, user.Email, -1, fmt.Sprintf("%s%s", strings.ReplaceAll(e.config().GetString("verification.email.address"), "\"", ""), code))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	// записываем в БД код для подтверждения почты и user_id
	// после верификации почты меняется статус на активированный
	err = e.us.CreateUserNotification(c, userID, "email_verification", code)
	if err != nil {
		logger.Error("<< CreateHandler error, creating user notification", err)
		return APIErrorSilent(http.StatusBadRequest, errs.CreateUserNotificationError)
	}

	err = utils.CreateTask(e.config, span, utils.TypeTelegramDelivery, user.Email, user.Email, userID, fmt.Sprintf("New user creation: %s, IP:%s", user.Email, ctx.RealIP()))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	logger.Info("<< CreateHandler done")
	return APISuccess(http.StatusOK, map[string]string{"message": "на указанную вами почту направлено письмо для подтверждения регистрации"})
}

func (e *CreateEndpoint) EmailVerifyHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> EmailVerifyHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "email verify handler")
	defer span.Finish()

	code := ctx.QueryParam("code")

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	notification, err := e.us.GetUserNotificationByTypeAndCode(c, "email_verification", code)
	if err != nil {
		logger.Error("<< EmailVerifyHandler error", err)
		return APIErrorSilent(http.StatusBadRequest, errs.GettingUserNotificationError)
	}

	if notification == nil {
		return APIErrorSilent(http.StatusForbidden, errs.InvalidNotificationCode)
	}

	user, err := e.us.ConfirmEmail(c, code, notification.UserID)
	if err != nil {
		logger.Error("<< EmailVerifyHandler error", err)
		return APIErrorSilent(http.StatusBadRequest, errs.EmailConfirmationError)
	}

	t, err := e.jwt.CreateJwtToken(c, user)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("creation jwt failed, reason: %s", err.Error()))
		logger.Info("<< EmailVerifyHandler done.")
		return APIErrorSilent(http.StatusForbidden, errs.JwtTokenCreationError)
	}

	err = utils.CreateTask(e.config, span, utils.TypeTelegramDelivery, user.Email, user.Email, user.ID, fmt.Sprintf("User email successfully verified: %s, IP: %s", user.Email, ctx.RealIP()))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	logger.Info("<< EmailVerifyHandler done")
	return APISuccess(http.StatusOK, t)
}
