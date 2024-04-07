package endpoint

import (
	"fmt"
	"net/http"
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
	"github.com/prometheus/client_golang/prometheus"
)

type LoginEndpoint struct {
	config              func() *hocon.Config
	us                  interfaces.UserService
	jwt                 interfaces.JwtService
	successLoginCounter prometheus.Counter
	failedLoginCounter  prometheus.Counter
}

func NewLoginEndpoint(config func() *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *LoginEndpoint {
	logger := logdoc.GetLogger()
	successLoginCounter := prometheus.NewCounter( // create new counter metric. This is replacement for `prometheus.Metric` struct
		prometheus.CounterOpts{
			Subsystem: "sso",
			Name:      "successful_login_attempts_total",
			Help:      "How many successful login attempts.",
		},
	)
	// register your new counter metric with default metrics registry
	if err := prometheus.Register(successLoginCounter); err != nil {
		logger.Fatal(err)
	}
	failedLoginCounter := prometheus.NewCounter( // create new counter metric.
		prometheus.CounterOpts{
			Subsystem: "sso",
			Name:      "failed_login_attempts_total",
			Help:      "How many failed login attempts.",
		},
	)
	// register your new counter metric with default metrics registry
	if err := prometheus.Register(failedLoginCounter); err != nil {
		logger.Fatal(err)
	}
	return &LoginEndpoint{
		config:              config,
		us:                  us,
		jwt:                 jwt,
		successLoginCounter: successLoginCounter,
		failedLoginCounter:  failedLoginCounter,
	}
}

func (login *LoginEndpoint) LoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> LoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "login handler")
	defer span.Finish()

	var user structs.IncomingUser
	if err := ctx.Bind(&user); err != nil {
		return err
	}

	// Throws unauthorized error
	if user.Login == "" || user.Password == "" {
		login.failedLoginCounter.Inc()
		return APIErrorSilent(http.StatusUnauthorized, errs.InvalidInputData)
	}

	span.LogKV("login", user.Login)
	span.SetTag("handler", "login")

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := login.us.FindUserByLogin(c, user.Login)
	if err != nil {
		logger.Error(fmt.Errorf("user not found, reason: %s", err.Error()))
		logger.Info("<< LoginHandler done.")
		login.failedLoginCounter.Inc()
		return APIErrorSilent(http.StatusForbidden, errs.UserGettingError)
	}

	if u == nil {
		span.SetTag("error", true)
		span.LogKV("error.message", "пользователь "+user.Login+" отсутствует в БД")
		err := utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, user.Login, user.Login, -1, fmt.Sprintf("Attention required! Error in user service, account login error: %s not found in database\nIP:%s", user.Login, ctx.RealIP()))
		if err != nil {
			logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
			return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
		}
		return APIErrorSilent(http.StatusForbidden, errs.AccessDenied)
	}

	// Сначала проверяем пароль на корректность
	if !crypto.ComparePass(u.Password, user.Password) {
		login.failedLoginCounter.Inc()
		err := utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, u.Name, u.Email, u.ID, fmt.Sprintf("Attention required! Error in user service, account login error: invalid password for user %s\nIP:%s", u.Email, ctx.RealIP()))
		if err != nil {
			logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
			return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
		}
		return APIErrorSilent(http.StatusForbidden, errs.AccessDenied)
	}

	// затем подтверждена ли почта
	if !u.EmailVerified {
		return APIErrorSilent(http.StatusForbidden, errs.AccessDenied)
	}

	isSubscriptionValid, err := utils.ValidateUserSubscription(c, u)
	if err != nil {
		return APIErrorSilent(http.StatusInternalServerError, errs.SubscriptionValidationError)
	}

	// и в конце уже проверяем подписку
	if !isSubscriptionValid {
		return APIErrorSilent(http.StatusForbidden, errs.SubscriptionValidationError)
	}

	t, err := login.jwt.CreateJwtToken(c, u)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
		logger.Info("<< LoginHandler done.")
		login.failedLoginCounter.Inc()
		err := utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, u.Name, u.Email, u.ID, fmt.Sprintf("Attention required! Error in user service, create jwt error: %s", err.Error()))
		if err != nil {
			logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
			return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
		}
		return APIErrorSilent(http.StatusForbidden, errs.AccessDenied)
	}

	logger.Info("<< LoginHandler done.")
	login.successLoginCounter.Inc()
	err = utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, user.Login, user.Login, -1, fmt.Sprintf("Account login successful: %s\nIP:%s", user.Login, ctx.RealIP()))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	return APISuccess(http.StatusOK, t)
}
