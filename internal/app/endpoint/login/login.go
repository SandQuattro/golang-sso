package login

import (
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	"sso/internal/app/crypto"
	"sso/internal/app/interfaces"
	"sso/internal/app/structs"
	"sso/internal/app/utils"
)

type Endpoint struct {
	config              *hocon.Config
	us                  interfaces.UserService
	jwt                 interfaces.JwtService
	successLoginCounter prometheus.Counter
	failedLoginCounter  prometheus.Counter
}

func New(config *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *Endpoint {
	logger := logdoc.GetLogger()
	successLoginCounter := prometheus.NewCounter( // create new counter metric. This is replacement for `prometheus.Metric` struct
		prometheus.CounterOpts{
			Subsystem: "demo_sso",
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
			Subsystem: "demo_sso",
			Name:      "failed_login_attempts_total",
			Help:      "How many failed login attempts.",
		},
	)
	// register your new counter metric with default metrics registry
	if err := prometheus.Register(failedLoginCounter); err != nil {
		logger.Fatal(err)
	}
	return &Endpoint{
		config:              config,
		us:                  us,
		jwt:                 jwt,
		successLoginCounter: successLoginCounter,
		failedLoginCounter:  failedLoginCounter,
	}
}

func (login *Endpoint) LoginHandler(ctx echo.Context) error {
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
		return echo.ErrUnauthorized
	}

	span.LogKV("login", user.Login)
	span.SetTag("handler", "login")

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := login.us.FindUserByLogin(c, user.Login)
	if err != nil {
		logger.Error(fmt.Errorf("user not found, reason: %s", err.Error()))
		logger.Info("<< LoginHandler done.")
		login.failedLoginCounter.Inc()
		return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
	}

	if u == nil {
		span.SetTag("error", true)
		span.LogKV("error.message", "пользователь "+user.Login+" отсутствует в БД")
		err := utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, user.Login, user.Login, -1, fmt.Sprintf("Attention required! Error in user service, account login error: %s not found in database", user.Login))
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
		}
		return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Code: 9, Error: "пользователь отсутствует в БД"})
	}

	// Сначала проверяем пароль на корректность
	if !crypto.ComparePass(u.Password, user.Password) {
		login.failedLoginCounter.Inc()
		err := utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, u.Name, u.Email, u.ID, fmt.Sprintf("Attention required! Error in user service, account login error: invalid password for user %s", u.Email))
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
		}
		return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Error: fmt.Sprintf("неверно указан пароль пользователя %s", u.Email)})
	}

	// затем подтверждена ли почта
	if !u.EmailVerified {
		return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Code: 8, Error: fmt.Sprintf("пользователь %s не подтвердил почту", u.Email)})
	}

	isSubscriptionValid, err := utils.ValidateUserSubscription(c, u)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
	}

	// и в конце уже проверяем подписку
	if !isSubscriptionValid {
		return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Code: 4, Error: fmt.Sprintf("срок действия подписки истек для пользователя %s", u.Email)})
	}

	t, _, err := login.jwt.CreateJwtToken(u)
	if err != nil || t == "" {
		logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
		logger.Info("<< LoginHandler done.")
		login.failedLoginCounter.Inc()
		err := utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, u.Name, u.Email, u.ID, fmt.Sprintf("Attention required! Error in user service, create jwt error: %s", err.Error()))
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
		}
		return echo.NewHTTPError(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
	}

	res := &structs.AuthRes{
		Token: t,
	}

	logger.Info("<< LoginHandler done.")
	login.successLoginCounter.Inc()
	err = utils.CreateTask(login.config, span, utils.TypeTelegramDelivery, user.Login, user.Login, -1, fmt.Sprintf("Account login successful: %s", user.Login))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, structs.ErrorResponse{Error: err.Error()})
	}
	return ctx.JSON(http.StatusOK, res)
}
