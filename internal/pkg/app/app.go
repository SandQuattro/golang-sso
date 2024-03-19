package app

import (
	"context"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/jmoiron/sqlx"
	"github.com/kitabisa/teler-waf"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"sso/internal/app/endpoint/auth/google"
	"sso/internal/app/endpoint/auth/mailru"
	"sso/internal/app/endpoint/auth/vk"
	"sso/internal/app/endpoint/create"
	"sso/internal/app/endpoint/login"
	"sso/internal/app/endpoint/refresh"
	"sso/internal/app/endpoint/reset"
	"sso/internal/app/endpoint/root"
	customcors "sso/internal/app/mv/cors"
	"sso/internal/app/mv/headerchecker"
	"sso/internal/app/service/jwtservice"
	"sso/internal/app/service/userservice"
	"sso/internal/app/utils"
	echopprof "sso/internal/pprof"
	"strings"
	"time"
)

type App struct {
	port    string
	db      *sqlx.DB
	config  *hocon.Config
	Echo    *echo.Echo
	root    *root.Endpoint
	google  *google.Endpoint
	mailru  *mailru.Endpoint
	vk      *vk.Endpoint
	create  *create.Endpoint
	login   *login.Endpoint
	refresh *refresh.Endpoint
	reset   *reset.Endpoint

	jwt *jwtservice.JwtService
	u   *userservice.UserService
}

var logger *logrus.Logger

func New(ctx context.Context, config *hocon.Config, port string, rdb *redis.Client, db *sqlx.DB) (*App, error) {
	logger = logdoc.GetLogger()

	a := App{port: port, config: config, db: db}

	a.jwt = jwtservice.New(ctx, config, rdb, db)
	a.u = userservice.New(config, db)

	a.root = root.New()
	a.google = google.New(config, a.u, a.jwt)
	a.mailru = mailru.New(config, a.u, a.jwt)
	a.vk = vk.New(config, a.u, a.jwt)
	a.create = create.New(config, a.jwt, a.u)
	a.login = login.New(config, a.u, a.jwt)
	a.refresh = refresh.New(a.jwt)
	a.reset = reset.New(config, a.u)

	// Echo instance
	a.Echo = echo.New()

	if a.config.GetBoolean("debug") {
		echopprof.Wrap(a.Echo)
		a.Echo.Use(headerchecker.HeaderPrinter())
	}

	// rate limiter
	store := middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
		Rate: 20,
	})
	rateConfig := middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store:   store,
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			return middleware.ErrRateLimitExceeded
		},
	}
	a.Echo.Use(middleware.RateLimiterWithConfig(rateConfig))

	// Global Endpoints Middleware
	// Вызов перед каждым обработчиком
	// В них может быть логгирование,
	// поверка токенов, ролей, прав и многое другое
	// TODO: !!! пофиксить на боевом корсы !!!
	a.Echo.Use(customcors.CORS())

	//// Teler Intrusion Detection MW
	telerMiddleware := teler.New(
		teler.Options{
			//Development: true,
			Whitelists: []string{
				`request.IP in ["127.0.0.1", "::1", "0.0.0.0"]`,
				`request.URI matches "^/(login|create)?$"`,
				`request.URI matches "^/oauth/.*$"`,
				`request.Headers matches "(curl|PostmanRuntime)/*" && threat == BadCrawler`,
			},
		},
	)
	a.Echo.Use(echo.WrapMiddleware(telerMiddleware.Handler))

	a.Echo.Use(middleware.RequestID())

	a.Echo.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		Skipper: func(c echo.Context) bool {
			return strings.Compare(c.Request().RequestURI, "/sso/metrics") == 0
		},
		LogUserAgent: true,
		LogReferer:   true,
		LogHost:      true,
		LogRequestID: true,
		LogRemoteIP:  true,
		LogURI:       true,
		LogStatus:    true,
		LogError:     true,
		HandleError:  true,
		LogValuesFunc: func(c echo.Context, values middleware.RequestLoggerValues) error {
			if values.Error != nil || values.Status > 399 {
				logger.WithFields(logrus.Fields{
					"error":     values.Error,
					"status":    values.Status,
					"ip":        values.RemoteIP,
					"reqId":     values.RequestID,
					"userAgent": values.UserAgent,
					"referer":   values.Referer,
					"host":      values.Host,
				}).Error(values.StartTime.Format(time.RFC3339Nano), " incoming request ", values.URI, " error:")
			} else {
				logger.WithFields(logrus.Fields{
					"ip":        values.RemoteIP,
					"reqId":     values.RequestID,
					"userAgent": values.UserAgent,
					"referer":   values.Referer,
					"host":      values.Host,
					"status":    values.Status,
				}).Debug(values.StartTime.Format(time.RFC3339Nano), " incoming request ", values.URI)
			}

			return nil
		},
	}))

	a.Echo.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		LogErrorFunc: func(c echo.Context, err error, stack []byte) error {
			logger.Error("Recovery from panic, ", err.Error(), "\n", string(stack))
			return err
		},
	}))

	// Metrics middleware
	a.Echo.Use(echoprometheus.NewMiddleware("demo_sso"))
	a.Echo.GET("/sso/metrics", echoprometheus.NewHandler())

	// Body dump mv captures the request and response payload and calls the registered handler.
	// Generally used for debugging/logging purpose.
	// Avoid using it if your request/response payload is huge e.g. file upload/download
	a.Echo.Use(middleware.BodyDumpWithConfig(middleware.BodyDumpConfig{
		Skipper: func(c echo.Context) bool {
			return strings.Compare(c.Request().RequestURI, "/login") == 0 ||
				strings.Contains(c.Request().RequestURI, "/debug/") ||
				strings.Contains(c.Request().RequestURI, "/sso/metrics")
		},
		Handler: func(c echo.Context, reqBody, resBody []byte) {
			logger.Debug(fmt.Sprintf(`>> BodyDump middleware
			request ip:%s
			request metod:%s
			request uri:%s
			request paylod (if any):%s
			response body:
%s`,
				c.RealIP(),
				c.Request().Method,
				c.Request().RequestURI,
				reqBody,
				resBody))
		},
	}))

	// Routes
	a.Echo.GET("/", a.root.RootHandler)
	a.Echo.POST("/login", a.login.LoginHandler)
	a.Echo.POST("/create", a.create.CreateHandler)
	a.Echo.GET("/refresh", a.refresh.RefreshHandler)
	a.Echo.GET("/email/verify", a.create.EmailVerifyHandler)
	a.Echo.POST("/password/reset", a.reset.ResetHandler)
	a.Echo.POST("/password/reset/validate", a.reset.PasswordResetValidateHandler)
	// oauth2 google
	a.Echo.GET("/oauth/google/url", a.google.GoogleAuthGetCodeHandler)
	a.Echo.GET("/oauth/google/login", a.google.GoogleAuthLoginHandler)
	// oauth2 mailru
	a.Echo.GET("/oauth/mailru/url", a.mailru.MailRuAuthGetCodeHandler)
	a.Echo.GET("/oauth/mailru/login", a.mailru.MailRuAuthLoginHandler)
	// oauth2 VK
	a.Echo.GET("/oauth/vk/url", a.vk.VKAuthGetCodeHandler)
	a.Echo.GET("/oauth/vk/login", a.vk.VKAuthLoginHandler)

	logger.Info("Application created!")

	return &a, nil
}

func (a *App) Run() error {
	closer := utils.Tracing(a.Echo)
	defer closer.Close()

	// Start server
	err := a.Echo.Start(":" + a.port)
	if err != nil {
		logger.Warn("Stopping server")
	}
	return nil
}
