package app

import (
	"context"
	"fmt"
	jwtverification "github.com/SandQuattro/jwt-verification"
	"golang.org/x/time/rate"
	"sso/internal/app/endpoint"
	"sso/internal/app/mv"
	"sso/internal/app/service"
	"sso/internal/app/utils"
	echopprof "sso/internal/pprof"
	"strings"
	"time"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type App struct {
	port   string
	db     *sqlx.DB
	rdb    *redis.Client
	config func() *hocon.Config
	Echo   *echo.Echo

	// endpoints
	root        *endpoint.RootEndpoint
	maintenance *endpoint.MaintenanceEndpoint
	profile     *endpoint.ProfileEndpoint
	create      *endpoint.CreateEndpoint
	login       *endpoint.LoginEndpoint
	refresh     *endpoint.RefreshEndpoint
	reset       *endpoint.ResetEndpoint

	// oauth
	google *endpoint.GoogleEndpoint
	mailru *endpoint.MailRuEndpoint
	vk     *endpoint.VKEndpoint
	yandex *endpoint.YandexEndpoint

	// services
	jwt *service.JwtService
	u   *service.UserService
}

var logger *logrus.Logger

func New(ctx context.Context, config func() *hocon.Config, port string, rdb *redis.Client, db *sqlx.DB) (*App, error) {
	logger = logdoc.GetLogger()

	a := App{port: port, config: config, db: db, rdb: rdb}

	a.jwt = service.NewJWTService(ctx, config, rdb, db)
	a.u = service.NewUserService(config, db)

	// endpoints
	a.root = endpoint.NewRootEndpoint()

	a.maintenance = endpoint.NewMaintenanceEndpoint(rdb)

	a.login = endpoint.NewLoginEndpoint(config, a.u, a.jwt)
	a.google = endpoint.NewGoogleEndpoint(config, a.u, a.jwt)
	a.mailru = endpoint.NewMailRuEndpoint(config, a.u, a.jwt)
	a.vk = endpoint.NewVKEndpoint(config, a.u, a.jwt)
	a.yandex = endpoint.NewYandexEndpoint(config, a.u, a.jwt)

	a.create = endpoint.NewCreateEndpoint(config, a.jwt, a.u)
	a.refresh = endpoint.NewRefreshEndpoint(config, db, rdb, a.jwt, a.u)
	a.reset = endpoint.NewResetEndpoint(config, a.u)

	jwtVerificationService := jwtverification.New(config, logger, jwtverification.PEM)
	a.profile = endpoint.NewProfileEndpoint(jwtVerificationService, db, rdb)

	// Echo instance
	a.Echo = echo.New()

	if a.config().GetBoolean("debug") {
		echopprof.Wrap(a.Echo)
		a.Echo.Use(mv.HeaderPrinter())
	}

	// Global Endpoints Middleware
	// Вызов перед каждым обработчиком
	// В них может быть логгирование,
	// поверка токенов, ролей, прав и многое другое
	// TODO: !!! пофиксить на боевом корсы !!!

	// Проверяем, установлен ли режим обслуживания
	// отклоняем все запросы
	a.Echo.Use(mv.Maintenance(rdb))

	a.Echo.Use(mv.CORS())

	// rate limiter
	store := middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
		Rate:  rate.Limit(config().GetInt("rate.limit")),
		Burst: config().GetInt("rate.burst"),
	})
	rateConfig := middleware.RateLimiterConfig{
		Store: store,
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			// by default, we have an ctx.RealIP() in identifier extracted by IdentifierExtractor func
			logger.Warn(fmt.Sprintf(">> Rate Limiter Middleware > rate limiter access denied for %s, error:%v", identifier, err))
			rdb.Set(context.Request().Context(), "blocked:"+identifier, true, 10*time.Minute)
			return middleware.ErrRateLimitExceeded
		},
	}

	a.Echo.Use(mv.AntiDDOSProtection(rdb))
	a.Echo.Use(middleware.RateLimiterWithConfig(rateConfig))

	//// Teler Intrusion Detection MW
	//telerMiddleware := teler.New(
	//	teler.Options{
	//		//Development: true,
	//		Whitelists: []string{
	//			`request.IP in ["127.0.0.1", "::1", "0.0.0.0"]`,
	//			`request.URI matches "^/(login|create)?$"`,
	//			`request.URI matches "^/oauth/.*$"`,
	//			`request.Headers matches "(curl|PostmanRuntime)/*" && threat == BadCrawler`,
	//		},
	//	},
	//)
	//a.Echo.Use(echo.WrapMiddleware(telerMiddleware.Handler))

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
	a.Echo.Use(echoprometheus.NewMiddleware("sso"))
	a.Echo.GET("/sso/metrics", echoprometheus.NewHandler())

	// Routes
	a.Echo.GET("/", a.root.RootHandler)
	a.Echo.GET("/maintenance", a.maintenance.MaintenanceHandler)
	a.Echo.POST("/maintenance", a.maintenance.SaveMaintenanceHandler, mv.AdminHeaderCheck(config, rdb, jwtVerificationService))
	a.Echo.DELETE("/maintenance", a.maintenance.StopMaintenanceHandler, mv.AdminHeaderCheck(config, rdb, jwtVerificationService))

	a.Echo.POST("/login", a.login.LoginHandler)
	a.Echo.POST("/create", a.create.CreateHandler)
	a.Echo.GET("/refresh", a.refresh.RefreshHandler)

	a.Echo.GET("/user/profile", a.profile.ProfileHandler, mv.HeaderCheck(config, rdb, jwtVerificationService))
	a.Echo.POST("/user/profile", a.profile.SaveProfileHandler, mv.HeaderCheck(config, rdb, jwtVerificationService))

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
	// oauth2 Yandex
	a.Echo.GET("/oauth/yandex/url", a.yandex.YandexAuthGetCodeHandler)
	a.Echo.GET("/oauth/yandex/login", a.yandex.YandexAuthLoginHandler)

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
