package endpoint

import (
	"errors"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"net/http"
	"sso/internal/app/errs"
)

type MaintenanceEndpoint struct {
	rdb *redis.Client
}

func NewMaintenanceEndpoint(rdb *redis.Client) *MaintenanceEndpoint {
	return &MaintenanceEndpoint{rdb}
}

func (e *MaintenanceEndpoint) MaintenanceHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> MaintenanceHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "get maintenance status handler")
	defer span.Finish()

	value, err := e.rdb.Get(ctx.Request().Context(), "maintenance").Bool()
	if errors.Is(err, redis.Nil) {
		logger.Info("<< MaintenanceHandler done.")
		return APISuccess(http.StatusOK, nil)
	}

	logger.Info("<< MaintenanceHandler done.")
	return APISuccess(http.StatusOK, value)
}

func (e *MaintenanceEndpoint) SaveMaintenanceHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> SaveMaintenanceHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "save maintenance handler")
	defer span.Finish()

	err := e.rdb.Set(ctx.Request().Context(), "maintenance", true, 0).Err()
	if err != nil {
		logger.Error("<< SaveMaintenanceHandler error, ", err)
		return APIErrorSilent(http.StatusInternalServerError, errs.RedisError)
	}

	return APISuccess(http.StatusOK, nil)
}

func (e *MaintenanceEndpoint) StopMaintenanceHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> StopMaintenanceHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "stop maintenance handler")
	defer span.Finish()

	err := e.rdb.Del(ctx.Request().Context(), "maintenance").Err()
	if err != nil {
		logger.Error("<< StopMaintenanceHandler error, ", err)
		return APIErrorSilent(http.StatusInternalServerError, errs.RedisError)
	}

	return APISuccess(http.StatusOK, nil)
}
