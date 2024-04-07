package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gurkankaymak/hocon"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"net/http"
	"sso/internal/app/errs"
	"sso/internal/app/interfaces"
	"sso/internal/app/repository"
	"sso/internal/app/service"
	"sso/internal/app/structs"
	"sso/internal/app/utils"
	"strconv"
	"time"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
)

const AUTHORIZATION = "Authorization"

type Token interface {
	FindToken(ctx context.Context, token string) (*structs.RefreshToken, error)
	CreateToken(ctx context.Context, userID int, token string, expiresIn int64) error
}

type RefreshEndpoint struct {
	config func() *hocon.Config
	rdb    *redis.Client
	jwt    interfaces.JwtService
	tokens *repository.TokenRepository
	users  *service.UserService
}

func NewRefreshEndpoint(config func() *hocon.Config, db *sqlx.DB, rdb *redis.Client, jwt interfaces.JwtService, users *service.UserService) *RefreshEndpoint {
	// Создаем endpoint и возвращаем
	tokens := repository.NewTokenRepository(db)
	return &RefreshEndpoint{config, rdb, jwt, tokens, users}
}

func (r *RefreshEndpoint) RefreshHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> RefreshHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "refresh handler")
	defer span.Finish()

	// получаем токен из redis, если его нет, он протух, возвращаем ошибку
	m := make(map[string]string)
	bytes, err := r.rdb.Get(ctx.Request().Context(), ctx.Request().Header.Get(AUTHORIZATION)).Bytes()
	if err != nil {
		return APIErrorSilent(http.StatusUnauthorized, errs.SessionExpired)
	}

	err = json.Unmarshal(bytes, &m)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.DecodingJSONError)
	}

	userID, err := strconv.Atoi(m["userId"])
	if err != nil {
		return APIErrorSilent(http.StatusInternalServerError, errs.InvalidInputData)
	}

	unixstamp, err := strconv.Atoi(m["timestamp"])
	if err != nil {
		return APIErrorSilent(http.StatusInternalServerError, errs.InvalidInputData)
	}

	user, err := r.users.FindUserById(ctx.Request().Context(), userID)
	if err != nil {
		return APIErrorSilent(http.StatusUnauthorized, errs.UserGettingError)
	}

	if user == nil {
		return APIErrorSilent(http.StatusUnauthorized, errs.UserGettingError)
	}

	timestamp := time.Unix(0, int64(unixstamp))
	refreshTokenExpiresIn := timestamp.Add(time.Minute*time.Duration(r.config().GetInt("jwt.refresh.expiredAfterMinutes"))).Unix() - timestamp.Unix()
	token, _, err := utils.GenerateRefreshToken(user, timestamp.UnixNano(), refreshTokenExpiresIn)
	if err != nil {
		return APIErrorSilent(http.StatusInternalServerError, errs.GenerateRefreshTokenError)
	}

	if token != ctx.Request().Header.Get(AUTHORIZATION) {
		return APIErrorSilent(http.StatusUnauthorized, errs.TokenMismatch)
	}

	var subscriptionInvalidatedError service.SubscriptionInvalidatedError

	_, err = utils.ValidateUserSubscription(ctx.Request().Context(), user)
	if err != nil {
		switch {
		case errors.As(err, &subscriptionInvalidatedError):
			logger.Error(fmt.Errorf("refresh failed, subscription invalidated"))
			logger.Info("<< RefreshHandler done.")
			return APIErrorSilent(http.StatusForbidden, errs.SubscriptionValidationError)
		default:
			logger.Error(fmt.Errorf("refresh failed, reason: %s", err.Error()))
			logger.Info("<< RefreshHandler done.")
			return APIErrorSilent(http.StatusForbidden, errs.RefreshTokenFailed)
		}
	}

	err = r.rdb.Del(ctx.Request().Context(), ctx.Request().Header.Get(AUTHORIZATION)).Err()
	if err != nil {
		return APIErrorSilent(http.StatusInternalServerError, errs.RedisError)
	}

	jwtToken, err := r.jwt.CreateJwtToken(ctx.Request().Context(), user)
	if err != nil {
		return err
	}

	logger.Info("<< RefreshHandler done.")
	return APISuccess(http.StatusOK, jwtToken)
}
