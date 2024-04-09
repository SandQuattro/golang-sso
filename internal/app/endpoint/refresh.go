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

	refreshToken, err := ctx.Cookie("refresh_token")
	if err != nil && errors.Is(err, http.ErrNoCookie) {
		logger.Error(fmt.Errorf(">> RefreshHandler >  refresh token error: %w", err))
		return APIErrorSilent(http.StatusUnauthorized, errs.SessionExpired)
	}

	logger.Debug(">> RefreshHandler > got refresh token: ", refreshToken.Value)

	// получаем токен из redis, если его нет, он протух, возвращаем ошибку
	m := make(map[string]string)
	bytes, err := r.rdb.Get(ctx.Request().Context(), refreshToken.Value).Bytes()
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

	if token != refreshToken.Value {
		return APIErrorSilent(http.StatusUnauthorized, errs.TokenMismatch)
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
	return APISuccessWithRefreshToken(ctx, http.StatusOK, jwtToken)
}
