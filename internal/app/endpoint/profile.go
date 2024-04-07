package endpoint

import (
	"encoding/json"
	"errors"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	jwtverification "github.com/SandQuattro/jwt-verification"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"net/http"
	"sso/internal/app/errs"
	"sso/internal/app/repository"
	"strconv"
)

type ProfileEndpoint struct {
	jwt  *jwtverification.JwtService
	rdb  *redis.Client
	repo *repository.UserRepository
}

func NewProfileEndpoint(jwt *jwtverification.JwtService, db *sqlx.DB, rdb *redis.Client) *ProfileEndpoint {
	repo := repository.New(db)
	return &ProfileEndpoint{jwt, rdb, repo}
}

func (e *ProfileEndpoint) ProfileHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> ProfileHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "profile handler")
	defer span.Finish()

	claims := ctx.Get("claims").(jwt.MapClaims)
	userID := int(claims["id"].(float64))

	var result map[string]interface{}
	bytes, err := e.rdb.Get(ctx.Request().Context(), "profile:"+strconv.Itoa(userID)).Bytes()
	if errors.Is(err, redis.Nil) {
		result, err = e.repo.FindUserProfile(ctx.Request().Context(), userID)
		if err != nil {
			logger.Error("<< ProfileHandler error, ", err)
			return APIErrorSilent(http.StatusBadRequest, errs.RedisNotFoundError)
		}

		if result == nil {
			err = e.repo.CreateUserProfile(ctx.Request().Context(), userID, map[string]interface{}{"send_messages": 0})
			if err != nil {
				logger.Error("<< ProfileHandler error, ", err)
				return APIErrorSilent(http.StatusBadRequest, errs.CreateUserProfileError)
			}
			result, err = e.repo.FindUserProfile(ctx.Request().Context(), userID)
			if err != nil {
				logger.Error("<< ProfileHandler error, ", err)
				return APIErrorSilent(http.StatusBadRequest, errs.FindUserProfileError)
			}
		}

		jsonData, err := json.Marshal(result)
		if err != nil {
			return APIErrorSilent(http.StatusBadRequest, errs.EncodingJSONError)
		}

		_, err = e.rdb.Set(ctx.Request().Context(), "profile:"+strconv.Itoa(userID), jsonData, 0).Result()
		if err != nil {
			logger.Error("<< ProfileHandler error, ", err)
		}
		return APISuccess(http.StatusOK, result)
	}

	err = json.Unmarshal(bytes, &result)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.DecodingJSONError)
	}

	logger.Info("<< ProfileHandler done.")
	return APISuccess(http.StatusOK, result)
}

func (e *ProfileEndpoint) SaveProfileHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> SaveProfileHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "profile handler")
	defer span.Finish()

	claims := ctx.Get("claims").(jwt.MapClaims)
	userID := int(claims["id"].(float64))

	profile := make(map[string]interface{})
	err := ctx.Bind(&profile)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	if _, ok := profile["send_messages"]; !ok {
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	userProfile, err := e.repo.FindUserProfile(ctx.Request().Context(), userID)
	if err != nil {
		return APIErrorSilent(http.StatusInternalServerError, errs.FindUserProfileError)
	}

	userProfile["send_messages"] = profile["send_messages"]

	jsonData, err := json.Marshal(userProfile)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.EncodingJSONError)
	}

	_, err = e.rdb.Set(ctx.Request().Context(), "profile:"+strconv.Itoa(userID), jsonData, 0).Result()
	if err != nil {
		logger.Error("<< ProfileHandler error, ", err)
	}

	err = e.repo.CreateUserProfile(ctx.Request().Context(), userID, profile)
	if err != nil {
		logger.Error("<< SaveProfileHandler error, ", err)
		return APIErrorSilent(http.StatusBadRequest, errs.CreateUserProfileError)
	}

	logger.Info("<< SaveProfileHandler done.")
	return APISuccess(http.StatusCreated, nil)
}
