package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2/yandex"
	"io"
	"net/http"
	"net/url"
	"sso/internal/app/errs"
	"sso/internal/app/interfaces"
	"sso/internal/app/structs"
	"sso/internal/app/utils"
	"strings"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"golang.org/x/oauth2"
)

type YandexEndpoint struct {
	config func() *hocon.Config
	us     interfaces.UserService
	jwt    interfaces.JwtService
	// создание конфигурации OAuth2
	oauth2config *oauth2.Config
}

func NewYandexEndpoint(config func() *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *YandexEndpoint {
	cfg := &oauth2.Config{
		ClientID:     config().GetString("oauth.yandex.clientID"),
		ClientSecret: config().GetString("oauth.yandex.secretID"),
		RedirectURL: config().GetString("oauth.yandex.redirectUrl.proto") + "://" +
			config().GetString("oauth.yandex.redirectUrl.host") +
			config().GetString("oauth.yandex.redirectUrl.uri"),
		Scopes:   []string{"login:email"},
		Endpoint: yandex.Endpoint,
	}

	return &YandexEndpoint{config: config, us: us, jwt: jwt, oauth2config: cfg}
}

func (e *YandexEndpoint) YandexAuthGetCodeHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> YandexAuthGetCodeHandler started..")

	// получение URL для авторизации
	authURL := e.oauth2config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	authURL = strings.ReplaceAll(authURL, "%22", "")
	unescape, err := url.QueryUnescape(authURL)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.URLDecodeError)
	}

	logger.Info("<< YandexAuthGetCodeHandler done.")
	return APISuccess(http.StatusOK, URLResponse{unescape})
}

func (e *YandexEndpoint) YandexAuthLoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> YandexAuthLoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "Yandex auth handler")
	defer span.Finish()

	code := ctx.QueryParam("code")
	if code == "nil" {
		logger.Error("Error processing code")
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	c := context.Background()
	token, err := e.oauth2config.Exchange(c, code)
	if err != nil {
		logger.Error("Error code exchange, possibly code expired", err)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	// использование токена для получения информации о пользователе
	client := getClient(c, e.oauth2config, token)
	resp, clErr := client.Get("https://login.yandex.ru/info")
	if clErr != nil {
		logger.Error("Error getting user info context, ", clErr)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserInfoGettingError)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		span.SetTag("error", true)
		return err
	}
	logger.Debug("yandex userinfo oauth response:", string(body))

	var userInfo structs.YandexUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		logger.Error("Error decoding json, ", err)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.DecodingJSONError)
	}

	span.LogKV("login", userInfo.Login)
	span.SetTag("handler", "Yandex auth")

	ct := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := e.us.LoginYandexUser(ct, &userInfo)
	if err != nil {
		logger.Error("Error login as Yandex user, ", err)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserLoginError)
	}

	t, err := e.jwt.CreateJwtToken(c, u)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
		logger.Info("<< YandexAuthLoginHandler done.")
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusForbidden, errs.JwtTokenCreationError)
	}

	err = utils.CreateTask(e.config, span, utils.TypeTelegramDelivery, u.Email, u.Email, u.ID, fmt.Sprintf("yandex account login successful: %s\nIP:%s", u.Email, ctx.RealIP()))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	logger.Info("<< YandexAuthLoginHandler done.")
	return APISuccess(http.StatusOK, t)
}
