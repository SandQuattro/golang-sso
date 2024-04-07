package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
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
	"golang.org/x/oauth2/google"
)

type GoogleEndpoint struct {
	config func() *hocon.Config
	us     interfaces.UserService
	jwt    interfaces.JwtService
}

func NewGoogleEndpoint(config func() *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *GoogleEndpoint {
	return &GoogleEndpoint{config: config, us: us, jwt: jwt}
}

func (e *GoogleEndpoint) GoogleAuthGetCodeHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> GoogleAuthGetCodeHandler started..")

	// создание конфигурации OAuth2
	config := &oauth2.Config{
		ClientID:     e.config().GetString("oauth.google.clientID"),
		ClientSecret: e.config().GetString("oauth.google.secretID"),
		RedirectURL: e.config().GetString("oauth.google.redirectUrl.proto") + "://" +
			e.config().GetString("oauth.google.redirectUrl.host") +
			e.config().GetString("oauth.google.redirectUrl.uri"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// получение URL для авторизации
	googleURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	googleURL = strings.ReplaceAll(googleURL, "%22", "")
	unescape, err := url.QueryUnescape(googleURL)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.URLDecodeError)
	}

	logger.Info("<< GoogleAuthGetCodeHandler done.")
	return APISuccess(http.StatusOK, URLResponse{unescape})
}

func (e *GoogleEndpoint) GoogleAuthLoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> GoogleAuthLoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "google auth handler")
	defer span.Finish()

	// создание конфигурации OAuth2
	config := &oauth2.Config{
		ClientID:     e.config().GetString("oauth.google.clientID"),
		ClientSecret: e.config().GetString("oauth.google.secretID"),
		RedirectURL: e.config().GetString("oauth.google.redirectUrl.proto") + "://" +
			e.config().GetString("oauth.google.redirectUrl.host") +
			e.config().GetString("oauth.google.redirectUrl.uri"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	code := ctx.QueryParam("code")
	if code == "nil" {
		logger.Error("Error processing code")
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	c := context.Background()
	token, err := config.Exchange(c, code)
	if err != nil {
		logger.Error("Error code exchange, possibly code expired", err)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	// использование токена для получения информации о пользователе
	client := getClient(c, config, token)
	resp, clErr := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if clErr != nil {
		logger.Error("Error getting user info context, ", clErr)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserInfoGettingError)
	}
	defer resp.Body.Close()

	var userInfo structs.GoogleUserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		logger.Error("Error decoding json, ", err)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.DecodingJSONError)
	}

	span.LogKV("login", userInfo.Email)
	span.SetTag("handler", "google auth")

	ct := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := e.us.LoginGoogleUser(ct, &userInfo)
	if err != nil {
		logger.Error("Error login as google user, ", err)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserLoginError)
	}

	t, err := e.jwt.CreateJwtToken(c, u)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("jwt token creation failed, reason: %s", err.Error()))
		logger.Info("<< LoginHandler done.")
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusForbidden, errs.JwtTokenCreationError)
	}

	err = utils.CreateTask(e.config, span, utils.TypeTelegramDelivery, u.Email, u.Email, u.ID, fmt.Sprintf("Google account login successful: %s\nIP: %s", u.Email, ctx.RealIP()))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	logger.Info("<< GoogleAuthLoginHandler done.")
	return APISuccess(http.StatusOK, t)
}
