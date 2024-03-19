package google

import (
	"context"
	"encoding/json"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
	"net/url"
	authutils "sso/internal/app/endpoint/auth"
	"sso/internal/app/interfaces"
	"sso/internal/app/structs"
	"strconv"
	"strings"
)

type Endpoint struct {
	config *hocon.Config
	us     interfaces.UserService
	jwt    interfaces.JwtService
}

type URLResponse struct {
	URL string
}

type CodeRequest struct {
	Code string `json:"code"`
}

func New(config *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *Endpoint {
	return &Endpoint{config: config, us: us, jwt: jwt}
}

func (e *Endpoint) GoogleAuthGetCodeHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> GoogleAuthGetCodeHandler started..")

	// создание конфигурации OAuth2
	config := &oauth2.Config{
		ClientID:     e.config.GetString("oauth.google.clientID"),
		ClientSecret: e.config.GetString("oauth.google.secretID"),
		RedirectURL: e.config.GetString("oauth.google.redirectUrl.proto") + "://" +
			e.config.GetString("oauth.google.redirectUrl.host") +
			e.config.GetString("oauth.google.redirectUrl.uri"),
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
		return ctx.JSON(http.StatusBadRequest, "Ошибка декодирования url")
	}

	logger.Info("<< GoogleAuthGetCodeHandler done.")
	return ctx.JSON(http.StatusOK, URLResponse{unescape})
}

func (e *Endpoint) GoogleAuthLoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> GoogleAuthLoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "google auth handler")
	defer span.Finish()

	// создание конфигурации OAuth2
	config := &oauth2.Config{
		ClientID:     e.config.GetString("oauth.google.clientID"),
		ClientSecret: e.config.GetString("oauth.google.secretID"),
		RedirectURL: e.config.GetString("oauth.google.redirectUrl.proto") + "://" +
			e.config.GetString("oauth.google.redirectUrl.host") +
			e.config.GetString("oauth.google.redirectUrl.uri"),
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
		return ctx.JSON(http.StatusBadRequest, "Error processing code")
	}

	c := context.Background()
	token, err := config.Exchange(c, code)
	if err != nil {
		logger.Error("Error code exchange, possibly code expired", err)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	// использование токена для получения информации о пользователе
	client := getClient(c, config, token)
	resp, clErr := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if clErr != nil {
		logger.Error("Error getting user info context, ", clErr)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, "Error creating context")
	}
	defer resp.Body.Close()

	var userInfo structs.GoogleUserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		logger.Error("Error decoding json, ", err)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, "Error decoding json")
	}

	span.LogKV("login", userInfo.Email)
	span.SetTag("handler", "google auth")

	ct := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := e.us.LoginGoogleUser(ct, &userInfo)
	if err != nil {
		logger.Error("Error login as google user, ", err)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, "Error login as google user")
	}

	t, err := e.jwt.CreateJwtToken(u)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
		logger.Info("<< LoginHandler done.")
		span.SetTag("error", true)
		return ctx.JSON(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
	}

	res := &structs.AuthRes{
		Token: t["access_token"].(string),
	}

	// объединяем данные незареганного пользователя и пользователя VK
	cookie, err := ctx.Cookie("session_id")
	if err != nil {
		logger.Warn("session_id кука не найдена, не объединяем пользовательские данные")
	} else {
		sessionID, err := strconv.Atoi(cookie.Value)
		if err != nil {
			logger.Warn("Ошибка преобразования сессии в число, session_id:", cookie.Value)
		} else {
			err = authutils.MergeUserData(e.us, sessionID, u.ID)
			if err != nil {
				logger.Warn("Ошибка объединения пользовательских данных, session:", cookie.Value, ", userId:", u.ID)
			}
		}
	}

	logger.Info("<< GoogleAuthLoginHandler done.")
	return ctx.JSON(http.StatusOK, res)
}

func getClient(c context.Context, config *oauth2.Config, token *oauth2.Token) *http.Client {
	return config.Client(c, token)
}
