package mailru

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
	"golang.org/x/oauth2/mailru"
	"io"
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
	// создание конфигурации OAuth2
	oauth2config *oauth2.Config
}

type URLResponse struct {
	URL string
}

type CodeRequest struct {
	Code string `json:"code"`
}

func New(config *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *Endpoint {
	cfg := &oauth2.Config{
		ClientID:     config.GetString("oauth.mailru.clientID"),
		ClientSecret: config.GetString("oauth.mailru.secretID"),
		RedirectURL: config.GetString("oauth.mailru.redirectUrl.proto") + "://" +
			config.GetString("oauth.mailru.redirectUrl.host") +
			config.GetString("oauth.mailru.redirectUrl.uri"),
		Scopes:   []string{"userinfo"},
		Endpoint: mailru.Endpoint,
	}

	return &Endpoint{config: config, us: us, jwt: jwt, oauth2config: cfg}
}

func (e *Endpoint) MailRuAuthGetCodeHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> MailRuAuthGetCodeHandler started..")

	// получение URL для авторизации
	authURL := e.oauth2config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	authURL = strings.ReplaceAll(authURL, "%22", "")
	unescape, err := url.QueryUnescape(authURL)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, "Ошибка декодирования url")
	}

	logger.Info("<< MailRuAuthGetCodeHandler done.")
	return ctx.JSON(http.StatusOK, URLResponse{unescape})
}

func (e *Endpoint) MailRuAuthLoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> MailRuAuthLoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "mailru auth handler")
	defer span.Finish()

	code := ctx.QueryParam("code")
	if code == "nil" {
		logger.Error("Error processing code")
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, "Error processing code")
	}

	c := context.Background()
	token, err := e.oauth2config.Exchange(c, code)
	if err != nil {
		logger.Error("Error code exchange, possibly code expired", err)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	// использование токена для получения информации о пользователе
	client := getClient(c, e.oauth2config, token)
	resp, clErr := client.Get("https://oauth.mail.ru/userinfo?access_token=" + token.AccessToken)
	if clErr != nil {
		logger.Error("Error getting user info context, ", clErr)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, "Error creating context")
	}
	defer resp.Body.Close()

	// {"error":"invalid request","error_code":2,"error_description":"missing request parameter: access_token"}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		span.SetTag("error", true)
		return err
	}
	logger.Debug("mail.ru userinfo oauth response:", string(body))

	var userInfo structs.MailRuUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		logger.Error("Error decoding json, ", err)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, "Error decoding json")
	}

	span.LogKV("login", userInfo.Email)
	span.SetTag("handler", "mailru auth")

	ct := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := e.us.LoginMailRuUser(ct, &userInfo)
	if err != nil {
		logger.Error("Error login as MailRu user, ", err)
		span.SetTag("error", true)
		return ctx.JSON(http.StatusBadRequest, "Error login as MailRu user")
	}

	t, _, err := e.jwt.CreateJwtToken(u)
	if err != nil || t == "" {
		logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
		logger.Info("<< MailRuAuthLoginHandler done.")
		span.SetTag("error", true)
		return ctx.JSON(http.StatusForbidden, structs.ErrorResponse{Error: err.Error()})
	}

	res := &structs.AuthRes{
		Token: t,
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

	logger.Info("<< MailRuAuthLoginHandler done.")
	return ctx.JSON(http.StatusOK, res)
}

func getClient(c context.Context, config *oauth2.Config, token *oauth2.Token) *http.Client {
	return config.Client(c, token)
}
