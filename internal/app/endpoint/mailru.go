package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
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
	"golang.org/x/oauth2/mailru"
)

type MailRuEndpoint struct {
	config func() *hocon.Config
	us     interfaces.UserService
	jwt    interfaces.JwtService
	// создание конфигурации OAuth2
	oauth2config *oauth2.Config
}

func NewMailRuEndpoint(config func() *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *MailRuEndpoint {
	cfg := &oauth2.Config{
		ClientID:     config().GetString("oauth.mailru.clientID"),
		ClientSecret: config().GetString("oauth.mailru.secretID"),
		RedirectURL: config().GetString("oauth.mailru.redirectUrl.proto") + "://" +
			config().GetString("oauth.mailru.redirectUrl.host") +
			config().GetString("oauth.mailru.redirectUrl.uri"),
		Scopes:   []string{"userinfo"},
		Endpoint: mailru.Endpoint,
	}

	// new endpoints
	cfg.Endpoint.AuthURL = "https://oauth.mail.ru/login"
	cfg.Endpoint.TokenURL = "https://oauth.mail.ru/token"

	return &MailRuEndpoint{config: config, us: us, jwt: jwt, oauth2config: cfg}
}

func (e *MailRuEndpoint) MailRuAuthGetCodeHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> MailRuAuthGetCodeHandler started..")

	// получение URL для авторизации
	authURL := e.oauth2config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	authURL = strings.ReplaceAll(authURL, "%22", "")
	unescape, err := url.QueryUnescape(authURL)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.URLDecodeError)
	}

	logger.Info("<< MailRuAuthGetCodeHandler done.")
	return APISuccess(http.StatusOK, URLResponse{unescape})
}

func (e *MailRuEndpoint) MailRuAuthLoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> MailRuAuthLoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "mailru auth handler")
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
	resp, clErr := client.Get("https://oauth.mail.ru/userinfo?access_token=" + token.AccessToken)
	if clErr != nil {
		logger.Error("Error getting user info context, ", clErr)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserInfoGettingError)
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
		return APIErrorSilent(http.StatusBadRequest, errs.DecodingJSONError)
	}

	span.LogKV("login", userInfo.Email)
	span.SetTag("handler", "mailru auth")

	ct := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := e.us.LoginMailRuUser(ct, &userInfo)
	if err != nil {
		logger.Error("Error login as MailRu user, ", err)
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserLoginError)
	}

	t, err := e.jwt.CreateJwtToken(c, u)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("malru login failed, reason: %s", err.Error()))
		logger.Info("<< MailRuAuthLoginHandler done.")
		span.SetTag("error", true)
		return APIErrorSilent(http.StatusForbidden, errs.JwtTokenCreationError)
	}

	err = utils.CreateTask(e.config, span, utils.TypeTelegramDelivery, u.Email, u.Email, u.ID, fmt.Sprintf("Mail.ru account login successful: %s\nIP: %s", u.Email, ctx.RealIP()))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	logger.Info("<< MailRuAuthLoginHandler done.")
	return APISuccessWithRefreshToken(ctx, http.StatusOK, t)
}
