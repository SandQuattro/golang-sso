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
	"strconv"
	"strings"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/vk"
)

type VKEndpoint struct {
	config func() *hocon.Config
	us     interfaces.UserService
	jwt    interfaces.JwtService
	// создание конфигурации OAuth2
	oauth2config *oauth2.Config
}

func NewVKEndpoint(config func() *hocon.Config, us interfaces.UserService, jwt interfaces.JwtService) *VKEndpoint {
	cfg := &oauth2.Config{
		ClientID:     config().GetString("oauth.vk.clientID"),
		ClientSecret: config().GetString("oauth.vk.secretID"),
		RedirectURL: config().GetString("oauth.vk.redirectUrl.proto") + "://" +
			config().GetString("oauth.vk.redirectUrl.host") +
			config().GetString("oauth.vk.redirectUrl.uri"),
		Scopes:   []string{strconv.Itoa(1 << 22)},
		Endpoint: vk.Endpoint,
	}

	return &VKEndpoint{config: config, us: us, jwt: jwt, oauth2config: cfg}
}

func (e *VKEndpoint) VKAuthGetCodeHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> VKAuthGetCodeHandler started..")

	// получение URL для авторизации
	d := oauth2.SetAuthURLParam("display", "popup")
	authURL := e.oauth2config.AuthCodeURL("state-token", oauth2.AccessTypeOffline, d)
	authURL = strings.ReplaceAll(authURL, "%22", "")
	unescape, err := url.QueryUnescape(authURL)
	if err != nil {
		return APIErrorSilent(http.StatusBadRequest, errs.URLDecodeError)
	}

	logger.Info("<< VKAuthGetCodeHandler done.")
	return APISuccess(http.StatusOK, URLResponse{unescape})
}

func (e *VKEndpoint) VKAuthLoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> VKAuthLoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "vk auth handler")
	defer span.Finish()

	code := ctx.QueryParam("code")
	if code == "nil" {
		logger.Error("Error processing code")
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	c := context.Background()
	token, exchErr := e.oauth2config.Exchange(c, code)
	if exchErr != nil {
		logger.Error("Error code exchange, possibly code expired", exchErr)
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	email := token.Extra("email")
	if email == "" {
		logger.Error("Error getting email from user, email approved?")
		return APIErrorSilent(http.StatusBadRequest, errs.InvalidInputData)
	}

	// использование токена для получения информации о пользователе
	client := getClient(c, e.oauth2config, token)
	resp, clErr := client.Get("https://api.vk.com/method/users.get?&v=5.131&access_token=" + token.AccessToken)
	if clErr != nil {
		logger.Error("Error getting user info context, ", clErr)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserInfoGettingError)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	logger.Debug("VK userinfo oauth response:", string(body))

	var userInfo structs.VKUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		logger.Error("Error decoding json, ", err)
		return APIErrorSilent(http.StatusBadRequest, errs.DecodingJSONError)
	}

	if userInfo.Response == nil || len(userInfo.Response) == 0 {
		logger.Error("Error VK response, ", string(body))
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserInfoGettingError)
	}

	userInfo.Response[0].Email = email.(string)

	span.LogKV("login", userInfo.Response[0].Email)
	span.SetTag("handler", "vk auth")

	ct := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := e.us.LoginVKUser(ct, &userInfo.Response[0])
	if err != nil {
		logger.Error("Error login as vk user, ", err)
		return APIErrorSilent(http.StatusBadRequest, errs.OAuthUserLoginError)
	}

	t, err := e.jwt.CreateJwtToken(c, u)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
		logger.Info("<< VKAuthLoginHandler done.")
		return APIErrorSilent(http.StatusForbidden, errs.JwtTokenCreationError)
	}

	err = utils.CreateTask(e.config, span, utils.TypeTelegramDelivery, u.Email, u.Email, u.ID, fmt.Sprintf("VK account login successful: %s\nIP:%s", u.Email, ctx.RealIP()))
	if err != nil {
		logger.Error(fmt.Errorf("error creating task: %s", err.Error()))
		return APIErrorSilent(http.StatusInternalServerError, errs.TaskCreationError)
	}

	logger.Info("<< VKAuthLoginHandler done.")
	return APISuccess(http.StatusOK, t)
}
