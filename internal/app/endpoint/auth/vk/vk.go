package vk

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
	"golang.org/x/oauth2/vk"
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
		ClientID:     config.GetString("oauth.vk.clientID"),
		ClientSecret: config.GetString("oauth.vk.secretID"),
		RedirectURL: config.GetString("oauth.vk.redirectUrl.proto") + "://" +
			config.GetString("oauth.vk.redirectUrl.host") +
			config.GetString("oauth.vk.redirectUrl.uri"),
		Scopes:   []string{strconv.Itoa(1 << 22)},
		Endpoint: vk.Endpoint,
	}

	return &Endpoint{config: config, us: us, jwt: jwt, oauth2config: cfg}
}

func (e *Endpoint) VKAuthGetCodeHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> VKAuthGetCodeHandler started..")

	// получение URL для авторизации
	d := oauth2.SetAuthURLParam("display", "popup")
	authURL := e.oauth2config.AuthCodeURL("state-token", oauth2.AccessTypeOffline, d)
	authURL = strings.ReplaceAll(authURL, "%22", "")
	unescape, err := url.QueryUnescape(authURL)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, "Ошибка декодирования url")
	}

	logger.Info("<< VKAuthGetCodeHandler done.")
	return ctx.JSON(http.StatusOK, URLResponse{unescape})
}

func (e *Endpoint) VKAuthLoginHandler(ctx echo.Context) error {
	logger := logdoc.GetLogger()
	logger.Info(">> VKAuthLoginHandler started..")

	span := jaegertracing.CreateChildSpan(ctx, "vk auth handler")
	defer span.Finish()

	code := ctx.QueryParam("code")
	if code == "nil" {
		logger.Error("Error processing code")
		return ctx.JSON(http.StatusBadRequest, "Error processing code")
	}

	c := context.Background()
	token, exchErr := e.oauth2config.Exchange(c, code)
	if exchErr != nil {
		logger.Error("Error code exchange, possibly code expired", exchErr)
		return ctx.JSON(http.StatusBadRequest, exchErr.Error())
	}

	email := token.Extra("email")
	if email == "" {
		logger.Error("Error getting email from user, email approved?")
		return ctx.JSON(http.StatusBadRequest, "error getting email from user")
	}

	// использование токена для получения информации о пользователе
	client := getClient(c, e.oauth2config, token)
	resp, clErr := client.Get("https://api.vk.com/method/users.get?&v=5.131&access_token=" + token.AccessToken)
	if clErr != nil {
		logger.Error("Error getting user info context, ", clErr)
		return ctx.JSON(http.StatusBadRequest, "Error creating context")
	}
	defer resp.Body.Close()

	// {"error":"invalid request","error_code":2,"error_description":"missing request parameter: access_token"}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	logger.Debug("VK userinfo oauth response:", string(body))

	// {"response":[{"id":1690403,"first_name":"","last_name":"","can_access_closed":true,"is_closed":false}]}
	var userInfo structs.VKUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		logger.Error("Error decoding json, ", err)
		return ctx.JSON(http.StatusBadRequest, "Error decoding json")
	}

	if userInfo.Response == nil || len(userInfo.Response) == 0 {
		logger.Error("Error VK response, ", string(body))
		return ctx.JSON(http.StatusBadRequest, "Error VK response")
	}

	userInfo.Response[0].Email = email.(string)

	span.LogKV("login", userInfo.Response[0].Email)
	span.SetTag("handler", "vk auth")

	ct := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	u, err := e.us.LoginVKUser(ct, &userInfo.Response[0])
	if err != nil {
		logger.Error("Error login as vk user, ", err)
		return ctx.JSON(http.StatusBadRequest, "Error login as vk user")
	}

	t, err := e.jwt.CreateJwtToken(u)
	if err != nil || t == nil {
		logger.Error(fmt.Errorf("login failed, reason: %s", err.Error()))
		logger.Info("<< VKAuthLoginHandler done.")
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

	logger.Info("<< VKAuthLoginHandler done.")
	return ctx.JSON(http.StatusOK, res)
}

func getClient(c context.Context, config *oauth2.Config, token *oauth2.Token) *http.Client {
	return config.Client(c, token)
}
