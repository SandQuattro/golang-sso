package endpoint

import (
	"context"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"net/http"
	"sso/internal/app/structs"
	"time"
)

type URLResponse struct {
	URL string
}

type CodeRequest struct {
	Code string `json:"code"`
}

func APISuccess(httpStatus int, data interface{}) error {
	return echo.NewHTTPError(httpStatus, data)
}

func APISuccessWithRefreshToken(ctx echo.Context, httpStatus int, data interface{}) error {
	m := data.(map[string]interface{})
	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    m["refresh_token"].(string),
		Expires:  time.Now().UTC().Add(15 * time.Minute),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		Path:     "/refresh",
		Domain:   ctx.Request().Host,
	}
	ctx.SetCookie(cookie)
	delete(m, "refresh_token")
	return echo.NewHTTPError(httpStatus, data)
}

func APIErrorSilent(httpStatus int, code int) error {
	return echo.NewHTTPError(httpStatus, structs.ErrorResponse{Code: code})
}

func APIError(httpStatus int, code int, err error) error {
	if err == nil {
		return echo.NewHTTPError(httpStatus, structs.ErrorResponse{Code: code})
	}
	return echo.NewHTTPError(httpStatus, structs.ErrorResponse{Code: code, Error: err.Error()})
}

func getClient(c context.Context, config *oauth2.Config, token *oauth2.Token) *http.Client {
	return config.Client(c, token)
}
