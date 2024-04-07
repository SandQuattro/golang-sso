package endpoint

import (
	"context"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"net/http"
	"sso/internal/app/structs"
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
