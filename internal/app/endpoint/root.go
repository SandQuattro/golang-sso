package endpoint

import (
	"net/http"

	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
)

type RootEndpoint struct {
}

func NewRootEndpoint() *RootEndpoint {
	return &RootEndpoint{}
}
func (root *RootEndpoint) RootHandler(ctx echo.Context) error {
	span := jaegertracing.CreateChildSpan(ctx, "root handler")
	defer span.Finish()

	return APISuccess(http.StatusOK, "online")
}
