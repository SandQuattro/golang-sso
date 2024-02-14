package root

import (
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"net/http"
)

type Endpoint struct {
}

func New() *Endpoint {
	return &Endpoint{}
}
func (root *Endpoint) RootHandler(ctx echo.Context) error {
	span := jaegertracing.CreateChildSpan(ctx, "root handler")
	defer span.Finish()

	return ctx.String(http.StatusOK, "online")
}
