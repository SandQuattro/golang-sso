package interfaces

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"sso/internal/app/structs"
)

type JwtService interface {
	RefreshJwtToken(ctx echo.Context, token string) (string, error)
	CreateJwtToken(user *structs.User) (token string, response *structs.ResponseUser, err error)
	JwtClaims(tokenStr string) (jwt.MapClaims, error)
}
