package interfaces

import (
	"context"
	"crypto"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"sso/internal/app/structs"
)

type JwtService interface {
	CreateJwtToken(ctx context.Context, user *structs.User) (map[string]interface{}, error)
	RefreshJwtToken(ctx echo.Context, token string) (string, error)
	GenerateRSAKeys(bits int) (crypto.PublicKey, crypto.PrivateKey, error)
	ConvertRSAPublicKeyToPEM(publicKey crypto.PublicKey) ([]byte, error)
	ConvertRSAPrivateKeyToPEM(privateKey crypto.PrivateKey) ([]byte, error)
	GenerateED25519Keys() (crypto.PublicKey, crypto.PrivateKey, error)
	ConvertPublicKeyToPEM(key crypto.PublicKey) ([]byte, error)
	ConvertPrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error)
	GetCurrentPublicKeyFromRedis(rdb *redis.Client) string
}
