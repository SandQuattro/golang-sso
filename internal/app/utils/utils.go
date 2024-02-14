package utils

import (
	"context"
	"github.com/labstack/gommon/random"
	"github.com/opentracing/opentracing-go"
	"sso/internal/app/structs"
	"time"
)

func Ternary(cond bool, a any, b any) any {
	if cond {
		return a
	} else {
		return b
	}
}

func GenerateCode(length uint8) string {
	return random.String(length, random.Alphanumeric)
}

func ValidateUserSubscription(ctx context.Context, user *structs.User) (bool, error) {
	span, _ := opentracing.StartSpanFromContext(ctx, "validating user subscription service")
	defer span.Finish()

	// если поле не пустое (те подписка не лимитирована), проверяем дату окончания подписки
	if user.ValidTill.Valid {
		if time.Now().UTC().After(user.ValidTill.Time.UTC()) {
			span.SetTag("error", true)
			span.LogKV("error.message", "срок действия подписки истек")
			return false, nil
		}
	}
	return true, nil
}
