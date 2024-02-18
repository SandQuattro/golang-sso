package jwtservice

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/golang-jwt/jwt"
	"github.com/gurkankaymak/hocon"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"sso/internal/app/utils"

	"os"
	"sso/internal/app/errs"
	"sso/internal/app/repository"
	"sso/internal/app/structs"
	"strings"
	"time"
	"unicode/utf8"
)

type JwtService struct {
	config *hocon.Config
	r      repository.UserRepository
}

type SubscriptionInvalidatedError struct{}

func (m SubscriptionInvalidatedError) Error() string {
	return "subscription invalidated"
}

var SubscriptionInvalidated = SubscriptionInvalidatedError{}

func New(config *hocon.Config, db *sqlx.DB) *JwtService {
	urepo := repository.New(db)
	return &JwtService{config: config, r: *urepo}
}

func (s *JwtService) CreateJwtToken(user *structs.User) (token string, response *structs.ResponseUser, err error) {
	defer func() {
		err = errs.WrapIfErr("Ошибка формирования jwt токена", err)
	}()

	logger := logdoc.GetLogger()

	privateKey, err := readPrivatePEMKey()
	if err != nil {
		return "", nil, err
	}

	// Устанавливаем параметры токена
	var fio string
	if user.GivenName != "" {
		l, _ := utf8.DecodeRuneInString(user.FamilyName)
		fio = user.GivenName + " " + string(l) + "."
	} else {
		fio = ""
	}

	claims := jwt.MapClaims{
		"id":  user.ID,
		"sub": user.Sub,
		"sys": user.AuthSystem,
		"fio": fio,
		"iss": s.config.GetString("jwt.issuer"),
		"aud": s.config.GetString("jwt.audience"),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * time.Duration(s.config.GetInt("jwt.expiredAfterMinutes"))).Unix(),
		"adr": user.Email,
		"rol": user.Role,
	}

	// Генерируем токен
	token, err = jwt.NewWithClaims(getSigningMethod(privateKey), claims).SignedString(privateKey)
	if err != nil {
		logger.Error("Ошибка генерации токена, ", err)
		return
	}

	response = &structs.ResponseUser{
		ID:    user.ID,
		Email: user.Email,
	}

	return token, response, nil
}

func (s *JwtService) RefreshJwtToken(ctx echo.Context, tokenStr string) (string, error) {
	logger := logdoc.GetLogger()

	span := jaegertracing.CreateChildSpan(ctx, "jwt service")
	defer span.Finish()

	publicKey := readPublicPEMKey()

	// проверка токена
	tok, err := jwt.Parse(strings.ReplaceAll(tokenStr, "Bearer ", ""), func(jwtToken *jwt.Token) (interface{}, error) {
		switch publicKey.(type) {
		case *rsa.PublicKey:
			if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
			}
		case ed25519.PublicKey:
			if _, ok := jwtToken.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
			}
		default:
			logger.Error("Неизвестный тип открытого ключа")
			return "", fmt.Errorf("неизвестный тип открытого ключа")
		}

		return publicKey, nil
	})
	if err != nil {
		logger.Error("Ошибка парсинга jwt токена, ", err)
		return "", err
	}

	if tok == nil || tok.Claims == nil {
		logger.Error("Ошибка парсинга jwt токена")
		return "", errors.New("ошибка парсинга jwt токена")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token, claims parse error: %w", err)
	}

	if !claims.VerifyIssuer(s.config.GetString("jwt.issuer"), true) {
		return "", fmt.Errorf("token issuer error")
	}

	if !claims.VerifyAudience(s.config.GetString("jwt.audience"), true) {
		return "", fmt.Errorf("token audience error")
	}

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	if claims["sub"] != nil && claims["sub"] != "" {
		sub := claims["sub"].(string)
		user, err := s.r.FindUserBySub(sub)
		if err != nil {
			logger.Warn("error getting user by sub, trying by id")
			return "", fmt.Errorf("error getting user by sub, %w", err)
		}

		isSubscriptionValid, err := utils.ValidateUserSubscription(c, user)
		if err != nil {
			return "", err
		}
		if !isSubscriptionValid {
			return "", SubscriptionInvalidated
		}
	} else {
		user, err := s.r.FindUserByID(c, int(claims["id"].(float64)))
		if err != nil {
			logger.Warn("error getting user by id")
			return "", fmt.Errorf("error getting user by id, %w", err)
		}
		isSubscriptionValid, err := utils.ValidateUserSubscription(c, user)
		if err != nil {
			return "", err
		}
		if !isSubscriptionValid {
			return "", SubscriptionInvalidated
		}
	}

	span.SetTag("userID", int(claims["id"].(float64)))
	token, err := s.recreateJwtTokenWithClaims(claims)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *JwtService) JwtClaims(tokenStr string) (jwt.MapClaims, error) {
	logger := logdoc.GetLogger()
	claims, isValid, err := s.ValidateToken(tokenStr)
	if !isValid {
		logger.Error("JwtClaims getting failed")
		return nil, err
	}
	return claims, nil
}

func (s *JwtService) ValidateToken(tokenStr string) (jwt.MapClaims, bool, error) {
	logger := logdoc.GetLogger()

	publicKey := readPublicPEMKey()

	// проверка токена
	tok, err := jwt.Parse(strings.ReplaceAll(tokenStr, "Bearer ", ""), func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		logger.Error("Ошибка формирования jwt токена, ", err)
		return nil, false, err
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, false, fmt.Errorf("invalid token, claims parse error: %w", err)
	}

	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return nil, false, fmt.Errorf("token expired")
	}

	if !claims.VerifyIssuer(s.config.GetString("jwt.issuer"), true) {
		return nil, false, fmt.Errorf("token issuer error")
	}

	if !claims.VerifyAudience(s.config.GetString("jwt.audience"), true) {
		return nil, false, fmt.Errorf("token audience error")
	}

	return claims, true, nil
}

func (s *JwtService) recreateJwtTokenWithClaims(claims jwt.MapClaims) (string, error) {
	logger := logdoc.GetLogger()

	privateKey, err := readPrivatePEMKey()
	if err != nil {
		return "", err
	}

	// Меняем даты выдачи и expire
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(s.config.GetInt("jwt.expiredAfterMinutes"))).Unix()

	// Генерируем токен
	token, err := jwt.NewWithClaims(getSigningMethod(privateKey), claims).SignedString(privateKey)
	if err != nil {
		logger.Error("Ошибка генерации jwt токена, ", err)
		return "", err
	}

	return token, nil
}

func readPrivatePEMKey() (crypto.PrivateKey, error) {
	logger := logdoc.GetLogger()

	// Читаем приватный ключ
	keyBytes, err := os.ReadFile("conf/keys/private.pem")
	if err != nil {
		logger.Error("Ошибка чтения приватного ключа, ", err)
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(err)
	}

	var privateKey crypto.PrivateKey
	privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.Warn("Ошибка парсинга приватного ключа, ", err)
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			logger.Error("Ошибка парсинга приватного ключа, ", err)
			return nil, err
		}
		return privateKey, err
	}
	return privateKey, nil
}

func readPublicPEMKey() crypto.PublicKey {
	logger := logdoc.GetLogger()

	// Читаем открытый ключ
	keyBytes, err := os.ReadFile("conf/keys/public.pem")
	if err != nil {
		logger.Error("Ошибка чтения открытого ключа, ", err)
		return nil
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Error("Ошибка парсинга открытого ключа, ", err)
		return nil
	}

	return publicKey
}

func getSigningMethod(privateKey any) jwt.SigningMethod {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA
	default:
		return nil
	}
}
