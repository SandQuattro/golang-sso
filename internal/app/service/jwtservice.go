package service

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sso/internal/app/utils"

	"strconv"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	jwtverification "github.com/SandQuattro/jwt-verification"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gurkankaymak/hocon"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"github.com/redis/go-redis/v9"

	"os"
	"sso/internal/app/repository"
	"sso/internal/app/structs"
	"strings"
	"time"
	"unicode/utf8"
)

type JwtService struct {
	config     func() *hocon.Config
	rdb        *redis.Client
	privateKey *crypto.PrivateKey
	r          repository.UserRepository
	t          repository.TokenRepository
}

func NewJWTService(ctx context.Context, config func() *hocon.Config, rdb *redis.Client, db *sqlx.DB) *JwtService {
	urepo := repository.New(db)
	trepo := repository.NewTokenRepository(db)

	jwtService := &JwtService{config: config, rdb: rdb, r: *urepo, t: *trepo}

	if config().GetBoolean("jwt.rotate") {

		jwtService.GenerateKeys(rdb, config().GetInt("jwt.type"), config().GetString("jwt.algo"))

		if rdb != nil {
			ticker := time.NewTicker(1 * time.Minute)

			go func() {
				logger := logdoc.GetLogger()

				for {
					select {
					case <-ctx.Done():
						return
					case t := <-ticker.C:
						jwtService.GenerateKeys(rdb, config().GetInt("jwt.type"), config().GetString("jwt.algo"))
						logger.Warn("Keys rotation completed at", t)
					}
				}
			}()
		}
	}

	return jwtService
}

func (s *JwtService) GenerateKeys(rdb *redis.Client, keyType int, algo string) {
	logger := logdoc.GetLogger()
	logger.Info("Rotating keys...")

	var err error
	var public crypto.PublicKey
	var private crypto.PrivateKey

	if rdb != nil {
		if algo == "ED25519" {
			public, private, err = s.GenerateED25519Keys()
			if err != nil {
				logger.Fatalf("Failed to generate public key: %v", err)
			}
		} else if algo == "RSA" {
			public, private, err = s.GenerateRSAKeys(4096)
			if err != nil {
				logger.Fatalf("Failed to generate public key: %v", err)
			}
		} else {
			logger.Fatalf("Invalid algorithm")
		}

		s.privateKey = &private

		if keyType == jwtverification.PEM {
			pemPublic, err := s.ConvertPublicKeyToPEM(public)
			if err != nil {
				logger.Fatalf("Failed to convert public key to PEM: %v", err)
			}

			pubKeyBase := base64.StdEncoding.EncodeToString(pemPublic)

			err = rdb.LPush(context.Background(), "key:pem", pubKeyBase).Err()
			if err != nil {
				logger.Fatalf("Failed to store public key in redis: %v", err)
			}

			// Опционально, установить ограничение на размер истории ключей
			rdb.LTrim(context.Background(), "key:pem", 0, 9) // Сохраняем последние 10 ключей
		} else if keyType == jwtverification.DER {
			derPublic, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				logger.Fatalf("Failed to convert public key to DER: %v", err)
			}
			base64.StdEncoding.EncodeToString(derPublic)

			err = rdb.LPush(context.Background(), "key:der", derPublic).Err()
			if err != nil {
				logger.Fatalf("Failed to store public key in redis: %v", err)
			}

			// Опционально, установить ограничение на размер истории ключей
			rdb.LTrim(context.Background(), "key:der", 0, 9) // Сохраняем последние 10 ключей
		} else {
			logger.Fatalf("Invalid key type")
		}
	} else {
		var publicKey crypto.PublicKey
		var privateKey crypto.PrivateKey

		switch keyType {
		case jwtverification.PEM:
			privateKey, err = readPrivatePEMKey()
			if err != nil {
				logger.Fatalf("Failed to read private PEM key: %v", err)
			}
			publicKey = readPublicPEMKey()
			if publicKey == nil {
				logger.Fatalf("Failed to read public PEM key")
			}
		case jwtverification.DER:
			// Assuming there are methods readPrivateDERKey and readPublicDERKey that return private and public keys respectively
			derPrivateKey, err := os.ReadFile("conf/keys/private.der")
			if err != nil {
				logger.Fatalf("Failed to read private DER key: %v", err)
			}
			privateKey = readPrivateDERKey(derPrivateKey)
			if privateKey == nil {
				logger.Fatalf("Failed to parse private DER key")
			}

			derPublicKey, err := os.ReadFile("conf/keys/public.der")
			if err != nil {
				logger.Fatalf("Failed to read public DER key: %v", err)
			}
			publicKey = readPublicDERKey(derPublicKey)
			if publicKey == nil {
				logger.Fatalf("Failed to parse public DER key")
			}
		default:
			logger.Fatalf("Invalid key type")
		}

		s.privateKey = &privateKey

	}

	logger.Info("Keys rotation completed.")
}

func (s *JwtService) CreateJwtToken(ctx context.Context, user *structs.User) (map[string]interface{}, error) {
	logger := logdoc.GetLogger()

	var err error
	var privateKey crypto.PrivateKey

	if s.privateKey != nil {
		privateKey = *s.privateKey
	} else {
		privateKey, err = readPrivatePEMKey()
		if err != nil {
			return nil, err
		}
	}

	// Устанавливаем параметры токена
	var fio string
	if user.GivenName != "" {
		l, _ := utf8.DecodeRuneInString(user.FamilyName)
		fio = user.GivenName + " " + string(l) + "."
	} else {
		fio = ""
	}

	expirationTime := time.Now().Add(time.Minute * time.Duration(s.config().GetInt("jwt.expiredAfterMinutes")))
	claims := jwt.MapClaims{
		"id":  user.ID,
		"sub": user.Sub,
		"sys": user.AuthSystem,
		"fio": fio,
		"iss": s.config().GetString("jwt.issuer"),
		"aud": s.config().GetString("jwt.audience"),
		"iat": time.Now().UTC().Unix(),
		"exp": expirationTime.UTC().Unix(),
		"adr": user.Email,
		"rol": user.Role,
	}

	// Генерируем токен
	token, err := jwt.NewWithClaims(getSigningMethod(privateKey), claims).SignedString(privateKey)
	if err != nil {
		logger.Error("Ошибка генерации токена, ", err)
		return nil, err
	}

	// Генерируем refresh токен и время его действия
	timestamp := time.Now().UTC()
	// к текущему timestamp utc добавляем время жизни refresh токена в минутах и вычитаем из него текущее время
	// получаем время жизни refresh токена в секундах
	refreshTokenExpiresIn := timestamp.Add(time.Minute*time.Duration(s.config().GetInt("jwt.refresh.expiredAfterMinutes"))).Unix() - timestamp.Unix()
	refreshToken, refreshTokenExpiresIn, err := utils.GenerateRefreshToken(user, timestamp.UnixNano(), refreshTokenExpiresIn)
	if err != nil {
		logger.Error("Ошибка генерации refresh токена, ", err)
		return nil, err
	}

	m := make(map[string]string)
	m["userId"] = strconv.Itoa(user.ID)
	m["timestamp"] = strconv.FormatInt(timestamp.UnixNano(), 10)

	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	// сохраняем refresh токен в redis, устанавливаем ему ttl = refresh токен refreshTokenExpiresIn
	err = s.rdb.Set(ctx, refreshToken, data, time.Duration(refreshTokenExpiresIn)*time.Second).Err()
	if err != nil {
		logger.Error(fmt.Errorf("ошибка записи refresh токена в redis, %w", err))
		return nil, err
	}
	//err = s.t.CreateToken(context.Background(), user.ID, refreshToken, refreshTokenExpiresIn)
	//if err != nil {
	//	return nil, err
	//}

	return map[string]interface{}{
		"access_token":             token,
		"token_type":               "Bearer",
		"expires_in":               expirationTime.Unix() - time.Now().Unix(),
		"refresh_token":            refreshToken,
		"refresh_token_expires_in": refreshTokenExpiresIn,
	}, nil
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
	},
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(s.config().GetString("jwt.issuer")),
		jwt.WithAudience(s.config().GetString("jwt.audience")))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			logger.Warn("Token expired")
		} else {
			logger.Error(fmt.Sprintf("Token verification error: %s", err.Error()))
			taskerr := utils.CreateTask(s.config, span, utils.TypeTelegramDelivery, "unknown", "unknown", -1,
				fmt.Sprintf("Attention required! Error in RefreshJwtToken service, %s", err.Error()))
			if taskerr != nil {
				logger.Error(fmt.Errorf("error creating task: %s", taskerr.Error()))
				return "", taskerr
			}
			return "", err
		}
	}

	if tok == nil || tok.Claims == nil {
		logger.Error("Ошибка парсинга jwt токена")
		return "", errors.New("ошибка парсинга jwt токена")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token, claims parse error: %w", err)
	}

	c := opentracing.ContextWithSpan(ctx.Request().Context(), span)

	if claims["sub"] != nil && claims["sub"] != "" {
		sub := claims["sub"].(string)
		_, err := s.r.FindUserBySub(sub)
		if err != nil {
			logger.Warn("error getting user by sub, trying by id")
			return "", fmt.Errorf("error getting user by sub, %w", err)
		}
	} else {
		_, err := s.r.FindUserByID(c, int(claims["id"].(float64)))
		if err != nil {
			logger.Warn("error getting user by id")
			return "", fmt.Errorf("error getting user by id, %w", err)
		}
	}

	span.SetTag("userID", int(claims["id"].(float64)))
	token, err := s.recreateJwtTokenWithClaims(claims)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *JwtService) recreateJwtTokenWithClaims(claims jwt.MapClaims) (string, error) {
	logger := logdoc.GetLogger()

	var privateKey crypto.PrivateKey
	var err error

	if s.privateKey != nil {
		privateKey = *s.privateKey
	} else {
		privateKey, err = readPrivatePEMKey()
		if err != nil {
			return "", err
		}
	}

	// Меняем даты выдачи и expire
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(s.config().GetInt("jwt.expiredAfterMinutes"))).Unix()

	// Генерируем токен
	token, err := jwt.NewWithClaims(getSigningMethod(privateKey), claims).SignedString(privateKey)
	if err != nil {
		logger.Error("Ошибка генерации jwt токена, ", err)
		return "", err
	}

	return token, nil
}

func (s *JwtService) GenerateRSAKeys(bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	// Генерация приватного ключа
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey

	return publicKey, privateKey, err
}

func (s *JwtService) ConvertRSAPublicKeyToPEM(publicKey crypto.PublicKey) ([]byte, error) {

	// Преобразование публичного ключа в формат ASN.1 PKCS#1 DER
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	// Создание блока PEM для публичного ключа
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}

	var pubKey bytes.Buffer
	err = pem.Encode(&pubKey, publicKeyBlock)
	if err != nil {
		return nil, err
	}

	return pubKey.Bytes(), nil
}

func (s *JwtService) ConvertRSAPrivateKeyToPEM(privateKey crypto.PrivateKey) ([]byte, error) {
	// Преобразование приватного ключа в формат ASN.1 PKCS#8 DER
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Создание блока PEM для приватного ключа
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}

	var privKey bytes.Buffer
	err = pem.Encode(&privKey, privateKeyBlock)
	if err != nil {
		return nil, err
	}

	return privKey.Bytes(), nil
}

func (s *JwtService) GenerateED25519Keys() (crypto.PublicKey, crypto.PrivateKey, error) {
	// Генерация приватного ключа
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func (s *JwtService) ConvertPublicKeyToPEM(key crypto.PublicKey) ([]byte, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}

	var pubKey bytes.Buffer
	err = pem.Encode(&pubKey, publicKeyBlock)
	if err != nil {
		return nil, err
	}

	return pubKey.Bytes(), nil
}

func (s *JwtService) ConvertPrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	var privateKey bytes.Buffer
	err = pem.Encode(&privateKey, privateKeyBlock)
	if err != nil {
		return nil, err
	}

	return privateKey.Bytes(), nil
}

func (s *JwtService) GetCurrentPublicKeyFromRedis(rdb *redis.Client) string {
	logger := logdoc.GetLogger()
	// Используем LINDEX с индексом 0 для получения последнего добавленного ключа
	key, err := rdb.LIndex(context.Background(), "keys:pem", 0).Result()
	if err != nil {
		logger.Fatalf("Failed to get current public key: %v", err)
	}
	decodedString, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return ""
	}

	return string(decodedString)
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
		panic("failed to decode PEM block")
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
		panic("failed to decode PEM block")
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

// DER keys format
// https://www.openssl.org/docs/man1.1.1/man1/pkcs8.html
func readPublicDERKey(der []byte) crypto.PublicKey {
	keyData, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil
	}

	switch key := keyData.(type) {
	case *rsa.PublicKey:
		return key
	case ed25519.PublicKey:
		return key
	default:
		return nil
	}

}

func readPrivateDERKey(der []byte) crypto.PrivateKey {
	keyData, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil
	}

	switch key := keyData.(type) {
	case *rsa.PrivateKey:
		return key
	case ed25519.PrivateKey:
		return key
	default:
		return nil
	}

}
