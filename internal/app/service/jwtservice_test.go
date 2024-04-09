package service

import (
	"context"
	"os"
	"testing"
	"time"

	jwtverification "github.com/SandQuattro/jwt-verification"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gurkankaymak/hocon"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var CONFIG, _ = hocon.ParseString(`
jwt {
    issuer=me
    audience=me
	rotate = false
	algo = "RSA" // ED25519, RSA
	type = 0 // PEM 0, DER 1
}`)

var REDIS = redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

func getConfig() *hocon.Config {
	return CONFIG
}

func TestRSAPEMKeysGenerate(t *testing.T) {
	service := NewJWTService(context.Background(), getConfig, REDIS, nil)
	pubKey, privKey, err := service.GenerateRSAKeys(2048)
	if err != nil {
		t.Fatalf("Error generating RSA keys: %v", err)
	}
	assert.NotNil(t, pubKey)
	assert.NotNil(t, privKey)
}

func TestED25519PEMKeysGenerate(t *testing.T) {
	service := NewJWTService(context.Background(), getConfig, REDIS, nil)
	_, _, err := service.GenerateED25519Keys()
	if err != nil {
		t.Fatalf("Error generating ED25519 keys: %v", err)
	}
}

func TestDataSigningWithED25519(t *testing.T) {
	service := NewJWTService(context.Background(), getConfig, REDIS, nil)
	publicKey, privateKey, err := service.GenerateED25519Keys()
	if err != nil || privateKey == nil {
		t.Fatalf("Error generating keys or private key is nil: %v", err)
	}

	tempFile, err := os.CreateTemp("", "public_test.pem")
	if err != nil {
		t.Fatalf("Error creating temp file: %v", err)
	}
	defer os.Remove(tempFile.Name()) // clean up

	pubpem, err := service.ConvertPublicKeyToPEM(publicKey)
	if err != nil {
		t.Fatalf("Error converting public key to PEM: %v", err)
	}

	_, err = tempFile.Write(pubpem)
	if err != nil {
		t.Fatalf("Error writing public key to temp file: %v", err)
	}

	claims := jwt.MapClaims{
		"id":  float64(1),
		"iss": "me",
		"aud": "me",
		"exp": float64(time.Now().Add(time.Second * 1).Unix()),
	}

	// Генерируем токен
	token, err := jwt.NewWithClaims(getSigningMethod(privateKey), claims).SignedString(privateKey)
	if err != nil {
		t.Fatalf("Ошибка генерации токена: %v", err)
	}

	verificator := jwtverification.New(getConfig, logrus.New(), jwtverification.PEM)
	claims2, _, err := verificator.ValidateToken(token, tempFile.Name(), nil)
	if err != nil {
		t.Fatalf("Ошибка проверки токена: %v", err)
	}

	assert.Equal(t, claims, claims2)
}

func TestGenerateED25519Keys(t *testing.T) {
	service := NewJWTService(context.Background(), getConfig, REDIS, nil)
	publicKey, privateKey, err := service.GenerateED25519Keys()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 keys: %v", err)
	}
	if publicKey == nil || privateKey == nil {
		t.Fatal("Generated keys are nil")
	}
}

func TestConvertPublicKeyToPEM(t *testing.T) {
	service := NewJWTService(context.Background(), getConfig, REDIS, nil)
	publicKey, _, err := service.GenerateED25519Keys()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 keys: %v", err)
	}

	pubPEM, err := service.ConvertPublicKeyToPEM(publicKey)
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}
	if len(pubPEM) == 0 {
		t.Fatal("Generated PEM is empty")
	}
}

func TestGenerateKeysRotation(t *testing.T) {
	// Mocking Redis client and context
	ctx := context.Background()
	mockRedis := redis.NewClient(&redis.Options{})
	defer mockRedis.Close()

	service := NewJWTService(ctx, getConfig, mockRedis, nil)
	service.GenerateKeys(mockRedis, jwtverification.PEM, "ED25519")

	// Assuming the key is pushed to Redis, check if the list is not empty
	result, err := mockRedis.LLen(ctx, "key:pem").Result()
	if err != nil {
		t.Fatalf("Failed to get keys from Redis: %v", err)
	}
	if result == 0 {
		t.Fatal("No keys were rotated into Redis")
	}
}
