package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"log"
	"sso/internal/app/crypto"
	"testing"
)

var testQueries *Queries
var conn *sql.DB

func init() {
	c, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=admin dbname=demo sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	conn = c
	testQueries = New(conn)
}

func TestCreateUser(t *testing.T) {
	defer conn.Close()

	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		log.Println("Ошибка заполнения salt slice, ", err.Error())
		t.Fail()
	}

	hashedPwd := crypto.HashArgon2(salt, "12345", 32)

	arg := CreateUserParams{
		Name:           "Test",
		FamilyName:     sql.NullString{},
		GivenName:      sql.NullString{},
		Email:          "test@ya.ru",
		HashedPassword: hashedPwd,
		Role:           "user",
	}

	user, err := testQueries.CreateUser(context.Background(), arg)
	defer func() {
		err := testQueries.DeleteUser(context.Background(), user.ID)
		if err != nil {
			log.Println(err)
		}
	}()
	require.NoError(t, err)
	require.NotEmpty(t, user)

	require.Equal(t, arg.Name, user.Name)
	require.Equal(t, arg.FamilyName, user.FamilyName)
	require.Equal(t, arg.GivenName, user.GivenName)
	require.Equal(t, arg.Email, user.Email)
	require.Equal(t, arg.Role, user.Role)

	require.NotZero(t, user.ID)
}
