package structs

import (
	"database/sql"
)

type ErrorResponse struct {
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

type RefreshToken struct {
	ID        int    `db:"id" json:"id"`
	UserID    int    `db:"user_id" json:"user_id"`
	Token     string `db:"token" json:"token"`
	ExpiredAt string `db:"expired_at" json:"expired_at"`
	CreatedAt string `db:"created_at" json:"created_at"`
}

type CreateUser struct {
	Last     string `json:"lastName" validate:"required"`
	First    string `json:"firstName" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type IncomingUser struct {
	Login    string `json:"login" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type User struct {
	ID            int          `db:"id"`
	AuthSystem    string       `db:"auth_system"`
	Sub           string       `db:"sub"`
	Name          string       `db:"name"`
	GivenName     string       `db:"given_name"`
	FamilyName    string       `db:"family_name"`
	Avatar        string       `db:"avatar"`
	Email         string       `db:"email" validate:"required,email"`
	EmailVerified bool         `db:"email_verified"`
	Locale        string       `db:"locale"`
	Password      []byte       `db:"hashed_password" validate:"required"`
	Role          string       `db:"role" validate:"required"`
	ValidTill     sql.NullTime `db:"valid_till" validate:"required"`
}

type UserNotification struct {
	ID        int          `db:"id"`
	UserID    int          `db:"user_id"`
	Code      string       `db:"code"`
	CreatedAt sql.NullTime `db:"created_at"`
}

type GoogleUserInfo struct {
	ID            int    `db:"id"`
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
	Password      []byte `db:"hashed_password" validate:"required"`
	Role          string `db:"role" validate:"required"`
}

type MailRuUserInfo struct {
	ID        int    `db:"id" json:"id,string,omitempty"`
	ClientID  string `json:"client_id"`
	Gender    string `json:"gender"`
	Name      string `json:"name"`
	Nickname  string `json:"nickname"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Locale    string `json:"locale"`
	Email     string `json:"email"`
	Birthday  string `json:"birthday"`
	Image     string `json:"image"`
}

type VKUserInfo struct {
	Response []VKUser `json:"response"`
}

type YandexUserInfo struct {
	ID           string   `json:"id"`
	Login        string   `json:"login"`
	ClientID     string   `json:"client_id"`
	DefaultEmail string   `json:"default_email"`
	Emails       []string `json:"emails"`
	Psuid        string   `json:"psuid"`
}

type VKUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Photo     string `json:"photo_400_orig"`
	City      City   `json:"city"`
}

type City struct {
	Title string `json:"title"`
}

type ResponseUser struct {
	ID         int    `json:"-"`
	First      string `json:"firstName" validate:"required"`
	Last       string `json:"lastName" validate:"required"`
	Email      string `json:"email" validate:"required,email"`
	TenantName string `json:"tenant" validate:"required"`
	Role       string `json:"role" validate:"required"`
}

type Token struct {
	Token string `json:"token" xml:"token"`
}

type AuthRes struct {
	Token string `json:"token"`
}
