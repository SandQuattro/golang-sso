package interfaces

import (
	"context"
	"sso/internal/app/structs"
)

type UserRepository interface {
	FindUserByLogin(ctx context.Context, login string) (user *structs.User, err error)
	FindUserBySub(sub string) (user *structs.User, err error)
	FindUserByID(ctx context.Context, id int) (user *structs.User, err error)
	FindUserByLoginAndSystem(ctx context.Context, login string, system string) (user *structs.User, err error)
	FindUserProfile(ctx context.Context, userID int) (map[string]interface{}, error)
	CreateUserProfile(ctx context.Context, userID int, profile map[string]interface{}) error
	Create(ctx context.Context, hashedPassword []byte, createUser *structs.CreateUser) (err error)
	CreateGoogleUser(ctx context.Context, googleUser *structs.GoogleUserInfo) (user *structs.User, err error)
	CreateMailRuUser(ctx context.Context, mailRuUser *structs.MailRuUserInfo) (user *structs.User, err error)
	CreateVKUser(ctx context.Context, vkUser *structs.VKUser) (user *structs.User, err error)
	CreateYandexUser(ctx context.Context, info *structs.YandexUserInfo) (*structs.User, error)
	MergeUserData(sessionID int, userID int) error
	MergeResults(sessionID int, userID int) error
	CreateUserNotification(ctx context.Context, userID int, notificationType string, code string) error
	FindUserNotificationByTypeAndCode(ctx context.Context, notificationType string, code string) (*structs.UserNotification, error)
	ConfirmEmail(ctx context.Context, code string, userID int) (*structs.User, error)
	UpdateUserPassword(ctx context.Context, code string, userID int, pwd []byte) error
}
