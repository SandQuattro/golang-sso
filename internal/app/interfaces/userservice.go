package interfaces

import (
	"context"
	db "sso/internal/app/repository/generated"
	"sso/internal/app/structs"
)

type UserService interface {
	FindUserById(ctx context.Context, id int) (user *structs.User, err error)
	FindUserByLogin(ctx context.Context, login string) (user *structs.User, err error)
	CreateUser(ctx context.Context, createUser *structs.CreateUser) (*db.User, error)
	LoginGoogleUser(ctx context.Context, googleUser *structs.GoogleUserInfo) (user *structs.User, err error)
	LoginMailRuUser(ctx context.Context, mailRuUser *structs.MailRuUserInfo) (user *structs.User, err error)
	LoginVKUser(ctx context.Context, vkUser *structs.VKUser) (user *structs.User, err error)
	LoginYandexUser(ctx context.Context, s *structs.YandexUserInfo) (user *structs.User, err error)
	MergeUserData(sessionID int, userID int) (err error)
	CreateUserNotification(ctx context.Context, userID int, notificationType string, code string) error
	GetUserNotificationByTypeAndCode(ctx context.Context, notificationType string, code string) (*structs.UserNotification, error)
	ConfirmEmail(ctx context.Context, code string, userID int) (*structs.User, error)
	UpdateUserPassword(ctx context.Context, code string, userID int, pwd []byte) error
}
