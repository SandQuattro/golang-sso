package userservice

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/jmoiron/sqlx"
	"github.com/opentracing/opentracing-go"
	"sso/internal/app/errs"
	"sso/internal/app/interfaces"
	"sso/internal/app/repository"
	db "sso/internal/app/repository/generated"
	"sso/internal/app/structs"
	"sso/internal/app/utils"
	"strconv"
)

type UserService struct {
	db      *sqlx.DB
	config  *hocon.Config
	queries *db.Queries
	r       interfaces.UserRepository
}

func New(config *hocon.Config, database *sqlx.DB) *UserService {
	urepo := repository.New(database)
	queries := db.New(database)
	return &UserService{db: database, config: config, queries: queries, r: urepo}
}

func (s *UserService) FindUserById(ctx context.Context, id int) (user *structs.User, err error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "find user by id service")
	defer span.Finish()

	u, err := s.r.FindUserByID(ctx, id)
	if err != nil {
		span.SetTag("error", true)
		span.LogKV("error.message", err.Error())
		return nil, err
	}

	if u != nil {
		span.LogKV("user found", u.Email)
		span.SetTag("service", "user service")
	}

	return u, nil
}

func (s *UserService) FindUserByLogin(ctx context.Context, login string) (user *structs.User, err error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "find user by login service")
	defer span.Finish()

	u, err := s.r.FindUserByLogin(ctx, login)
	if err != nil {
		span.SetTag("error", true)
		span.LogKV("error.message", err.Error())
		return nil, err
	}

	if u != nil {
		span.LogKV("user found", u.Email)
		span.SetTag("service", "user service")
	}

	return u, nil
}

func (s *UserService) CreateUser(ctx context.Context, createUser *structs.CreateUser) (*db.User, error) {
	logger := logdoc.GetLogger()

	span, ctx := opentracing.StartSpanFromContext(ctx, "create user service")
	defer span.Finish()

	u, err := s.r.FindUserByLoginAndSystem(ctx, createUser.Email, "direct")
	if err != nil {
		logger.Warn(err)
	}

	if u != nil {
		logger.Warn("пользователь уже существует, выходим")
		span.LogKV("error.message", "пользователь "+u.Email+" уже существует")
		span.SetTag("error", true)
		err := utils.CreateTask(s.config, span, utils.TypeTelegramDelivery, u.Name, u.Email, u.ID, fmt.Sprintf("Attention required! Error in user service, account registration error: %s already exists", u.Email))
		if err != nil {
			return nil, err
		}
		return nil, errors.New("пользователь уже существует")
	}

	salt := make([]byte, 8)
	_, err = rand.Read(salt)
	if err != nil {
		logger.Error("Ошибка заполнения salt slice, ", err.Error())
		span.SetTag("error", true)
		return nil, err
	}

	hashedPwd := utils.HashArgon2(salt, createUser.Password, 32)

	// err = s.r.Create(ctx, hashedPwd, createUser)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	qtx := s.queries.WithTx(tx)

	args := db.CreateUserParams{
		Email:         createUser.Email,
		EmailVerified: false,
		Name:          createUser.Last + " " + createUser.First,
		FamilyName: sql.NullString{
			String: createUser.Last,
			Valid:  true,
		},
		HashedPassword: hashedPwd,
		Role:           "user",
	}

	user, err := qtx.CreateUser(ctx, args)
	if err != nil {
		return nil, err
	}

	if err != nil {
		span.LogKV("error.message", err.Error())
		span.SetTag("error", true)
		return nil, err
	}

	return &user, tx.Commit()
}

func (s *UserService) CreateUserNotification(ctx context.Context, userId int, notificationType string, code string) error {
	logger := logdoc.GetLogger()

	span, ctx := opentracing.StartSpanFromContext(ctx, "create user notification")
	defer span.Finish()

	err := s.r.CreateUserNotification(ctx, userId, notificationType, code)
	if err != nil {
		logger.Error(err)
		return err
	}

	return nil
}

func (s *UserService) GetUserNotificationByTypeAndCode(ctx context.Context, notificationType string, code string) (*structs.UserNotification, error) {
	logger := logdoc.GetLogger()

	span, ctx := opentracing.StartSpanFromContext(ctx, "get user notification")
	defer span.Finish()

	notification, err := s.r.FindUserNotificationByTypeAndCode(ctx, notificationType, code)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	return notification, nil
}

func (s *UserService) ConfirmEmail(ctx context.Context, code string, userID int) (*structs.User, error) {
	logger := logdoc.GetLogger()

	span, ctx := opentracing.StartSpanFromContext(ctx, "confirm email")
	defer span.Finish()

	user, err := s.r.ConfirmEmail(ctx, code, userID)

	if err != nil {
		logger.Error(err)
		return nil, err
	}

	return user, nil
}

func (s *UserService) LoginGoogleUser(ctx context.Context, googleUser *structs.GoogleUserInfo) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> UserService > Ошибка входа под google пользователем", err)
	}()

	logger := logdoc.GetLogger()

	span, ctx := opentracing.StartSpanFromContext(ctx, "login google user service")
	defer span.Finish()

	u, err := s.r.FindUserByLoginAndSystem(ctx, googleUser.Email, "google")
	if err != nil {
		span.SetTag("error", true)
		return nil, err
	}

	if u != nil {
		logger.Info("пользователь уже существует")
		span.SetTag("error", true)
		return u, nil
	}

	u, err = s.r.CreateGoogleUser(ctx, googleUser)
	if err != nil {
		span.SetTag("error", true)
		return nil, err
	}

	u.Sub = googleUser.Sub

	return u, nil
}

func (s *UserService) LoginMailRuUser(ctx context.Context, mailRuUser *structs.MailRuUserInfo) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> UserService > Ошибка входа под maiRu пользователем", err)
	}()

	logger := logdoc.GetLogger()

	span, ctx := opentracing.StartSpanFromContext(ctx, "login mail user service")
	defer span.Finish()

	u, err := s.r.FindUserByLoginAndSystem(ctx, mailRuUser.Email, "mailru")
	if err != nil {
		span.SetTag("error", true)
		return nil, err
	}

	if u != nil {
		logger.Info("пользователь уже существует")
		span.SetTag("error", true)
		return u, nil
	}

	u, err = s.r.CreateMailRuUser(ctx, mailRuUser)
	if err != nil {
		span.SetTag("error", true)
		return nil, err
	}

	u.Sub = strconv.Itoa(int(mailRuUser.ID))

	return u, nil
}

func (s *UserService) LoginVKUser(ctx context.Context, vkUser *structs.VKUser) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> UserService > Ошибка входа под VK пользователем", err)
	}()

	logger := logdoc.GetLogger()

	span, ctx := opentracing.StartSpanFromContext(ctx, "login vk user service")
	defer span.Finish()

	u, err := s.r.FindUserByLoginAndSystem(ctx, vkUser.Email, "vk")
	if err != nil {
		span.SetTag("error", true)
		return nil, err
	}

	if u != nil {
		logger.Info("пользователь уже существует")
		span.SetTag("error", true)
		return u, nil
	}

	u, err = s.r.CreateVKUser(ctx, vkUser)
	if err != nil {
		span.SetTag("error", true)
		return nil, err
	}

	u.Sub = strconv.Itoa(int(vkUser.ID))

	return u, nil
}

func (s *UserService) MergeUserData(sessionID int, userID int) (err error) {
	defer func() {
		err = errs.WrapIfErr(">> UserService > Ошибка объединения пользовательских данных VK", err)
	}()

	err = s.r.MergeUserData(sessionID, userID)
	if err != nil {
		return err
	}

	err = s.r.MergeResults(sessionID, userID)
	if err != nil {
		return err
	}

	return nil
}

func (s *UserService) UpdateUserPassword(ctx context.Context, code string, userID int, pwd []byte) error {
	return s.r.UpdateUserPassword(ctx, code, userID, pwd)
}
