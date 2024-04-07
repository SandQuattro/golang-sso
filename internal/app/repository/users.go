package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/jmoiron/sqlx"
	"github.com/opentracing/opentracing-go"
	"sso/internal/app/errs"
	"sso/internal/app/structs"
	"time"
)

type UserRepository struct {
	DB *sqlx.DB
}

func New(db *sqlx.DB) *UserRepository {
	return &UserRepository{db}
}

func (r *UserRepository) FindUserByID(ctx context.Context, id int) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> FindUserByID > Ошибка поиска пользователя по id", err)
	}()

	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "find user by id repository")
	defer span.Finish()

	var u structs.User
	err = r.DB.QueryRowx(`SELECT u.id,
       									COALESCE(u.auth_system, '') as auth_system,
										COALESCE(u.sub,'') as sub,
										COALESCE(u.name,'') as name,
										COALESCE(u.given_name,'') as given_name,
										COALESCE(u.family_name,'') as family_name,
										COALESCE(u.avatar,'') as avatar,
										COALESCE(u.email,'') as email,
										u.email_verified,
										COALESCE(u.locale,'') as locale,
										COALESCE(u.hashed_password,'') as hashed_password,
										COALESCE(u.role, '') as role,
										valid_till
								  FROM users u
								 WHERE u.id = $1`, id).StructScan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil || u.ID == 0 {
		logger.Warn(fmt.Sprintf(">> FindUserById > Ошибка поиска пользователя по id: %d", id))
		// A return statement without arguments returns the named return values.
		// This is known as a "naked" return.
		return
	}

	user = &u
	// A return statement without arguments returns the named return values.
	// This is known as a "naked" return.
	return
}

func (r *UserRepository) FindUserByLogin(ctx context.Context, login string) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> FindUserByLogin > Ошибка поиска пользователя по login", err)
	}()

	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "find user by login repository")
	defer span.Finish()

	var u structs.User
	err = r.DB.QueryRowx(`SELECT u.id,
       									COALESCE(u.auth_system, '') as auth_system,
										COALESCE(u.sub,'') as sub,
										COALESCE(u.name,'') as name,
										COALESCE(u.given_name,'') as given_name,
										COALESCE(u.family_name,'') as family_name,
										COALESCE(u.avatar,'') as avatar,
										COALESCE(u.email,'') as email,
										u.email_verified,
										COALESCE(u.locale,'') as locale,
										COALESCE(u.hashed_password,'') as hashed_password,
										COALESCE(u.role, '') as role,
										valid_till
								   FROM users u
								  WHERE u.email = $1`, login).StructScan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil || u.ID == 0 {
		logger.Warn(fmt.Sprintf(">> FindUserByLogin > Ошибка поиска пользователя по login: %s", login))
		// A return statement without arguments returns the named return values.
		// This is known as a "naked" return.
		return nil, err
	}

	user = &u

	span.LogKV("user found in db", u.Email)
	span.SetTag("repository", "users repository")

	return
}

func (r *UserRepository) FindUserBySub(sub string) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> FindUserBySub > Ошибка поиска пользователя по sub", err)
	}()

	logger := logdoc.GetLogger()

	var u structs.User
	err = r.DB.Get(&u, `SELECT id,
										coalesce(sub,'') as sub,
										name,
										given_name,
										family_name,
										coalesce(avatar, '') as avatar,
										email,
										email_verified,
										coalesce(locale,'') as locale,
										hashed_password,
										role
									FROM users u
								   WHERE u.sub = $1`, sub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil || u.ID == 0 {
		logger.Warn(fmt.Sprintf(">> FindUserBySub > Ошибка поиска пользователя по sub: %s", sub))
		// A return statement without arguments returns the named return values.
		// This is known as a "naked" return.
		return
	}

	user = &u
	// A return statement without arguments returns the named return values.
	// This is known as a "naked" return.
	return
}

func (r *UserRepository) FindUserByLoginAndSystem(ctx context.Context, login string, system string) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> FindUserByLoginAndSystem > Ошибка поиска пользователя по login и auth system", err)
	}()

	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "find user by login and system repository")
	defer span.Finish()

	var u structs.User
	err = r.DB.QueryRowx(`SELECT u.id,
       									COALESCE(u.auth_system, '') as auth_system,
										COALESCE(u.sub,'') as sub,
										COALESCE(u.name,'') as name,
										COALESCE(u.given_name,'') as given_name,
										COALESCE(u.family_name,'') as family_name,
										COALESCE(u.avatar,'') as avatar,
										COALESCE(u.email,'') as email,
										u.email_verified,
										COALESCE(u.locale,'') as locale,
										COALESCE(u.hashed_password,'') as hashed_password,
										COALESCE(u.role, '') as role
								   FROM users u
								  WHERE u.email = $1 and u.auth_system = $2`, login, system).StructScan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil || u.ID == 0 {
		logger.Warn(fmt.Sprintf(">> FindUserByLogin > Ошибка поиска пользователя по login:%s и auth system:%s", login, system))
		// A return statement without arguments returns the named return values.
		// This is known as a "naked" return.
		return nil, err
	}

	user = &u
	// A return statement without arguments returns the named return values.
	// This is known as a "naked" return.
	return
}

func (r *UserRepository) FindUserProfile(ctx context.Context, userID int) (map[string]interface{}, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "getting user profile repository")
	defer span.Finish()

	profile := make(map[string]interface{})

	err := r.DB.QueryRowx(`SELECT id,
									     user_id,
									     send_messages
								   FROM user_profile_settings
								  WHERE user_id = $1`, userID).MapScan(profile)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		logger.Warn(fmt.Sprintf(">> FindUserProfile > Ошибка поиска профиля пользователя по id:%d", userID))
		return nil, err
	}

	return profile, nil
}

func (r *UserRepository) FindUserNotificationByTypeAndCode(ctx context.Context, notificationType string, code string) (*structs.UserNotification, error) {
	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "find user notification by type and code repository")
	defer span.Finish()

	var notification structs.UserNotification
	err := r.DB.QueryRowx(`SELECT n.id,
       									n.user_id,
       									n.code,
       									n.created_at
								   FROM user_notifications n
								  WHERE type = $1 AND code = $2`, notificationType, code).StructScan(&notification)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil || notification.ID == 0 {
		logger.Warn(fmt.Sprintf(">> FindUserNotificationByTypeAndCode > Ошибка поиска нотификации пользователя по code:%s", code))
		return nil, err
	}

	return &notification, nil
}

func (r *UserRepository) Create(ctx context.Context, hashedPassword []byte, createUser *structs.CreateUser) (err error) {
	defer func() {
		err = errs.WrapIfErr(">> CreateUser > Ошибка создания пользователя", err)
	}()

	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "create user repository")
	defer span.Finish()

	_, err = r.DB.Exec(`INSERT INTO users(auth_system,
                  								name,
												family_name,
												given_name,
												email,
												hashed_password,
												role) 
											VALUES($1, 
											       $2, 
											       $3,
											       $4,
											       $5,
											       $6,
											       $7)`,
		"direct",
		createUser.Last+" "+createUser.First,
		createUser.Last,
		createUser.First,
		createUser.Email,
		hashedPassword,
		"user",
	)
	if err != nil {
		logger.Error("Ошибка создания пользователя, ", err.Error())
		// A return statement without arguments returns the named return values.
		// This is known as a "naked" return.
		return
	}

	// A return statement without arguments returns the named return values.
	// This is known as a "naked" return.
	return nil
}

func (r *UserRepository) CreateUserProfile(ctx context.Context, userID int, profile map[string]interface{}) error {
	logger := logdoc.GetLogger()
	span, _ := opentracing.StartSpanFromContext(ctx, "create user profile repository")
	defer span.Finish()

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		logger.Error(">> CreateUserProfile > error starting transaction")
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`DELETE FROM user_profile_settings WHERE user_id = $1`, userID)
	if err != nil {
		logger.Error("Ошибка удаления профиля пользователя, ", err.Error())
		return err
	}

	_, err = tx.Exec(`INSERT INTO user_profile_settings(user_id, send_messages) 
											VALUES($1, $2)`,
		userID,
		profile["send_messages"],
	)
	if err != nil {
		logger.Error("Ошибка создания профиля пользователя, ", err.Error())
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (r *UserRepository) CreateUserNotification(ctx context.Context, userID int, notificationType string, code string) error {
	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "create user notification repository")
	defer span.Finish()

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Commit()

	_, err = tx.Exec(`DELETE FROM user_notifications WHERE user_id = $1 and type = $2`, userID, notificationType)
	if err != nil {
		logger.Error("Ошибка удаления нотификаций пользователя, ", err.Error())
		tx.Rollback()
		return err
	}

	_, err = tx.Exec(`INSERT INTO user_notifications(user_id,
														   code,
                               							   type,
														   created_at) 
											VALUES($1, 
											       $2, 
											       $3,
											       now()
											      );`,
		userID,
		code,
		notificationType,
	)
	if err != nil {
		logger.Error("Ошибка создания нотификации пользователя, ", err.Error())
		tx.Rollback()
		return err
	}

	return nil
}

func (r *UserRepository) ConfirmEmail(ctx context.Context, code string, userID int) (*structs.User, error) {
	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "confirm email repository")
	defer span.Finish()

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Commit()

	_, err = tx.Exec(`DELETE FROM user_notifications WHERE code = $2 and user_id = $1`, userID, code)
	if err != nil {
		logger.Error("Ошибка удаления нотификаций пользователя, ", err.Error())
		tx.Rollback()
		return nil, err
	}

	_, err = tx.Exec(`UPDATE users set email_verified = true WHERE id = $1`, userID)
	if err != nil {
		logger.Error("Ошибка обновления пользователя, ", err.Error())
		tx.Rollback()
		return nil, err
	}

	user, err := r.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) UpdateUserPassword(ctx context.Context, code string, userID int, pwd []byte) error {
	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "update user password repository")
	defer span.Finish()

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Commit()

	_, err = tx.Exec(`DELETE FROM user_notifications WHERE code = $2 and user_id = $1`, userID, code)
	if err != nil {
		logger.Error("Ошибка удаления нотификаций пользователя, ", err.Error())
		tx.Rollback()
		return err
	}

	_, err = tx.Exec(`UPDATE users set hashed_password = $2 WHERE id = $1`, userID, pwd)
	if err != nil {
		logger.Error("Ошибка обновления пароля пользователя, ", err.Error())
		tx.Rollback()
		return err
	}

	return nil
}

func (r *UserRepository) CreateGoogleUser(ctx context.Context, googleUser *structs.GoogleUserInfo) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> CreateGoogleUser > Ошибка создания google пользователя", err)
	}()

	logger := logdoc.GetLogger()

	_, err = r.DB.Exec(`INSERT INTO users( auth_system,
                  								  sub,
												  name,
												  given_name,
												  family_name,
												  avatar,
												  email,
												  email_verified,
												  locale,
												  hashed_password,
												  role,
												  valid_till)	 
											VALUES($1, 
											       $2,  
											       $3, 
											       $4, 
											       $5, 
											       $6, 
											       $7, 
											       $8, 
											       $9,
											       $10,
											       $11,
											       $12
											       )`,
		"google",
		googleUser.Sub,
		googleUser.Name,
		googleUser.GivenName,
		googleUser.FamilyName,
		googleUser.Picture,
		googleUser.Email,
		googleUser.EmailVerified,
		googleUser.Locale,
		nil,
		"user",
		time.Now().UTC().Add(1*24*time.Hour),
	)
	if err != nil {
		logger.Error("Ошибка создания google пользователя, ", err.Error())
		return nil, err
	}

	return r.FindUserByLoginAndSystem(ctx, googleUser.Email, "google")
}

func (r *UserRepository) CreateMailRuUser(ctx context.Context, mailRuUser *structs.MailRuUserInfo) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> CreateMailRuUser > Ошибка создания mailRu пользователя", err)
	}()

	logger := logdoc.GetLogger()

	_, err = r.DB.Exec(`INSERT INTO users( auth_system,
												  sub,
												  name,
												  given_name,
												  family_name,
												  avatar,
												  email,
												  email_verified,
												  locale,
												  hashed_password,
												  role) 
											VALUES($1, 
											       $2,  
											       $3, 
											       $4, 
											       $5, 
											       $6, 
											       $7, 
											       $8, 
											       $9,
											       $10,
											       $11
											       )`,
		"mailru",
		mailRuUser.ID,
		mailRuUser.Name,
		mailRuUser.FirstName,
		mailRuUser.LastName,
		mailRuUser.Image,
		mailRuUser.Email,
		true,
		mailRuUser.Locale,
		nil,
		"user",
	)
	if err != nil {
		logger.Error("Ошибка создания MailRu пользователя, ", err.Error())
		return nil, err
	}

	return r.FindUserByLoginAndSystem(ctx, mailRuUser.Email, "mailru")
}

func (r *UserRepository) CreateVKUser(ctx context.Context, vkUser *structs.VKUser) (user *structs.User, err error) {
	defer func() {
		err = errs.WrapIfErr(">> CreateMailRuUser > Ошибка создания VK пользователя", err)
	}()

	logger := logdoc.GetLogger()

	_, err = r.DB.Exec(`INSERT INTO users(auth_system, 
												sub,
											    name,
											    given_name,
											    family_name,
											    avatar,
											    email,
											    email_verified,
											    locale,
											    hashed_password,
											    role) 
											VALUES($1, 
											       $2,  
											       $3, 
											       $4, 
											       $5, 
											       $6, 
											       $7, 
											       $8, 
											       $9,
											       $10,
											       $11
											       )`,
		"vk",
		vkUser.ID,
		vkUser.FirstName+" "+vkUser.LastName,
		vkUser.FirstName,
		vkUser.LastName,
		vkUser.Photo,
		vkUser.Email,
		true,
		"ru",
		nil,
		"user",
	)
	if err != nil {
		logger.Error("Ошибка создания VK пользователя, ", err.Error())
		return nil, err
	}

	return r.FindUserByLoginAndSystem(ctx, vkUser.Email, "vk")
}

func (r *UserRepository) CreateYandexUser(ctx context.Context, userInfo *structs.YandexUserInfo) (*structs.User, error) {
	logger := logdoc.GetLogger()

	_, err := r.DB.Exec(`INSERT INTO users(auth_system, 
												sub,
											    name,
											    given_name,
											    family_name,
											    avatar,
											    email,
											    email_verified,
											    locale,
											    hashed_password,
											    role) 
											VALUES($1, 
											       $2,  
											       $3, 
											       $4, 
											       $5, 
											       $6, 
											       $7, 
											       $8, 
											       $9,
											       $10,
											       $11
											       )`,
		"yandex",
		userInfo.ID,
		userInfo.Login,
		"",
		"",
		"",
		userInfo.DefaultEmail,
		true,
		"ru",
		nil,
		"user",
	)
	if err != nil {
		logger.Error("Ошибка создания Yandex пользователя, ", err.Error())
		return nil, err
	}

	return r.FindUserByLoginAndSystem(ctx, userInfo.DefaultEmail, "yandex")
}

func (r *UserRepository) MergeUserData(sessionID int, userID int) error {
	logger := logdoc.GetLogger()

	_, err := r.DB.Exec(`UPDATE user_layers SET user_id = $2 WHERE user_id = $1`,
		sessionID,
		userID,
	)

	if err != nil {
		logger.Error("Ошибка объединения сессии и пользователя, ", err.Error())
		return err
	}

	return nil
}

func (r *UserRepository) MergeResults(sessionID int, userID int) error {
	logger := logdoc.GetLogger()

	_, err := r.DB.Exec(`UPDATE results SET user_id = $2 WHERE user_id = $1`,
		sessionID,
		userID,
	)

	if err != nil {
		logger.Error("Ошибка объединения результатов сессии и пользователя, ", err.Error())
		return err
	}

	return nil
}
