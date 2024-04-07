package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/jmoiron/sqlx"
	"github.com/opentracing/opentracing-go"
	"sso/internal/app/structs"
	"time"
)

type TokenRepository struct {
	DB *sqlx.DB
}

func NewTokenRepository(db *sqlx.DB) *TokenRepository {
	return &TokenRepository{db}
}

func (r *TokenRepository) FindToken(ctx context.Context, token string) (*structs.RefreshToken, error) {
	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "find token repository")
	defer span.Finish()

	var t structs.RefreshToken
	err := r.DB.QueryRowx(`SELECT id,
										user_id,
										token,
										expired_at,
										created_at
								  FROM tokens 
								 WHERE token = $1`, token).StructScan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		logger.Warn(fmt.Sprintf(">> FindToken > Ошибка поиска refresh токена: %s", token))
		return nil, err
	}

	return &t, nil
}

func (r *TokenRepository) CreateToken(ctx context.Context, userID int, token string, expiresIn int64) error {
	logger := logdoc.GetLogger()

	span, _ := opentracing.StartSpanFromContext(ctx, "create token repository")
	defer span.Finish()

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`DELETE FROM tokens WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		logger.Warn(fmt.Sprintf(">> CreateToken > Ошибка удаления refresh токена: %s", token))
		return err
	}

	_, err = tx.Exec(`INSERT INTO tokens(user_id,
												   token,
												   expired_at,
												   created_at)
								 VALUES ($1, $2, $3, $4)`,
		userID,
		token,
		time.Now().Add(time.Duration(expiresIn)*time.Second).UTC(),
		time.Now().UTC(),
	)

	if err != nil {
		logger.Warn(fmt.Sprintf(">> CreateToken > Ошибка создания refresh токена: %s", token))
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}
