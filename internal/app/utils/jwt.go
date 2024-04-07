package utils

import (
	localcrypto "sso/internal/app/crypto"
	"sso/internal/app/structs"
	"strconv"
)

func GenerateRefreshToken(user *structs.User, timestamp int64, refreshTokenExpiresIn int64) (string, int64, error) {
	refreshToken := localcrypto.Hash256(strconv.Itoa(user.ID) + user.AuthSystem + user.Email + strconv.Itoa(int(timestamp)))
	return refreshToken, refreshTokenExpiresIn, nil
}
