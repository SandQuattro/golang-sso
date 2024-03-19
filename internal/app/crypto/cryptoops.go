package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/crypto/argon2"
	"runtime"
)

func Hash256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func HashArgon2(salt []byte, data string, keyLen uint32) []byte {
	hashed := argon2.IDKey([]byte(data), salt, 1, 64*1024, uint8(runtime.NumCPU()), keyLen)
	return append(salt, hashed...)
}

func ComparePass(passHash []byte, plainPass string) bool {
	salt := passHash[0:8]
	hashed := argon2.IDKey([]byte(plainPass), salt, 1, 64*1024, uint8(runtime.NumCPU()), uint32(len(passHash)-8))

	return bytes.Equal(hashed, passHash[8:])
}

// InsertSliceInPosition Если использовать плавающую позицию для вставки соли в хеш пароля
func InsertSliceInPosition(original, insert []byte, position int) []byte {
	if position < 0 || position > len(original) {
		return original // Return the original slice if the position is incorrect
	}

	result := make([]byte, len(original)+len(insert))
	at := copy(result, original[:position])
	at += copy(result[at:], insert)
	copy(result[at:], original[position:])

	return result
}
