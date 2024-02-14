package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/klauspost/cpuid/v2"
	"golang.org/x/crypto/argon2"
)

func Hash256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func HashArgon2(salt []byte, data string, keyLen uint32) []byte {
	hashed := argon2.IDKey([]byte(data), salt, 1, 64*1024, uint8(cpuid.CPU.LogicalCores), keyLen)
	return append(salt, hashed...)
}

func ComparePass(passHash []byte, plainPass string) bool {
	salt := passHash[0:8]
	hashed := argon2.IDKey([]byte(plainPass), salt, 1, 64*1024, uint8(cpuid.CPU.LogicalCores), uint32(len(passHash)-8))

	return bytes.Equal(hashed, passHash[8:])
}

// Если использовать плавающую позицию для вставки соли в хеш пароля
func InsertSliceInPosition(original, insert []byte, position int) []byte {
	// Проверяем, что позиция в пределах допустимого диапазона для вставки
	if position < 0 || position > len(original) {
		return original // Возвращаем исходный срез, если позиция некорректна
	}
	// Создаем новый срез с достаточной емкостью
	result := make([]byte, len(original)+len(insert))
	at := copy(result, original[:position]) // Копируем первую часть до позиции вставки
	at += copy(result[at:], insert)         // Вставляем второй срез
	copy(result[at:], original[position:])  // Дополняем оставшейся частью первого среза
	return result
}
