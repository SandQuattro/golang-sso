package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash256(t *testing.T) {
	data := "test"
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" // hash of "test"
	hash := Hash256(data)
	assert.Equal(t, expected, hash)
}

func TestHashArgon2(t *testing.T) {
	salt := []byte("somesalt")
	data := "password"
	keyLen := uint32(32)
	hashed := HashArgon2(salt, data, keyLen)
	assert.Equal(t, int(keyLen)+len(salt), len(hashed))
}

func TestComparePass(t *testing.T) {
	salt := []byte("somesalt")
	password := "password"
	hashed := HashArgon2(salt, password, 32)
	assert.True(t, ComparePass(hashed, password))
	assert.False(t, ComparePass(hashed, "wrongpassword"))
}

func TestInsertSliceInPositionInvalidPosition(t *testing.T) {
	original := []byte("123456")
	insert := []byte("789")
	position := -1       // Invalid position
	expected := original // Expect the original slice to be returned
	result := InsertSliceInPosition(original, insert, position)
	assert.Equal(t, expected, result)

	position = 7        // Position out of range
	expected = original // Expect the original slice to be returned
	result = InsertSliceInPosition(original, insert, position)
	assert.Equal(t, expected, result)
}

func TestInsertSliceInPosition(t *testing.T) {
	original := []byte("123456")
	insert := []byte("789")
	position := 3
	expected := []byte("123789456")
	result := InsertSliceInPosition(original, insert, position)
	assert.Equal(t, expected, result)
}
