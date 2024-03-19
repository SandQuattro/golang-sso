package crypto

import (
	"reflect"
	"testing"
)

func TestHash256(t *testing.T) {
	testCases := []struct {
		name string
		data string
		want string
	}{
		{
			name: "Hash256 with empty string",
			data: "",
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "Hash256 with non-empty string",
			data: "hello",
			want: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Hash256(tc.data); got != tc.want {
				t.Errorf("Hash256() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHashArgon2(t *testing.T) {
	testCases := []struct {
		name   string
		salt   []byte
		data   string
		keyLen uint32
	}{
		{
			name:   "HashArgon2 with empty string and salt",
			salt:   []byte(""),
			data:   "",
			keyLen: 32,
		},
		{
			name:   "HashArgon2 with non-empty string and salt",
			salt:   []byte("somesalt"),
			data:   "hello",
			keyLen: 32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := HashArgon2(tc.salt, tc.data, tc.keyLen)
			if len(got) != int(tc.keyLen)+len(tc.salt) {
				t.Errorf("HashArgon2() length = %v, want %v", len(got), int(tc.keyLen)+len(tc.salt))
			}
		})
	}
}

func TestInsertSliceInPosition(t *testing.T) {
	testCases := []struct {
		name     string
		original []byte
		insert   []byte
		position int
		want     []byte
	}{
		{
			name:     "InsertSliceInPosition with invalid position",
			original: []byte("hello"),
			insert:   []byte("world"),
			position: -1,
			want:     []byte("hello"),
		},
		{
			name:     "InsertSliceInPosition with valid position",
			original: []byte("hello"),
			insert:   []byte("world"),
			position: 3,
			want:     []byte("helloworld"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := InsertSliceInPosition(tc.original, tc.insert, tc.position)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("InsertSliceInPosition() = %v, want %v", got, tc.want)
			}
		})
	}
}
