package symmetric

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestAesCrypt_Encrypt(t *testing.T) {
	key := "kLieko0EWllskjeWkLieko0EWllskjeW"
	value := "hello world"
	aesCipher := AesCrypt{
		Encrypter: Encrypter{
			Format:     "base64",
			DecodeFunc: base64.StdEncoding.DecodeString,
			EncodeFunc: base64.StdEncoding.EncodeToString,
		},
	}
	encrypt, err := aesCipher.Encrypt(key, value)
	if err != nil {
		t.Fail()
	}
	fmt.Println(aesCipher.EncodeFunc(encrypt))
}

func TestAesCrypt_Decrypt(t *testing.T) {
	key := "kLieko0EWllskjeWkLieko0EWllskjeW"
	raw := "eSFvkh0qejaCwdIlpV8DwQ=="
	aesCipher := AesCrypt{
		Encrypter: Encrypter{
			Format:     "base64",
			DecodeFunc: base64.StdEncoding.DecodeString,
			EncodeFunc: base64.StdEncoding.EncodeToString,
		},
	}
	rawBytes, err := aesCipher.DecodeFunc(raw)
	if err != nil {
		t.Fail()
	}
	result, err := aesCipher.Decrypt(key, rawBytes)
	if err != nil {
		t.Fail()
	}
	fmt.Println(string(result))
}
