package symmetric

import (
	"crypto/aes"
	"fmt"
)

type AesCrypt struct {
	Encrypter
}

func (this *AesCrypt) Encrypt(key, raw string) ([]byte, error) {
	keyBytes := []byte(key)
	rawBytes := []byte(raw)
	cipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Encrypt create cipher from key [ %s ] failed! error where : %s", key, err.Error())
	}
	blockSize := cipher.BlockSize()
	originData := PKCS7Padding(rawBytes, blockSize)
	result := make([]byte, len(originData))
	cipher.Encrypt(result, originData)
	return result, nil
}

func (this *AesCrypt) Decrypt(key string, cipher []byte) ([]byte, error) {
	keyBytes := []byte(key)
	cipherBytes := []byte(cipher)
	c, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Decrypt create cipher from key [ %s ] failed! error where is : %s", key, err.Error())
	}
	result := make([]byte, len(cipherBytes))
	c.Decrypt(result, cipherBytes)
	result = PKCS7UnPadding(result)
	return result, nil
}
