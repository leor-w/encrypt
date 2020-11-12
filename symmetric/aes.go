package symmetric

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

type AesCrypt struct {
}

func (this *AesCrypt) Encrypt(key, raw string) ([]byte, error) {
	keyBytes := []byte(key)
	rawBytes := []byte(raw)
	cipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Create cipher from key [ %s ] failed! error where : %s", key, err.Error())
	}
	blockSize := cipher.BlockSize()
	originData := PKCS7Padding(rawBytes, blockSize)
	result := make([]byte, len(originData))
	cipher.Encrypt(result, originData)
	return result, nil
}

func (this *AesCrypt) Decrypt(key, cipher string) ([]byte, error) {
	keyBytes := []byte(key)
	cipherBytes := []byte(cipher)
	c, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Decrypt create cipher from key [ %s ] failed! error where is : %s", key, err.Error())
	}
	originData := PKCS7UnPadding(cipherBytes)
	result := make([]byte, len(originData))
	c.Decrypt(result, originData)
	return result, nil
}

//补码
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
