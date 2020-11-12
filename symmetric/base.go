package symmetric

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
)

const (
	FORMAT_BASE64 = "base64"
	FORMAT_HEX    = "hex"
)

type Encrypt interface {
	// 加密
	Encrypt(key, raw string) ([]byte, error)
	// 解密
	Decrypt(key string, cipher []byte) ([]byte, error)
}

type Encrypter struct {
	Format     string
	DecodeFunc func(raw string) ([]byte, error)
	EncodeFunc func(raw []byte) string
}

func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func hexDecode(raw string) ([]byte, error) {
	return hex.DecodeString(raw)
}

func base64Decode(raw string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(raw)
}

func hexEncode(raw []byte) string {
	return hex.EncodeToString(raw)
}

func base64Encode(raw []byte) string {
	return hex.EncodeToString(raw)
}
