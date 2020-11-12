package symmetric

type Encrypt interface {
	// 加密
	Encrypt (key, raw string) ([]byte, error)
	// 解密
	Decrypt (key, cipher string) ([]byte, error)
}

type Encrypter struct {
	Key string
	Raw string
	Cipher string
}
