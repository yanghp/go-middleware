package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type aesKey struct {
	Version string
	key     []byte // AES秘钥key
	offset  []byte // AES秘钥向量
}

var signAlgorithm map[string]func(key, rasKey string) (*aesKey, error)

func init() {
	signAlgorithm = make(map[string]func(key, rasKey string) (*aesKey, error))
	signAlgorithm[version101] = algorithm101
}

const (
	version101 = "v1"
	// 版本升级可以往下加
)

// algorithm101 解密
func algorithm101(key, rasKey string) (*aesKey, error) {
	// base64 decode
	body, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	rest, err := rsaDecrypt(body, []byte(rasKey))
	if err != nil {
		return nil, err
	}

	split := strings.Split(string(rest), ":")
	if len(split) != 2 {
		return nil, errors.Errorf("signature is illegal, header secret:[%s]", string(rest))
	}

	return &aesKey{
		key:     []byte(split[0]),
		offset:  []byte(split[1]),
		Version: version101,
	}, nil
}

func aesEncrypt(plainText, key, ivAes []byte) (cryptText []byte, err error) {
	lenKey := len(key)
	if lenKey != 16 && lenKey != 24 && lenKey != 32 {
		return nil, errors.Errorf("aesEncrypt: key length error ,len:[ %d ] ", lenKey)
	}

	if len(ivAes) != 16 {
		return nil, errors.Errorf("iv aes len is :[%d], must len 16", len(ivAes))
	}
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("AES Encrypt error: %v", err)
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plainText = pKCS7Padding(plainText, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, ivAes)
	encrypted := make([]byte, len(plainText))
	blockMode.CryptBlocks(encrypted, plainText)
	return encrypted, nil
}

func pKCS5Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}

func pKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func aesDecrypt(crypted, key, ivAes []byte) ([]byte, error) {
	lenKey := len(key)
	if lenKey != 16 && lenKey != 24 && lenKey != 32 {
		return nil, errors.Errorf("aesEncrypt: key length error ,len:[ %d ] ", lenKey)
	}
	if len(ivAes) != 16 {
		return nil, errors.Errorf("iv aes len is :[%d], must len 16", len(ivAes))
	}
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("AES Decrypt error: %v", err)
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, ivAes)
	decrypted := make([]byte, len(crypted))

	blockMode.CryptBlocks(decrypted, crypted)
	return pkcs7UnPadding(decrypted)
}

func pkcs5UnPadding(decrypted []byte) []byte {
	length := len(decrypted)
	if length == 0 {
		return nil
	}
	unPadding := int(decrypted[length-1])
	return decrypted[:(length - unPadding)]
}

func pkcs7UnPadding(plantText []byte) ([]byte, error) {
	length := len(plantText)
	if length == 0 {
		return nil, errors.New("pkcs7UnPadding: plantText is nil")
	}
	unPadding := int(plantText[length-1])
	effectiveCount := length - unPadding
	if effectiveCount <= 0 {
		return nil, errors.New("The key does not support the ciphertext")
	}
	return plantText[:effectiveCount], nil
}

func rsaDecrypt(cryptText []byte, rasKey []byte) (plainText []byte, err error) {
	block, _ := pem.Decode(rasKey)

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, err
	}
	plainText, err = rsa.DecryptPKCS1v15(rand.Reader, rsaKey, cryptText)
	if err != nil {
		return []byte{}, err
	}
	return plainText, nil
}

func GetAesKeyFromAuth(auth, aesKey string) (*aesKey, error) {
	// 2 解析key
	split := strings.Split(auth, ":")
	if len(split) != 2 {
		return nil, errors.Errorf(fmt.Sprintf("X-AuthToken :[%s] illegal", auth))
	}

	// 3 根据版本获取解密算法函数
	fn, ok := signAlgorithm[split[0]]
	if !ok {
		return nil, errors.Errorf("not find [%s] version encrypt", split[0])
	}
	// 4 获取aeskey进行解密
	return fn(split[1], aesKey)
}

func DecryptRequest(req *http.Request, aesKey *aesKey) error {
	if req.Body == nil {
		return nil
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	if len(body) == 0 {
		return nil
	}
	decodeBody, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return err
	}
	decryptBody, err := aesDecrypt(decodeBody, aesKey.key, aesKey.offset)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(decryptBody))
	return nil
}

func EncryptResponseBody(body []byte, aesKey *aesKey) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	cryptBody, err := aesEncrypt(body, aesKey.key, aesKey.offset)
	if err != nil {
		return "", err
	}
	// 加密之后再进行base64
	cryptStr := base64.StdEncoding.EncodeToString(cryptBody)
	return cryptStr, nil
}

func GetAuthToken(r *http.Request) string {
	return r.Header.Get("X-AuthToken")
}
