package middleware

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
	"net/http/httptest"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func Security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//1 解析header
		authKey := r.Header.Get("X-AuthToken")
		if len(authKey) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		//2 解析key
		split := strings.Split(authKey, ":")
		if len(split) != 2 {
			unAuthorized(w, fmt.Sprintf("X-AuthToken :[%s] illegal", authKey))
			return
		}

		//3 根据版本获取解密算法函数
		fn, ok := signAlgorithm[split[0]]
		if !ok {
			unAuthorized(w, fmt.Sprintf("not find [%s] version security", split[0]))
			return
		}
		//4 获取aeskey进行解密
		aesKey, err := fn(split[1])
		if err != nil {
			unAuthorized(w, err.Error())
			return
		}

		if err := decryptRequest(r, aesKey); err != nil {
			unAuthorized(w, err.Error())
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)

		body, err := encryptResponse(rec, aesKey)
		if err != nil {
			unAuthorized(w, err.Error())
			return
		}
		writeEncrypt(w, rec, body)
	})
}

func writeEncrypt(w http.ResponseWriter, rec *httptest.ResponseRecorder, body string) {
	// write header
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	// write length
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	// write body
	w.Write([]byte(body))
}

func encryptResponse(resp *httptest.ResponseRecorder, aesKey *AesKey) (string, error) {

	if resp.Body == nil {
		return "", nil
	}
	body := resp.Body.Bytes()

	cryptBody, err := aesEncrypt(body, aesKey.key, aesKey.offset)
	if err != nil {
		return "", err
	}
	// 加密之后再进行base64
	cryptStr := base64.StdEncoding.EncodeToString(cryptBody)

	return cryptStr, nil
}

func unAuthorized(w http.ResponseWriter, msg string) {
	w.WriteHeader(401)
	w.Write([]byte("unAuthorized : " + msg))
}

func decryptRequest(req *http.Request, aesKey *AesKey) error {
	if req.Body == nil {
		return nil
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	defer req.Body.Close()

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

type AesKey struct {
	key    []byte // AES秘钥key
	offset []byte // AES秘钥向量
}

var signAlgorithm map[string]func(key string) (*AesKey, error)

func init() {
	signAlgorithm = make(map[string]func(key string) (*AesKey, error))
	signAlgorithm[version101] = algorithm101
}

const (
	version101 = "101"
	// 版本升级可以往下加
)

// algorithm101 解密
func algorithm101(key string) (*AesKey, error) {
	// base64 decode
	body, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	rest, err := rsaDecrypt(body)
	if err != nil {
		return nil, err
	}

	split := strings.Split(string(rest), ":")
	if len(split) != 2 {
		return nil, errors.Errorf("signature is illegal, header secret:[%s]", string(rest))
	}

	return &AesKey{
		key:    []byte(split[0]),
		offset: []byte(split[1]),
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
	plainText = pKCS5Padding(plainText, blockSize)

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
	decrypted = pkcs5UnPadding(decrypted)

	return decrypted, nil
}

func pkcs5UnPadding(decrypted []byte) []byte {
	length := len(decrypted)
	unPadding := int(decrypted[length-1])
	return decrypted[:(length - unPadding)]
}

func rsaEncrypt(plainText []byte) (cryptText []byte, err error) {
	block, _ := pem.Decode(publicKey)

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func rsaDecrypt(cryptText []byte) (plainText []byte, err error) {
	block, _ := pem.Decode(privateKey)

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

var privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCSJo53ytY5fEXLerYz7vHqUc47uL/wIdye4gFpq9o9BxCFFP31
0v3D/vMAA0xo/ZZYsDHI9/vtCZlwjbazGVZk+hXl32bG0e4+ZWzirgfpsEYefy2P
ZQsPdCgWKFK6crkY9nPB0NuC3BJ4X7+m3wMcfWryscM0B0YM8aC2KgUEVwIDAQAB
AoGBAIBaRDyIcuNBdLpjJqktbF/xQEHK2yY1VuBidAMt3hhCoAuAiBjgF+WNfjPA
sdZy/xscglyRDTr7dzoV+yIHWoswY1vYl0JKLwstl2zEfOkvDsqfubIq7V1bfUBp
eM+qoI2pDZVATpI0IBXw86SdzNipnXOmZVSdgRo1GA6pusIhAkEA728kiBiT8kQE
zpLZmAw99gk2wBSmt+qLoQEbLbFirDOD4+Zd566yeVX9jZ6KaTEXslGONz8S2aPd
HuimCpZcSwJBAJxDLQhMSECjx0biviYl4d3kVRS+V6fzqWDrijSJJDyDX/nTXwue
tAOmJHT3eO7wAQdHKf/AVwm0g2Eg+tGNmKUCQQDfNoUfH5KlU4YLstmKJzeIbHSP
Q3FdmhoLwkU9JtavZOM7DmNS/wlBlsnnQfsVMABAbEmh9Xo0TdBx5UAONLjbAkBn
OGyXzaPwpv8s0PygQGfZ5klZYX6PoAHj1tM9btXz7yhH45smFth8jJQKe6pz0zAq
uZSBr3EPJSGf2GQ2Zl1NAkA4J8g6rKLsYA/nH9jqaz0FoJLmwy0HkKZLm80GA8ez
Ill1gTIfSdE1TV8sLd64HjLDnYr070yNy8/8PP6Mk/le
-----END RSA PRIVATE KEY-----`)

var publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSJo53ytY5fEXLerYz7vHqUc47
uL/wIdye4gFpq9o9BxCFFP310v3D/vMAA0xo/ZZYsDHI9/vtCZlwjbazGVZk+hXl
32bG0e4+ZWzirgfpsEYefy2PZQsPdCgWKFK6crkY9nPB0NuC3BJ4X7+m3wMcfWry
scM0B0YM8aC2KgUEVwIDAQAB
-----END PUBLIC KEY-----`)
