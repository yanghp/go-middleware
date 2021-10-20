package middleware

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRsaEncrypt(t *testing.T) {
	text := "yanghpyanghph121:yanghpyanghph121"
	crypt, err := rsaEncrypt([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	cryptStr := base64.StdEncoding.EncodeToString(crypt)
	t.Log(cryptStr)
	source, err := rsaDecrypt(crypt)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(source), text)
}

func TestAesEncrypt(t *testing.T) {
	text := `{
  "score_value":5,
  "user_id":12333,
  "app_name":"com.skin.test",
  "token":"12333",
  "score_type":"default",
  "package_name":"com.skin.test"
}`
	aesKey := AesKey{
		key:    []byte("yanghpyanghph121"),
		offset: []byte("yanghpyanghph121"),
	}
	crypt, err := aesEncrypt([]byte(text), aesKey.key, aesKey.offset)
	if err != nil {
		t.Fatal(err)
	}
	cryptStr := base64.StdEncoding.EncodeToString(crypt)
	t.Log(cryptStr)
	decodeBody, _ := base64.StdEncoding.DecodeString(cryptStr)
	source, err := aesDecrypt(decodeBody, aesKey.key, aesKey.offset)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, text, string(source))
}

func TestAesDecode(t *testing.T) {
	aesKey := AesKey{
		key:    []byte("yanghpyanghph121"),
		offset: []byte("yanghpyanghph121"),
	}
	cryptStr := "JyupEdOnysZV7BInALRK8Q=="
	decode, _ := base64.StdEncoding.DecodeString(cryptStr)
	body, err := aesDecrypt(decode, aesKey.key, aesKey.offset)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(body)
	assert.Equal(t, "Hello", string(body))

}
