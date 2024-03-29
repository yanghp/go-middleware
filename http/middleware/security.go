package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"

	"github.com/yanghp/go-middleware/internal/encrypt"
)

type rasSecurity struct {
	rasKey string
}

func NewRasSecurity(rasKey string) *rasSecurity {
	return &rasSecurity{
		rasKey: rasKey,
	}
}

func (rs *rasSecurity) Encipher(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1 解析header
		authKey := encrypt.GetAuthToken(r)
		if len(authKey) == 0 {
			unAuthorized(w, "")
			return
		}
		aesKey, err := encrypt.GetAesKeyFromAuth(authKey, rs.rasKey)
		if err != nil {
			unAuthorized(w, err.Error())
			return
		}
		if err = encrypt.DecryptRequest(r, aesKey); err != nil {
			unAuthorized(w, err.Error())
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)

		body, err := encrypt.EncryptResponseBody(rec.Body.Bytes(), aesKey)
		if err != nil {
			unAuthorized(w, err.Error())
			return
		}
		rec.Header().Set("Encrypt", aesKey.Version)
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

func unAuthorized(w http.ResponseWriter, msg string) {
	w.WriteHeader(401)
	w.Write([]byte("unAuthorized : " + msg))
}
