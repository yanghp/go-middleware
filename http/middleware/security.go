package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"

	"glab.tagtic.cn/ad_gains/go-middleware/internal/encrypt"
)

// MustSecurity 强制必须加密
func MustSecurity(next http.Handler) http.Handler {
	return security(next, true)
}

// Security 只有请求头存在时加密
func Security(next http.Handler) http.Handler {
	return security(next, false)
}

func security(next http.Handler, must bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1 解析header
		authKey := encrypt.GetAuthToken(r)
		if len(authKey) == 0 {
			if must {
				unAuthorized(w, "")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		aesKey, err := encrypt.GetAesKeyFromAuth(authKey)
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
