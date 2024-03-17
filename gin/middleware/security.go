package middleware

import (
	"bytes"

	"github.com/gin-gonic/gin"
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

func (rs *rasSecurity) Encipher() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1 解析header
		authKey := encrypt.GetAuthToken(c.Request)
		if len(authKey) == 0 {
			c.AbortWithStatus(401)
			return
		}

		aesKey, err := encrypt.GetAesKeyFromAuth(authKey, rs.rasKey)
		if err != nil {
			c.AbortWithError(401, err)
			return
		}

		if err = encrypt.DecryptRequest(c.Request, aesKey); err != nil {
			c.AbortWithError(401, err)
			return
		}
		resp := newGinRespWriter(c.Writer)
		c.Writer = resp
		c.Next()

		body, err := encrypt.EncryptResponseBody(resp.body.Bytes(), aesKey)
		if err != nil {
			c.AbortWithError(401, err)
			return
		}
		c.Writer.Header().Set("Encrypt", aesKey.Version)
		resp.writeEncrypt(body)
	}
}

type ginRespWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func newGinRespWriter(w gin.ResponseWriter) *ginRespWriter {
	return &ginRespWriter{
		ResponseWriter: w,
		body:           bytes.NewBufferString(""),
	}
}

func (gw *ginRespWriter) Write(b []byte) (int, error) {
	return gw.body.Write(b)
}

func (gw *ginRespWriter) WriteString(s string) (int, error) {
	return gw.body.WriteString(s)
}

func (gw *ginRespWriter) writeEncrypt(body string) {
	gw.ResponseWriter.WriteString(body)
}
