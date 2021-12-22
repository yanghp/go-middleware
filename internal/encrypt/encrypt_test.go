package encrypt

import (
	"bytes"
	"net/http"
	"testing"
)

func TestDecryptRequest(t *testing.T) {
	reader := bytes.NewReader(nil)
	req, err := http.NewRequest(http.MethodPost, "http://localhost", reader)
	if err != nil {
		t.Fatal(err)
	}
	err = DecryptRequest(req, &aesKey{
		key:    []byte("1122334455667788"),
		offset: []byte("1122334455667788"),
	})

	if err != nil {
		t.Fatal(err)
	}
}
