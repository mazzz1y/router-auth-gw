package glinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	mockUser    = "root"
	mockPass    = "password"
	mockSession = "mock-session-id"
	mockSalt    = "mock-salt"
	mockNonce   = "mock-nonce"
	cookieName  = "mock-cookie"
	cookieValue = "mock-value"
	mockHash    = "f72036043192bb628b88c8cb7783bfe3"
)

func mockServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc":
			handleRPCRequest(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(handler)
}

func handleRPCRequest(w http.ResponseWriter, r *http.Request) {
	var requestBody map[string]interface{}
	json.NewDecoder(r.Body).Decode(&requestBody)

	switch requestBody["method"] {
	case "challenge":
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]string{"salt": mockSalt, "nonce": mockNonce},
		})
	case "login":
		params := requestBody["params"].(map[string]interface{})
		if params["username"] == mockUser && params["hash"] == mockHash {
			w.Header().Set("Set-Cookie", cookieName+"="+cookieValue)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"sid": mockSession},
			})
		} else {
			errorRes(w)
		}
	case "someMethod":
		if _, err := r.Cookie(cookieName); err != nil {
			errorRes(w)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true}`))
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func errorRes(w http.ResponseWriter) {
	http.Error(w, `{"id":1,"jsonrpc":"2.0","error":{"message":"Access denied"}}`, http.StatusOK)
}

func TestAuth(t *testing.T) {
	server := mockServer()
	defer server.Close()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		c := NewClient(server.URL, "", mockUser, mockPass)
		assert.NotNil(t, c)
		assert.NoError(t, c.auth(ctx))
		assert.Equal(t, mockSession, c.SessionID)
	})

	t.Run("Failed", func(t *testing.T) {
		c := NewClient(server.URL, "", mockUser, "wrong password")
		err := c.auth(ctx)
		assert.Error(t, err)
		assert.Equal(t, "", c.SessionID)
	})
}

func TestRequest(t *testing.T) {
	server := mockServer()
	defer server.Close()

	c := NewClient(server.URL, "", mockUser, mockPass)
	assert.NotNil(t, c)

	ctx := context.Background()
	response, err := c.Request(ctx, http.MethodPost, "/rpc", `{"method":"someMethod","params":{}}`)
	assert.NoError(t, err)
	defer response.Body.Close()

	assert.Equal(t, http.StatusOK, response.StatusCode)
}
