package keenetic_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mazzz1y/router-auth-gw/pkg/keenetic"
	"github.com/stretchr/testify/assert"
)

const (
	hashedPassword = "f44ed6746113894e4a8dbe6282315ae6354549dd385d2af5ca825004a3f8142e" // password
	mockUser       = "username"
	mockPass       = "password"
	cookieName     = "mock-cookie"
	cookieValue    = "cookie"
)

func mockServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			handleAuthRequest(w, r)
		case "/test-endpoint":
			handleTestEndpoint(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(handler)
}

func handleAuthRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("X-NDM-Realm", "mock-realm")
		w.Header().Set("X-NDM-Challenge", "mock-challenge")
		w.WriteHeader(http.StatusUnauthorized)
	case http.MethodPost:
		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload["login"] == mockUser && payload["password"] == hashedPassword {
			w.Header().Set("Set-Cookie", cookieName+"="+cookieValue)
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleTestEndpoint(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie(cookieName)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}
}

func TestAuth(t *testing.T) {
	server := mockServer()
	defer server.Close()

	t.Run("Success", func(t *testing.T) {
		c := keenetic.NewClient(server.URL, "", mockUser, mockPass)
		assert.NotNil(t, c)
		assert.NoError(t, c.Auth())
	})

	t.Run("Failed", func(t *testing.T) {
		c := keenetic.NewClient(server.URL, "", mockUser, "wrong password")
		assert.Error(t, c.Auth())
	})
}

func TestRequestWithAuth(t *testing.T) {
	server := mockServer()
	defer server.Close()

	c := keenetic.NewClient(server.URL, "", mockUser, mockPass)
	assert.NotNil(t, c)

	response, err := c.RequestWithAuth(http.MethodGet, "/test-endpoint", "")
	assert.NoError(t, err)
	defer response.Body.Close()

	assert.Equal(t, http.StatusOK, response.StatusCode)
}
