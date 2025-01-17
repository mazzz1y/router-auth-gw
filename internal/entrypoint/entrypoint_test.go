package entrypoint

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mazzz1y/router-auth-gw/internal/device"
	"golang.org/x/net/websocket"

	"github.com/stretchr/testify/assert"
)

type MockClient struct{}

func (m *MockClient) Auth() error {
	return nil
}

func (m *MockClient) Request(_, _, _ string) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("mock response"))),
		Header:     make(http.Header),
	}, nil
}

func (m *MockClient) Websocket() (*websocket.Conn, error) {
	return nil, errors.New("not implemented")
}

func NewMockDevice() device.Device {
	mockClient := &MockClient{}

	device := device.Device{
		Users: []device.User{
			{Name: "user", Client: mockClient},
		},
	}

	return device
}

func TestServerForwardedAuth(t *testing.T) {
	options := EntrypointOptions{
		Device:              NewMockDevice(),
		ForwardAuthHeader:   "X-Forwarded-User",
		OnlyGet:             true,
		BypassAuthEndpoints: []string{"/auth-bypass"},
	}

	server := NewEntrypoint(options)

	t.Run("Authorized access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/behind-auth", nil)
		req.Header.Set("X-Forwarded-User", "user")

		w := httptest.NewRecorder()

		handler := server.authenticateMiddleware(server.handleRequest)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, string(body), "mock response")
	})

	t.Run("Bypassed access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth-bypass?t=1", nil)

		w := httptest.NewRecorder()

		handler := server.authenticateMiddleware(server.handleRequest)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, string(body), "mock response")
	})

	t.Run("Unauthorized access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/not-allowed", nil)

		w := httptest.NewRecorder()

		handler := server.authenticateMiddleware(server.handleRequest)
		handler.ServeHTTP(w, req)

		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestServerBasicAuth(t *testing.T) {
	options := EntrypointOptions{
		Device: NewMockDevice(),
		BasicAuth: map[string]string{
			"user": "pass",
		},
		AllowedEndpoints: []string{"/allowed"},
	}

	server := NewEntrypoint(options)

	t.Run("Authorized access using Basic Auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/allowed", nil)
		req.SetBasicAuth("user", "pass")

		w := httptest.NewRecorder()

		handler := server.authenticateMiddleware(server.handleRequest)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, string(body), "mock response")
	})

	t.Run("Unauthorized access with incorrect credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/allowed", nil)
		req.SetBasicAuth("user", "wrongpass")

		w := httptest.NewRecorder()

		handler := server.authenticateMiddleware(server.handleRequest)
		handler.ServeHTTP(w, req)

		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Unauthorized access without credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/allowed", nil)

		w := httptest.NewRecorder()

		handler := server.authenticateMiddleware(server.handleRequest)
		handler.ServeHTTP(w, req)

		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
