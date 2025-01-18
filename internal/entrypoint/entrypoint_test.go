package entrypoint

import (
	"bytes"
	"errors"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	options := Options{
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
	options := Options{
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

func TestUpdateManifestLinks(t *testing.T) {
	tests := []struct {
		name           string
		htmlInput      string
		expectedOutput string
	}{
		{
			name: "Manifest exists and requires crossorigin",
			htmlInput: `
			<!DOCTYPE html>
			<html>
			<head>
				<link rel="stylesheet" href="style.css">
				<link rel="manifest" href="manifest.json">
			</head>
			<body>
			</body>
			</html>
			`,
			expectedOutput: `
			<!DOCTYPE html>
			<html>
			<head>
				<link rel="stylesheet" href="style.css">
				<link rel="manifest" href="manifest.json" crossorigin="use-credentials">
			</head>
			<body>
			</body>
			</html>
			`,
		},
		{
			name: "Manifest link does not exist",
			htmlInput: `
			<!DOCTYPE html>
			<html>
			<head>
				<link rel="stylesheet" href="style.css">
			</head>
			<body>
			</body>
			</html>
			`,
			expectedOutput: `
			<!DOCTYPE html>
			<html>
			<head>
				<link rel="stylesheet" href="style.css">
			</head>
			<body>
			</body>
			</html>
			`,
		},
		{
			name: "Manifest already has crossorigin",
			htmlInput: `
			<!DOCTYPE html>
			<html>
			<head>
				<link rel="stylesheet" href="style.css">
				<link rel="manifest" href="manifest.json" crossorigin="use-credentials">
			</head>
			<body>
			</body>
			</html>
			`,
			expectedOutput: `
			<!DOCTYPE html>
			<html>
			<head>
				<link rel="stylesheet" href="style.css">
				<link rel="manifest" href="manifest.json" crossorigin="use-credentials">
			</head>
			<body>
			</body>
			</html>
			`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := io.NopCloser(strings.NewReader(test.htmlInput))
			output, err := manifestFix(reader)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			parsedOutput, err := html.Parse(strings.NewReader(string(output)))
			if err != nil {
				t.Fatalf("Error parsing output HTML: %v", err)
			}

			parsedExpectedOutput, err := html.Parse(strings.NewReader(test.expectedOutput))
			if err != nil {
				t.Fatalf("Error parsing expected HTML: %v", err)
			}

			var outputBuf, expectedBuf bytes.Buffer
			html.Render(&outputBuf, parsedOutput)
			html.Render(&expectedBuf, parsedExpectedOutput)

			if outputBuf.String() != expectedBuf.String() {
				t.Errorf("Expected output:\n%s\n\nBut got:\n%s", expectedBuf.String(), outputBuf.String())
			}
		})
	}
}
