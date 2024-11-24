package entrypoint

import (
	"context"
	"fmt"
	"github.com/mazzz1y/keenetic-auth-gw/internal/device"
	"github.com/mazzz1y/keenetic-auth-gw/pkg/keenetic"
	"net/http"
	"strings"
)

func (e *Entrypoint) authenticateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := e.authenticate(r)
		if err != nil {
			e.log.Warn().
				Err(err).
				Str("from", r.RemoteAddr).
				Str("uri", r.URL.RequestURI()).
				Msg("authentication failed")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), clientContextKey, client)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (e *Entrypoint) isAllowedMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := e.isAllowed(r); err != nil {
			e.log.Info().
				Str("from", r.RemoteAddr).
				Str("uri", r.URL.RequestURI()).
				Msg("request not allowed")
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (e *Entrypoint) authenticate(r *http.Request) (keenetic.ClientWrapper, error) {
	if header := e.Options.ForwardAuthHeader; header != "" {
		user := r.Header.Get(header)
		if user == "" {
			return nil, fmt.Errorf("missing forward auth header: %s", header)
		}
		client, ok := getClientByName(e.Options.Device, user)
		if !ok {
			return nil, fmt.Errorf("user not found for forward auth header: %s", user)
		}
		return client, nil
	}

	if len(e.Options.BasicAuth) > 0 {
		user, pass, ok := r.BasicAuth()
		if !ok {
			return nil, fmt.Errorf("basic auth credentials not provided")
		}
		storedPass, exists := e.Options.BasicAuth[user]
		if !exists {
			return nil, fmt.Errorf("basic auth user not found: %s", user)
		}
		if storedPass != pass {
			return nil, fmt.Errorf("invalid password for user: %s", user)
		}
		client, ok := getClientByName(e.Options.Device, user)
		if !ok {
			return nil, fmt.Errorf("client not found for authenticated user: %s", user)
		}
		return client, nil
	}

	if len(e.Options.Device.Users) > 0 {
		return e.Options.Device.Users[0].Client, nil
	}

	return nil, fmt.Errorf("no valid authentication method found")
}

func (e *Entrypoint) isAllowed(r *http.Request) error {
	if e.Options.OnlyGet && r.Method != http.MethodGet {
		return fmt.Errorf("method not allowed")
	}

	if len(e.Options.AllowedEndpoints) == 0 {
		return nil
	}

	reqURI := r.URL.RequestURI()
	for _, endpoint := range e.Options.AllowedEndpoints {
		if strings.HasPrefix(reqURI, endpoint) {
			return nil
		}
	}

	return fmt.Errorf("forbidden")
}

func getClientByName(device device.Device, name string) (keenetic.ClientWrapper, bool) {
	for _, user := range device.Users {
		if user.Name == name {
			return user.Client, true
		}
	}
	return nil, false
}
