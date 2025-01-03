package entrypoint

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/mazzz1y/router-auth-gw/internal/device"
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
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
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
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (e *Entrypoint) authenticate(r *http.Request) (device.ClientWrapper, error) {
	if header := e.Options.ForwardAuthHeader; header != "" {
		user := r.Header.Get(header)
		if user == "" {
			return nil, fmt.Errorf("missing forward auth header: %s", header)
		}
		client, ok := e.getClientByName(user)
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

func (e *Entrypoint) getClientByName(name string) (device.ClientWrapper, bool) {
	if len(e.Options.ForwardAuthMapping) > 0 {
		name = e.Options.ForwardAuthMapping[name]
	}

	for _, user := range e.Options.Device.Users {
		if user.Name == name {
			return user.Client, true
		}
	}
	return nil, false
}
