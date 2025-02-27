package entrypoint

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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

func (e *Entrypoint) reqAllowedMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		if e.Options.OnlyGet && r.Method != http.MethodGet {
			err = fmt.Errorf("method not allowed")
		}

		uri := r.URL.RequestURI()
		if len(e.Options.AllowedEndpoints) > 0 && !isURIInSlice(e.Options.AllowedEndpoints, uri) {
			err = fmt.Errorf("uri not allowed")
		}

		if err != nil {
			e.log.Info().
				Str("from", r.RemoteAddr).
				Str("uri", uri).
				Msg("request not allowed")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (e *Entrypoint) authenticate(r *http.Request) (device.ClientWrapper, error) {
	uri := r.URL.RequestURI()

	bypass := (len(e.Options.BypassAuthEndpoints) > 0 && isURIInSlice(e.Options.BypassAuthEndpoints, uri)) ||
		isURIBypassed(uri)

	if bypass {
		return e.Options.Device.Users[0].Client, nil
	}

	if e.Options.ForwardAuthHeader != "" {
		return e.forwardAuth(r)
	}

	if len(e.Options.BasicAuth) > 0 {
		if err := e.basicAuth(r); err != nil {
			return nil, err
		}
	}

	if len(e.Options.Device.Users) > 0 {
		return e.Options.Device.Users[0].Client, nil
	}

	return nil, fmt.Errorf("no valid authentication method found")
}

func (e *Entrypoint) forwardAuth(r *http.Request) (device.ClientWrapper, error) {
	user := r.Header.Get(e.Options.ForwardAuthHeader)
	if user == "" {
		return nil, fmt.Errorf("missing forward auth header: %s", e.Options.ForwardAuthHeader)
	}

	client, ok := e.client(user)
	if !ok {
		return nil, fmt.Errorf("user not found for forward auth header: %s", user)
	}

	return client, nil
}

func (e *Entrypoint) basicAuth(r *http.Request) error {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return fmt.Errorf("basic auth credentials not provided")
	}

	storedPass, exists := e.Options.BasicAuth[user]
	if !exists {
		return fmt.Errorf("basic auth user not found: %s", user)
	}

	if storedPass != pass {
		return fmt.Errorf("invalid password for user: %s", user)
	}

	return nil
}

func (e *Entrypoint) client(name string) (device.ClientWrapper, bool) {
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

func isURIBypassed(uri string) bool {
	return strings.HasSuffix(uri, "/favicon.ico")
}

func isURIInSlice(endpoints []string, uri string) bool {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return false
	}

	for _, endpoint := range endpoints {
		if parsedURL.Path == endpoint {
			return true
		}
	}

	return false
}
