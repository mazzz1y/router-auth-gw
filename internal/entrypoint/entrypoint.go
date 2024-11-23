package entrypoint

import (
	"context"
	"fmt"
	"github.com/mazzz1y/keenetic-auth-gw/internal/devices"
	"github.com/mazzz1y/keenetic-auth-gw/pkg/keenetic"
	"io"
	"log"
	"net/http"
	"strings"
)

type Entrypoint struct {
	Options EntrypointOptions
}

type EntrypointOptions struct {
	Device            devices.Device
	ListenAddr        string
	ForwardAuthHeader string
	BasicAuth         map[string]string
	AllowedEndpoints  []string
	OnlyGet           bool
}

func NewEntrypoint(options EntrypointOptions) *Entrypoint {
	return &Entrypoint{
		Options: options,
	}
}

func (s *Entrypoint) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.authenticateMiddleware(s.handleRequest))

	log.Printf("listening on %s\n", s.Options.ListenAddr)
	return http.ListenAndServe(s.Options.ListenAddr, mux)
}

func (s *Entrypoint) authenticateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := s.authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "client", client)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Entrypoint) authenticate(r *http.Request) (keenetic.ClientWrapper, error) {
	if s.Options.ForwardAuthHeader != "" {
		user := r.Header.Get(s.Options.ForwardAuthHeader)
		client, ok := getClientByName(s.Options.Device, user)
		if !ok {
			return nil, fmt.Errorf("Unauthorized")
		}
		return client, nil
	}

	if len(s.Options.BasicAuth) > 0 {
		user, pass, _ := r.BasicAuth()
		if storedPass, exists := s.Options.BasicAuth[user]; !exists || storedPass != pass {
			return nil, fmt.Errorf("Unauthorized")
		}
	}

	return s.Options.Device.Users[0].Client, nil
}

func (s *Entrypoint) handleRequest(w http.ResponseWriter, r *http.Request) {
	if !s.isAllowed(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	client, ok := r.Context().Value("client").(keenetic.ClientWrapper)
	if !ok {
		http.Error(w, "Internal Entrypoint Error", http.StatusInternalServerError)
		return
	}

	s.handleProxyRequest(w, r, client)
}

func (s *Entrypoint) isAllowed(r *http.Request) bool {
	if len(s.Options.AllowedEndpoints) == 0 {
		return r.Method == "GET" || !s.Options.OnlyGet
	}

	isGetMethod := r.Method == "GET"
	if s.Options.OnlyGet && !isGetMethod {
		return false
	}

	for _, endpoint := range s.Options.AllowedEndpoints {
		if strings.HasPrefix(r.URL.RequestURI(), endpoint) {
			return true
		}
	}

	return false
}

func (s *Entrypoint) handleProxyRequest(w http.ResponseWriter, r *http.Request, client keenetic.ClientWrapper) {
	proxyBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	res, err := client.RequestWithAuth(r.Method, r.URL.RequestURI(), string(proxyBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	s.writeResponse(w, res)
}

func (s *Entrypoint) writeResponse(w http.ResponseWriter, res *http.Response) {
	for key, values := range res.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	w.Write(body)
}

func getClientByName(device devices.Device, name string) (keenetic.ClientWrapper, bool) {
	for _, item := range device.Users {
		if item.Name == name {
			return item.Client, true
		}
	}
	return nil, false
}
