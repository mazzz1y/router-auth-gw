package entrypoint

import (
	"io"
	"net/http"
	"strings"

	"github.com/mazzz1y/router-auth-gw/internal/device"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type contextKey string

const clientContextKey = contextKey("client")

type Entrypoint struct {
	log     zerolog.Logger
	Options EntrypointOptions
}

type EntrypointOptions struct {
	Device             device.Device
	ListenAddr         string
	ForwardAuthHeader  string
	ForwardAuthMapping map[string]string
	BasicAuth          map[string]string
	AllowedEndpoints   []string
	OnlyGet            bool
}

func NewEntrypoint(options EntrypointOptions) *Entrypoint {
	return &Entrypoint{
		log: log.With().
			Str("entrypoint", options.ListenAddr).
			Str("device", options.Device.Tag).
			Logger(),
		Options: options,
	}
}

func (e *Entrypoint) Start() error {
	mux := http.NewServeMux()
	handler := e.authenticateMiddleware(e.isAllowedMiddleware(e.handleRequest))
	mux.HandleFunc("/", handler)
	e.log.Info().Msg("listener started")
	return http.ListenAndServe(e.Options.ListenAddr, mux)
}

func (e *Entrypoint) handleRequest(w http.ResponseWriter, r *http.Request) {
	client, ok := r.Context().Value(clientContextKey).(device.ClientWrapper)
	if !ok {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		e.log.Error().Msg("getting user context error")
		return
	}

	e.log.Debug().
		Str("from", r.RemoteAddr).
		Str("uri", r.URL.RequestURI()).
		Msg("forwarding request")

	e.handleProxyRequest(w, r, client)
}

func (e *Entrypoint) handleProxyRequest(w http.ResponseWriter, r *http.Request, c device.ClientWrapper) {
	uri := r.URL.RequestURI()
	proxyBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		e.log.Error().Err(err).Str("uri", uri).Msg("failed to read request body")
		return
	}
	defer r.Body.Close()

	resp, err := c.RequestWithAuth(r.Method, uri, string(proxyBody))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		e.log.Error().Err(err).Str("uri", uri).Msg("request to backend failed")
		return
	}
	defer resp.Body.Close()

	e.forwardHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		e.log.Error().Err(err).Str("uri", uri).Msg("failed to write response body")
		return
	}
}

func (e *Entrypoint) forwardHeaders(w http.ResponseWriter, resp *http.Response) {
	for key, values := range resp.Header {
		if strings.EqualFold(key, "Host") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
}
