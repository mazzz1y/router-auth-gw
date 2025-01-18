package entrypoint

import (
	"github.com/mazzz1y/router-auth-gw/internal/device"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net/http"
)

type contextKey string

const clientContextKey = contextKey("client")

type Entrypoint struct {
	log     zerolog.Logger
	Options Options
}

type Options struct {
	Device              device.Device
	ListenAddr          string
	ForwardAuthHeader   string
	ForwardAuthMapping  map[string]string
	BasicAuth           map[string]string
	BypassAuthEndpoints []string
	AllowedEndpoints    []string
	OnlyGet             bool
}

func NewEntrypoint(options Options) *Entrypoint {
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
	handler := e.authenticateMiddleware(
		e.reqAllowedMiddleware(e.handleRequest),
	)
	mux.HandleFunc("/", handler)
	e.log.Info().Msg("listener started")
	return http.ListenAndServe(e.Options.ListenAddr, mux)
}

func (e *Entrypoint) isAuthEnabled() bool {
	return len(e.Options.BasicAuth) > 0 || e.Options.ForwardAuthHeader != ""
}

func (e *Entrypoint) handleRequest(w http.ResponseWriter, r *http.Request) {
	c, ok := r.Context().Value(clientContextKey).(device.ClientWrapper)
	if !ok {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		e.log.Error().Msg("getting user context error")
		return
	}

	e.log.Debug().
		Str("from", r.RemoteAddr).
		Str("uri", r.URL.RequestURI()).
		Msg("forwarding request")

	if isWSRequest(r) {
		e.wsRequest(w, r, c)
	} else {
		e.httpRequest(w, r, c)
	}
}
