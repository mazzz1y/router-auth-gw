package entrypoint

import (
	"io"
	"net/http"
	"strings"

	"github.com/mazzz1y/router-auth-gw/internal/device"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/websocket"
)

type contextKey string

const clientContextKey = contextKey("client")

type Entrypoint struct {
	log     zerolog.Logger
	Options EntrypointOptions
}

type EntrypointOptions struct {
	Device              device.Device
	ListenAddr          string
	ForwardAuthHeader   string
	ForwardAuthMapping  map[string]string
	BasicAuth           map[string]string
	BypassAuthEndpoints []string
	AllowedEndpoints    []string
	OnlyGet             bool
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
	handler := e.authenticateMiddleware(
		e.reqAllowedMiddleware(e.handleRequest),
	)
	mux.HandleFunc("/", handler)
	e.log.Info().Msg("listener started")
	return http.ListenAndServe(e.Options.ListenAddr, mux)
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

func (e *Entrypoint) wsRequest(w http.ResponseWriter, r *http.Request, c device.ClientWrapper) {
	conn, err := c.Websocket()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		e.log.Error().Err(err).Msg("failed to establish websocket connection")
		return
	}
	defer conn.Close()

	websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		go io.Copy(ws, conn)
		io.Copy(conn, ws)
	}).ServeHTTP(w, r)
}

func (e *Entrypoint) httpRequest(w http.ResponseWriter, r *http.Request, c device.ClientWrapper) {
	uri := r.URL.RequestURI()
	proxyBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		e.log.Error().Err(err).Str("uri", uri).Msg("failed to read request body")
		return
	}
	defer r.Body.Close()

	resp, err := c.Request(r.Method, uri, string(proxyBody))
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

func isWSRequest(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}
