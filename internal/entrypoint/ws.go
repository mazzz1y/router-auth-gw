package entrypoint

import (
	"github.com/mazzz1y/router-auth-gw/internal/device"
	"golang.org/x/net/websocket"
	"io"
	"net/http"
	"strings"
)

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

func isWSRequest(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}
