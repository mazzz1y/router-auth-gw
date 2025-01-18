package entrypoint

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/mazzz1y/router-auth-gw/internal/device"
	"golang.org/x/net/html"
)

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

	err = e.forwardResponse(resp, w)
	if err != nil {
		e.log.Error().Err(err).Str("uri", uri).Msg("failed to forward response")
	}

}

func (e *Entrypoint) forwardResponse(resp *http.Response, w http.ResponseWriter) error {
	for key, values := range resp.Header {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	bodyBytes, err := e.processBody(resp)
	if err != nil {
		return err
	}

	w.WriteHeader(resp.StatusCode)
	_, err = w.Write(bodyBytes)
	return err
}

func (e *Entrypoint) processBody(resp *http.Response) ([]byte, error) {
	if e.isAuthEnabled() && resp.Header.Get("Content-Type") == "text/html" {
		return manifestFix(resp.Body)
	}
	return io.ReadAll(resp.Body)
}

// Enable the HTTP crossorigin attribute to allow cookies and headers for manifest requests when the service is behind authentication.
// This prevents 401 errors, non-functional PWAs, and CSRF issues with forward authentication.
func manifestFix(r io.Reader) ([]byte, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	htmlNode := findHtmlElement(doc, "html")
	if htmlNode != nil {
		headNode := findHtmlElement(htmlNode, "head")
		if headNode != nil {
			if modifyManifestLink(headNode) {
				return renderHtml(doc)
			}
		}
	}

	return renderHtml(doc)
}

func findHtmlElement(n *html.Node, tagName string) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == tagName {
			return c
		}
	}
	return nil
}

func modifyManifestLink(n *html.Node) bool {
	for lc := n.FirstChild; lc != nil; lc = lc.NextSibling {
		if lc.Type == html.ElementNode && lc.Data == "link" {
			isManifest := false
			for i, attr := range lc.Attr {
				if attr.Key == "rel" && attr.Val == "manifest" {
					isManifest = true
				}
				if isManifest && attr.Key == "crossorigin" {
					lc.Attr[i].Val = "use-credentials"
					return true
				}
			}
			if isManifest {
				lc.Attr = append(lc.Attr, html.Attribute{Key: "crossorigin", Val: "use-credentials"})
				return true
			}
		}
	}
	return false
}

func renderHtml(node *html.Node) ([]byte, error) {
	var buffer bytes.Buffer
	if err := html.Render(&buffer, node); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
