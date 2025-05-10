package keenetic

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/websocket"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

type Client struct {
	URL      string
	Username string
	Password string
	Client   *http.Client
}

func NewClient(baseUrl, proxyURL, username, password string) *Client {
	jar, _ := cookiejar.New(nil)

	c := &Client{
		URL:      strings.TrimRight(baseUrl, "/"),
		Username: username,
		Password: password,
		Client: &http.Client{
			Jar:       jar,
			Transport: createTransport(proxyURL),
		},
	}

	return c
}

func (kc *Client) Request(ctx context.Context, method, endpoint, body string) (*http.Response, error) {
	endpoint = strings.TrimLeft(endpoint, "/")
	urlParsed, err := url.Parse(kc.URL + "/" + endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	res, err := kc.request(ctx, method, urlParsed.String(), body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusUnauthorized {
		if err := kc.auth(ctx); err != nil {
			return nil, err

		}
		return kc.request(ctx, method, urlParsed.String(), body)
	}

	res.Header.Del("Set-Cookie")
	return res, nil
}

func (kc *Client) Websocket() (*websocket.Conn, error) {
	return nil, errors.New("websocket not supported")
}

func (kc *Client) auth(ctx context.Context) error {
	challenge, realm, err := kc.getChallenge(ctx)
	if err != nil {
		return err
	}

	payload := buildAuthPayload(kc.Username, kc.Password, challenge, realm)
	res, err := kc.request(ctx, "POST", kc.URL+"/auth", payload)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.New("auth failed")
	}

	return nil
}

func (kc *Client) getChallenge(ctx context.Context) (string, string, error) {
	resp, err := kc.request(ctx, "GET", kc.URL+"/auth", "")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", "", fmt.Errorf("unexpected status code when getting challenge: %d", resp.StatusCode)
	}

	challenge := resp.Header.Get("X-NDM-Challenge")
	realm := resp.Header.Get("X-NDM-Realm")
	if challenge == "" || realm == "" {
		return "", "", fmt.Errorf("missing challenge or realm headers")
	}

	return challenge, realm, nil
}

func (kc *Client) request(ctx context.Context, method, url, body string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := kc.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	return resp, nil
}

func buildAuthPayload(user, pass, challenge, realm string) string {
	md5Hash := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", user, realm, pass)))
	md5Hex := hex.EncodeToString(md5Hash[:])
	shaHash := sha256.Sum256([]byte(challenge + md5Hex))
	passwordHash := hex.EncodeToString(shaHash[:])

	authPayload := map[string]string{"login": user, "password": passwordHash}
	payload, _ := json.Marshal(authPayload)
	return string(payload)
}

func createTransport(proxyURL string) *http.Transport {
	proxyFunc := http.ProxyFromEnvironment
	if proxyURL != "" {
		proxyFunc = func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}
	}

	return &http.Transport{
		Proxy: proxyFunc,
	}
}
