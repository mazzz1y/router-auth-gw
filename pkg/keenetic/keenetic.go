package keenetic

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type ClientWrapper interface {
	RequestWithAuth(method, endpoint, body string) (*http.Response, error)
	Auth() error
}

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
			Timeout:   10 * time.Second,
			Jar:       jar,
			Transport: createTransport(proxyURL),
		},
	}

	return c
}

func (kc *Client) Auth() error {
	challenge, realm, err := kc.getChallenge()
	if err != nil {
		return err
	}

	passwordHash := kc.generatePasswordHash(challenge, realm)
	authPayload := map[string]string{"login": kc.Username, "password": passwordHash}

	payloadBytes, _ := json.Marshal(authPayload)

	res, err := kc.request("POST", kc.URL+"/auth", string(payloadBytes))
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.New("auth failed")
	}

	return nil
}

func (kc *Client) RequestWithAuth(method, endpoint, body string) (*http.Response, error) {
	endpoint = strings.TrimLeft(endpoint, "/")
	urlParsed, err := url.Parse(kc.URL + "/" + endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	res, err := kc.request(method, urlParsed.String(), body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusUnauthorized {
		if err := kc.Auth(); err != nil {
			return nil, err

		}
		return kc.request(method, urlParsed.String(), body)
	}

	res.Header.Del("Set-Cookie")

	return res, nil
}

func (kc *Client) getChallenge() (string, string, error) {
	resp, err := kc.request("GET", kc.URL+"/auth", "")
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

func (kc *Client) request(method, url, body string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
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

func (kc *Client) generatePasswordHash(challenge, realm string) string {
	md5Hash := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", kc.Username, realm, kc.Password)))
	md5Hex := hex.EncodeToString(md5Hash[:])

	shaHash := sha256.Sum256([]byte(challenge + md5Hex))
	return hex.EncodeToString(shaHash[:])
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
