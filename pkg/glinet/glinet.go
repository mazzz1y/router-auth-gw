package glinet

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/nathanaelle/password/v2"
	"golang.org/x/net/websocket"
)

type Client struct {
	URL       string
	RPCUrl    string
	WSUrl     string
	Username  string
	Password  string
	Client    *http.Client
	SessionID string
}

func NewClient(baseUrl, proxyURL, username, password string) *Client {
	jar, _ := cookiejar.New(nil)
	url := strings.TrimRight(baseUrl, "/")

	return &Client{
		URL:      url,
		RPCUrl:   url + "/rpc",
		WSUrl:    strings.Replace(url, "http", "ws", 1) + "/ws",
		Username: username,
		Password: password,
		Client: &http.Client{
			Timeout:   10 * time.Second,
			Jar:       jar,
			Transport: createTransport(proxyURL),
		},
	}
}

func (kc *Client) Auth() error {
	salt, nonce, err := kc.getSaltAndNonce()
	if err != nil {
		return err
	}

	authPayload := buildAuthPayload(kc.Username, kc.Password, salt, nonce)
	res, err := kc.request("POST", kc.RPCUrl, authPayload)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if isAccessDenied(res) {
		return errors.New("auth failed")
	}

	return kc.extractSid(res)
}

func (kc *Client) Request(method, path, body string) (*http.Response, error) {
	url := kc.URL + path
	res, err := kc.request(method, url, body)
	if err != nil {
		return nil, err
	}

	if isAccessDenied(res) {
		if err = kc.Auth(); err != nil {
			return nil, err
		}
		return kc.request(method, url, body)
	}

	cleanResponseHeaders(res)
	return res, nil
}

func (kc *Client) Websocket() (*websocket.Conn, error) {
	wsUrl := kc.WSUrl + fmt.Sprintf("?sid=%s", kc.SessionID)
	config, err := websocket.NewConfig(wsUrl, kc.URL)
	if err != nil {
		return nil, err
	}

	return websocket.DialConfig(config)
}

func (kc *Client) request(method, url, body string) (*http.Response, error) {
	if url == kc.RPCUrl {
		body = kc.replaceSid(body)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return nil, err
	}

	resp, err := kc.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	return resp, nil
}

func (kc *Client) getSaltAndNonce() (string, string, error) {
	payload := buildChallengePayload(kc.Username)
	response, err := kc.request("POST", kc.RPCUrl, payload)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()

	return parseSaltAndNonce(response)
}

func (kc *Client) extractSid(res *http.Response) error {
	var response map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return err
	}

	sid, ok := response["result"].(map[string]interface{})["sid"].(string)
	if !ok {
		return errors.New("failed to extract session id")
	}

	kc.SessionID = sid
	return nil
}

func (kc *Client) replaceSid(body string) string {
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(body), &payload); err == nil {
		if paramsArray, ok := payload["params"].([]interface{}); ok && len(paramsArray) > 0 {
			paramsArray[0] = kc.SessionID
			payload["params"] = paramsArray
		} else if paramsMap, ok := payload["params"].(map[string]interface{}); ok {
			if _, ok := paramsMap["sid"]; ok {
				paramsMap["sid"] = kc.SessionID
				payload["params"] = paramsMap
			}
		}

		if updatedBody, err := json.Marshal(payload); err == nil {
			return string(updatedBody)
		}
	}
	return body
}

func parseSaltAndNonce(response *http.Response) (string, string, error) {
	var result map[string]interface{}
	json.NewDecoder(response.Body).Decode(&result)
	res, ok := result["result"].(map[string]interface{})
	if !ok {
		return "", "", errors.New("failed to parse response")
	}

	salt, saltOk := res["salt"].(string)
	nonce, nonceOk := res["nonce"].(string)
	if !saltOk || !nonceOk {
		return "", "", errors.New("missing salt or nonce in response")
	}

	return salt, nonce, nil
}

func buildChallengePayload(user string) string {
	authPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "challenge",
		"params": map[string]string{
			"username": user,
		},
	}
	payloadBytes, _ := json.Marshal(authPayload)
	return string(payloadBytes)
}

func buildAuthPayload(user, pass, salt, nonce string) string {
	passwd := password.MD5.Crypt([]byte(pass), []byte(salt), nil)
	loginData := fmt.Sprintf("%s:%s:%s", user, passwd, nonce)
	hash := md5.Sum([]byte(loginData))
	loginHash := hex.EncodeToString(hash[:])

	authPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "login",
		"params": map[string]string{
			"username": user,
			"hash":     loginHash,
		},
	}
	payloadBytes, _ := json.Marshal(authPayload)
	return string(payloadBytes)
}

func isAccessDenied(res *http.Response) bool {
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false
	}
	defer res.Body.Close()

	res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var responseMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseMap); err != nil {
		return false
	}

	if errData, ok := responseMap["error"].(map[string]interface{}); ok {
		if message, ok := errData["message"].(string); ok && message == "Access denied" {
			return true
		}
	}

	return false
}

func createTransport(proxyURL string) *http.Transport {
	proxyFunc := http.ProxyFromEnvironment
	if proxyURL != "" {
		proxyFunc = func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}
	}

	return &http.Transport{Proxy: proxyFunc}
}

func cleanResponseHeaders(res *http.Response) {
	res.Header.Del("Set-Cookie")
	// This is required by the frontend. Otherwise, it will loop until the cookie is set.
	res.Header.Set("Set-Cookie", "Admin-Token=1337")
}
