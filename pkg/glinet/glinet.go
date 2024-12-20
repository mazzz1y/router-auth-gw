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
)

type Client struct {
	URL       string
	Username  string
	Password  string
	Client    *http.Client
	SessionID string
}

func NewClient(baseUrl, proxyURL, username, password string) *Client {
	jar, _ := cookiejar.New(nil)

	return &Client{
		URL:      strings.TrimRight(baseUrl, "/"),
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

	loginHash := kc.generateLoginHash(salt, nonce)
	authPayload := kc.buildAuthPayload(loginHash)

	res, err := kc.request("POST", kc.URL+"/rpc", authPayload)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if isAccessDenied(res) {
		return errors.New("auth failed")
	}

	return kc.extractSessionID(res)
}

func (kc *Client) RequestWithAuth(method, endpoint, body string) (*http.Response, error) {
	urlParsed, err := kc.prepareURL(endpoint)
	if err != nil {
		return nil, err
	}

	res, err := kc.request(method, urlParsed.String(), body)
	if err != nil {
		return nil, err
	}

	if isAccessDenied(res) {
		if err = kc.Auth(); err != nil {
			return nil, err
		}
		return kc.request(method, urlParsed.String(), body)
	}

	cleanResponseHeaders(res)
	return res, nil
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

func (kc *Client) getSaltAndNonce() (string, string, error) {
	payload := kc.buildChallengePayload()
	response, err := kc.request("POST", kc.URL+"/rpc", payload)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()

	return kc.parseSaltAndNonce(response)
}

func (kc *Client) generateLoginHash(salt, nonce string) string {
	hashValue := kc.generateHash(salt, kc.Password)
	loginData := fmt.Sprintf("root:%s:%s", hashValue, nonce)
	hash := md5.Sum([]byte(loginData))
	return hex.EncodeToString(hash[:])
}

func (kc *Client) generateHash(salt, pass string) string {
	return password.MD5.Crypt([]byte(pass), []byte(salt), nil)
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

func (kc *Client) request(method, urlStr, body string) (*http.Response, error) {
	if strings.Contains(urlStr, "/rpc") {
		body = kc.updateRequestBodyWithSessionID(body)
	}

	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := kc.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	return resp, nil
}

func (kc *Client) updateRequestBodyWithSessionID(body string) string {
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

func (kc *Client) buildAuthPayload(loginHash string) string {
	authPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "login",
		"params": map[string]string{
			"username": kc.Username,
			"hash":     loginHash,
		},
	}
	payloadBytes, _ := json.Marshal(authPayload)
	return string(payloadBytes)
}

func (kc *Client) extractSessionID(res *http.Response) error {
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

func (kc *Client) prepareURL(endpoint string) (*url.URL, error) {
	endpoint = strings.TrimLeft(endpoint, "/")
	return url.Parse(kc.URL + "/" + endpoint)
}

func cleanResponseHeaders(res *http.Response) {
	res.Header.Del("Set-Cookie")
	// This is required by the frontend. Otherwise, it will loop until the cookie is set.
	res.Header.Set("Set-Cookie", "Admin-Token=1337")
}

func (kc *Client) buildChallengePayload() string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"challenge","params":{"username":"%s"}}`, kc.Username)
}

func (kc *Client) parseSaltAndNonce(response *http.Response) (string, string, error) {
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
