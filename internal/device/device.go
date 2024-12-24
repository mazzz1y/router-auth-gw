package device

import (
	"fmt"
	"net/http"

	"github.com/mazzz1y/router-auth-gw/internal/config"
	"github.com/mazzz1y/router-auth-gw/pkg/glinet"
	"github.com/mazzz1y/router-auth-gw/pkg/keenetic"
)

type Device struct {
	Tag   string
	Users []User
}

type User struct {
	Name   string
	Client ClientWrapper
}

type DeviceManager struct {
	Devices map[string]Device
}

type ClientWrapper interface {
	RequestWithAuth(method, endpoint, body string) (*http.Response, error)
	Auth() error
}

func NewDeviceManager(cfg []config.DeviceConfig, auth bool) (*DeviceManager, error) {
	deviceManager := &DeviceManager{
		Devices: make(map[string]Device),
	}

	for _, cfgDevice := range cfg {
		users, err := initClients(cfgDevice, auth)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", cfgDevice.URL, err)
		}

		deviceManager.Devices[cfgDevice.Tag] = Device{
			Tag:   cfgDevice.Tag,
			Users: users,
		}
	}
	return deviceManager, nil
}

func initClients(c config.DeviceConfig, auth bool) ([]User, error) {
	users := make([]User, len(c.Users))
	for i, v := range c.Users {
		client, err := createClient(c.Type, c.URL, c.ProxyUrl, v.Username, v.Password)
		if err != nil {
			return nil, err
		}

		if auth {
			if err := client.Auth(); err != nil {
				return nil, err
			}
		}

		users[i] = User{
			Name:   v.Username,
			Client: client,
		}
	}

	return users, nil
}

func createClient(deviceType, url, proxyUrl, username, password string) (ClientWrapper, error) {
	switch deviceType {
	case "keenetic":
		return keenetic.NewClient(url, proxyUrl, username, password), nil
	case "glinet":
		return glinet.NewClient(url, proxyUrl, username, password), nil
	default:
		if deviceType == "" {
			return nil, fmt.Errorf("you must specify a device type")
		}
		return nil, fmt.Errorf("unsupported device type: %s", deviceType)
	}
}
