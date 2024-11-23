package devices

import (
	"fmt"
	"github.com/mazzz1y/keenetic-auth-gw/internal/config"
	"github.com/mazzz1y/keenetic-auth-gw/pkg/keenetic"
)

type Device struct {
	Tag   string
	Users []User
}

type User struct {
	Name   string
	Client keenetic.ClientWrapper
}

type DeviceManager struct {
	Devices map[string]Device
}

func NewDeviceManager(cfg []config.DeviceConfig, auth bool) (*DeviceManager, error) {
	deviceManager := &DeviceManager{
		Devices: make(map[string]Device),
	}

	for _, cfgDevice := range cfg {
		users, err := initClients(cfgDevice, auth)
		if err != nil {
			return nil, err
		}

		deviceManager.Devices[cfgDevice.Tag] = Device{
			Tag:   cfgDevice.Tag,
			Users: users,
		}
	}
	return deviceManager, nil
}

func (dm *DeviceManager) Auth() error {
	for tag, device := range dm.Devices {
		for _, user := range device.Users {
			if err := user.Client.Auth(); err != nil {
				return fmt.Errorf("%s/%s: %v", tag, user.Name, err)
			}
		}
	}
	return nil
}

func (dm *DeviceManager) GetDeviceByTag(tag string) (Device, bool) {
	device, exists := dm.Devices[tag]
	return device, exists
}

func initClients(c config.DeviceConfig, auth bool) ([]User, error) {
	users := make([]User, len(c.Users))
	for i, v := range c.Users {
		client := keenetic.NewClient(c.URL, c.ProxyUrl, v.Username, v.Password)

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
