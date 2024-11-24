package device_test

import (
	"github.com/mazzz1y/keenetic-auth-gw/internal/config"
	"github.com/mazzz1y/keenetic-auth-gw/internal/device"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockConfig = &config.Config{
	Devices: []config.DeviceConfig{
		{
			Tag:      "Device1",
			URL:      "http://device1.local",
			ProxyUrl: "http://proxy.local",
			Users: []config.UserConfig{
				{Username: "user1", Password: "pass1"},
				{Username: "user2", Password: "pass2"},
			},
		},
	},
}

func TestNewDeviceManager(t *testing.T) {
	t.Run("Success", func(t *testing.T) {

		manager, _ := device.NewDeviceManager(mockConfig.Devices, false)
		assert.Equal(t, 1, len(manager.Devices))
		assert.Equal(t, "Device1", manager.Devices["Device1"].Tag)
		assert.Equal(t, 2, len(manager.Devices["Device1"].Users))
	})
}

func TestGetDeviceByTag(t *testing.T) {
	manager, _ := device.NewDeviceManager(mockConfig.Devices, false)

	t.Run("DeviceFound", func(t *testing.T) {
		device, found := manager.GetDeviceByTag("Device1")
		assert.True(t, found)
		assert.Equal(t, "Device1", device.Tag)
	})

	t.Run("DeviceNotFound", func(t *testing.T) {
		device, found := manager.GetDeviceByTag("InvalidTag")
		assert.False(t, found)
		assert.Equal(t, device.Device{}, device)
	})
}
