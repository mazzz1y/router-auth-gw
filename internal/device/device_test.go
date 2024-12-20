package device_test

import (
	"testing"

	"github.com/mazzz1y/router-auth-gw/internal/config"
	"github.com/mazzz1y/router-auth-gw/internal/device"

	"github.com/stretchr/testify/assert"
)

var mockConfig = &config.Config{
	Devices: []config.DeviceConfig{
		{
			Tag:      "Device1",
			URL:      "http://device1.local",
			ProxyUrl: "http://proxy.local",
			Type:     "keenetic",
			Users: []config.UserConfig{
				{Username: "user1", Password: "pass1"},
				{Username: "user2", Password: "pass2"},
			},
		},
	},
}

func TestNewDeviceManager(t *testing.T) {
	t.Run("Success", func(t *testing.T) {

		manager, err := device.NewDeviceManager(mockConfig.Devices, false)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(manager.Devices))
		assert.Equal(t, "Device1", manager.Devices["Device1"].Tag)
		assert.Equal(t, 2, len(manager.Devices["Device1"].Users))
	})
}
