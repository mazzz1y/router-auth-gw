package config_test

import (
	"os"
	"testing"

	"github.com/mazzz1y/keenetic-auth-gw/internal/config"

	"github.com/stretchr/testify/assert"
)

var yamlContent = `
entrypoints:
  - listen: "localhost:8080"
    device_tag: "device123"
    basic_auth:
      - username: xxx
        password: xxx
    allowed_endpoints: ["/status", "/health"]
    forward_auth:
      header: X-Forwared-User
      mapping:
        user1: user2
devices:
  - tag: "device123"
    url: "http://device.local"
    users:
      - username: "user1"
        password: "pass1"
`

func TestLoadConfig_Success(t *testing.T) {
	filePath, err := writeTempFile(yamlContent)
	assert.NoError(t, err)
	defer os.Remove(filePath)

	cfg, err := config.LoadConfig(filePath)
	assert.NoError(t, err)

	expected := &config.Config{
		Entrypoints: []config.EntrypointConfig{{
			Listen:    "localhost:8080",
			DeviceTag: "device123",
			BasicAuth: []config.BasicAuthConfig{
				{
					Username: "xxx",
					Password: "xxx",
				},
			},
			AllowedEndpoints: []string{"/status", "/health"},
			ForwardAuth: config.ForwardAuthConfig{
				Header: "X-Forwared-User",
				Mapping: map[string]string{
					"user1": "user2",
				},
			},
		}},
		Devices: []config.DeviceConfig{{
			Tag: "device123",
			URL: "http://device.local",
			Users: []config.UserConfig{{
				Username: "user1",
				Password: "pass1",
			}},
		}},
	}

	assert.Equal(t, expected, cfg)
}

func TestLoadConfig_Error(t *testing.T) {
	t.Run("FileNotFound", func(t *testing.T) {
		_, err := config.LoadConfig("non_existent.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open config file")
	})

	t.Run("InvalidYAML", func(t *testing.T) {
		content := "invalid: yaml: content"
		filePath, err := writeTempFile(content)
		assert.NoError(t, err)
		defer os.Remove(filePath)

		_, err = config.LoadConfig(filePath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal YAML")
	})
}

func writeTempFile(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	_, err = tmpFile.Write([]byte(content))
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}
