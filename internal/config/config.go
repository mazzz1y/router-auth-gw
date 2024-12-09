package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Entrypoints []EntrypointConfig `yaml:"entrypoints"`
	Devices     []DeviceConfig     `yaml:"devices"`
}

type EntrypointConfig struct {
	Listen           string            `yaml:"listen"`
	DeviceTag        string            `yaml:"device_tag"`
	ReadOnly         bool              `yaml:"read_only,omitempty"`
	ForwardAuth      ForwardAuthConfig `yaml:"forward_auth,omitempty"`
	BasicAuth        []BasicAuthConfig `yaml:"basic_auth,omitempty"`
	AllowedEndpoints []string          `yaml:"allowed_endpoints"`
}

type DeviceConfig struct {
	Tag      string       `yaml:"tag"`
	URL      string       `yaml:"url"`
	ProxyUrl string       `yaml:"proxy_url,omitempty"`
	Users    []UserConfig `yaml:"users"`
}

type UserConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type BasicAuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ForwardAuthConfig struct {
	Header  string            `yaml:"header"`
	Mapping map[string]string `yaml:"mapping"`
}

// BasicAuthMap converts a list of BasicAuthConfig entries into a map for easy lookup
func (ec EntrypointConfig) BasicAuthMap() map[string]string {
	basicAuthMap := make(map[string]string)
	for _, e := range ec.BasicAuth {
		basicAuthMap[e.Username] = e.Password
	}
	return basicAuthMap
}

func LoadConfig(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return &config, nil
}
