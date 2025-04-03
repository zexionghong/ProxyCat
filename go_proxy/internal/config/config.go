package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig      `yaml:"server"`
	Users  map[string]string `yaml:"users"`
}

type ServerConfig struct {
	DisplayLevel             int    `yaml:"display_level"`
	Port                     int    `yaml:"port"`
	WebPort                  int    `yaml:"web_port"`
	Mode                     string `yaml:"mode"`
	Interval                 int    `yaml:"interval"`
	UseGetIP                 bool   `yaml:"use_getip"`
	GetIPURL                 string `yaml:"getip_url"`
	ProxyUsername            string `yaml:"proxy_username"`
	ProxyPassword            string `yaml:"proxy_password"`
	ProxyFile                string `yaml:"proxy_file"`
	CheckProxies             bool   `yaml:"check_proxies"`
	TestURL                  string `yaml:"test_url"`
	Language                 string `yaml:"language"`
	WhitelistFile            string `yaml:"whitelist_file"`
	BlacklistFile            string `yaml:"blacklist_file"`
	IPAuthPriority           string `yaml:"ip_auth_priority"`
	Token                    string `yaml:"token"`
	DirectConnect            bool   `yaml:"direct_connect"`
	SessionExpirationMinutes int    `yaml:"session_expiration_minutes"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
