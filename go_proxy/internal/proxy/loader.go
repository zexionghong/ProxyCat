package proxy

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ProxyType 代理类型
type ProxyType string

const (
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeSOCKS5 ProxyType = "socks5"
)

// ProxyInfo 存储代理信息
type ProxyInfo struct {
	Host     string
	Port     string
	Username string
	Password string
	Type     ProxyType // 代理类型: http 或 socks5
}

// LoadProxyList 从文件中加载代理IP列表
func LoadProxyList(filename string) ([]ProxyInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open proxy file: %v", err)
	}
	defer file.Close()

	var proxies []ProxyInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		proxyInfo, err := parseProxyURL(line)
		if err != nil {
			fmt.Printf("Warning: Invalid proxy format '%s': %v\n", line, err)
			continue
		}
		proxies = append(proxies, proxyInfo)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading proxy file: %v", err)
	}

	return proxies, nil
}

// parseProxyURL 解析代理URL
func parseProxyURL(proxyURL string) (ProxyInfo, error) {
	// 默认为HTTP代理
	proxyType := ProxyTypeHTTP

	// 如果URL有明确的协议前缀，解析出代理类型
	if strings.HasPrefix(proxyURL, "socks5://") {
		proxyType = ProxyTypeSOCKS5
	} else if !strings.HasPrefix(proxyURL, "http://") && !strings.HasPrefix(proxyURL, "https://") {
		// 如果没有协议前缀，添加默认的http://前缀
		proxyURL = "http://" + proxyURL
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return ProxyInfo{}, fmt.Errorf("invalid URL format: %v", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		// 根据协议设置默认端口
		if proxyType == ProxyTypeSOCKS5 {
			port = "1080" // SOCKS5默认端口
		} else {
			port = "80" // HTTP默认端口
		}
	}

	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	return ProxyInfo{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Type:     proxyType,
	}, nil
}

// String 返回代理地址字符串
func (p ProxyInfo) String() string {
	var auth string
	if p.Username != "" && p.Password != "" {
		auth = fmt.Sprintf("%s:%s@", p.Username, p.Password)
	}

	return fmt.Sprintf("%s://%s%s:%s", p.Type, auth, p.Host, p.Port)
}
