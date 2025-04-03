package proxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

type ProxyChecker struct {
	timeout time.Duration
}

func NewProxyChecker(timeout time.Duration) *ProxyChecker {
	return &ProxyChecker{
		timeout: timeout,
	}
}

func (c *ProxyChecker) CheckProxy(proxy string, testURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// 创建一个带超时的连接
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy %s: %v", proxy, err)
	}
	defer conn.Close()

	// 如果提供了测试URL，尝试通过代理访问
	if testURL != "" {
		// TODO: 实现HTTP请求测试
		// 这里需要实现完整的HTTP代理请求测试
	}

	return nil
}

func (c *ProxyChecker) CheckProxies(proxies []string, testURL string) []string {
	var validProxies []string

	for _, proxy := range proxies {
		if err := c.CheckProxy(proxy, testURL); err != nil {
			fmt.Printf("Proxy %s is invalid: %v\n", proxy, err)
			continue
		}
		validProxies = append(validProxies, proxy)
	}

	return validProxies
}
