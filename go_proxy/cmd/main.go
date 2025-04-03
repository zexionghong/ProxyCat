package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"proxycat/internal/config"
	"proxycat/internal/proxy"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to config file")
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 加载代理IP列表
	proxies, err := proxy.LoadProxyList(cfg.Server.ProxyFile)
	if err != nil {
		log.Fatalf("Failed to load proxy list: %v", err)
	}

	// 打印加载的代理IP列表
	fmt.Println("Loaded proxy list:")
	for i, p := range proxies {
		fmt.Printf("%d. %s\n", i+1, p.String())
	}
	fmt.Printf("Total: %d proxies\n", len(proxies))

	// 创建代理服务器
	server := proxy.NewServer(cfg)
	server.UpdateProxyList(proxies)

	// 处理信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动服务器
	go func() {
		if err := server.Start(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// 等待信号
	<-sigChan
	log.Println("Shutting down server...")
	server.Stop()
}
