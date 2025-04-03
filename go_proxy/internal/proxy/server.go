package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"proxycat/internal/config"
)

const (
	// SOCKS5常量
	SOCKS5_VERSION  = byte(5)
	SOCKS5_RESERVED = byte(0)

	// SOCKS5命令
	SOCKS5_CMD_CONNECT       = byte(1)
	SOCKS5_CMD_BIND          = byte(2)
	SOCKS5_CMD_UDP_ASSOCIATE = byte(3)

	// SOCKS5认证方法
	SOCKS5_AUTH_NONE          = byte(0)
	SOCKS5_AUTH_GSSAPI        = byte(1)
	SOCKS5_AUTH_PASSWORD      = byte(2)
	SOCKS5_AUTH_NO_ACCEPTABLE = byte(0xFF)

	// SOCKS5地址类型
	SOCKS5_ADDR_IPV4   = byte(1)
	SOCKS5_ADDR_DOMAIN = byte(3)
	SOCKS5_ADDR_IPV6   = byte(4)

	// SOCKS5回复状态
	SOCKS5_REP_SUCCESS                    = byte(0)
	SOCKS5_REP_SERVER_FAILURE             = byte(1)
	SOCKS5_REP_CONNECTION_NOT_ALLOWED     = byte(2)
	SOCKS5_REP_NETWORK_UNREACHABLE        = byte(3)
	SOCKS5_REP_HOST_UNREACHABLE           = byte(4)
	SOCKS5_REP_CONNECTION_REFUSED         = byte(5)
	SOCKS5_REP_TTL_EXPIRED                = byte(6)
	SOCKS5_REP_COMMAND_NOT_SUPPORTED      = byte(7)
	SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED = byte(8)
)

type Server struct {
	config     *config.Config
	proxyList  []ProxyInfo
	currentIdx int
	mu         sync.RWMutex
	clients    map[net.Conn]struct{}
	stopChan   chan struct{}
	// 按类型缓存代理列表
	httpProxies   []ProxyInfo
	socks5Proxies []ProxyInfo
	// 代理计数器
	httpProxyIndex   int
	socks5ProxyIndex int

	// 会话管理相关
	sessions      map[string]sessionInfo // 会话ID到会话信息的映射
	sessionsMutex sync.RWMutex           // 用于sessions的互斥锁
}

// 会话信息
type sessionInfo struct {
	httpProxy   ProxyInfo // 分配给会话的HTTP代理
	socks5Proxy ProxyInfo // 分配给会话的SOCKS5代理
	lastAccess  time.Time // 最后访问时间
	created     time.Time // 创建时间
}

func NewServer(cfg *config.Config) *Server {
	return &Server{
		config:        cfg,
		clients:       make(map[net.Conn]struct{}),
		stopChan:      make(chan struct{}),
		httpProxies:   []ProxyInfo{},
		socks5Proxies: []ProxyInfo{},
		sessions:      make(map[string]sessionInfo),
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Server.Port))
	if err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}
	defer listener.Close()

	// 启动会话清理协程
	go s.cleanupSessions()

	log.Printf("Server started on port %d", s.config.Server.Port)

	for {
		select {
		case <-s.stopChan:
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}

			s.mu.Lock()
			s.clients[conn] = struct{}{}
			s.mu.Unlock()

			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.clients, clientConn)
		s.mu.Unlock()
		clientConn.Close()
	}()

	// 检查第一个字节以确定协议
	firstByte := make([]byte, 1)
	if _, err := clientConn.Read(firstByte); err != nil {
		if !isConnectionClosed(err) {
			log.Printf("Failed to read first byte: %v", err)
		}
		return
	}

	// 记录客户端IP
	clientIP := "unknown"
	if addr, ok := clientConn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	log.Printf("收到来自 %s 的连接请求，第一个字节: %d", clientIP, firstByte[0])

	// 首先判断是否是SOCKS5协议
	if firstByte[0] == SOCKS5_VERSION {
		log.Printf("检测到SOCKS5协议连接请求")
		s.handleSocks5Proxy(clientConn, firstByte[0])
		return
	} else {
		// 否则假设是HTTP，将读取的字节放回
		log.Printf("尝试作为HTTP协议处理连接请求")
		bufReader := bufio.NewReader(io.MultiReader(bytes.NewReader(firstByte), clientConn))
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			if !isConnectionClosed(err) {
				log.Printf("解析HTTP请求失败: %v", err)
			}

			// 如果不是HTTP请求，尝试作为SOCKS5处理
			log.Printf("解析HTTP请求失败，尝试作为SOCKS5协议处理")
			// 创建一个新的连接，因为我们已经消耗了部分数据
			s.handleSocks5Proxy(clientConn, firstByte[0])
			return
		}

		// 处理HTTP CONNECT方法（用于HTTPS代理）
		if req.Method == http.MethodConnect {
			s.handleHttpsProxy(clientConn, req)
			return
		}

		// 处理普通HTTP代理
		s.handleHttpProxy(clientConn, req)
	}
}

func (s *Server) handleSocks5Proxy(clientConn net.Conn, firstByte byte) {
	// 输出客户端IP
	clientIP := "unknown"
	if addr, ok := clientConn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}
	log.Printf("[SOCKS5] 处理来自 %s 的连接", clientIP)

	// 如果第一个字节不是SOCKS5版本，打印警告但继续处理
	if firstByte != SOCKS5_VERSION {
		log.Printf("[SOCKS5] 警告：客户端发送的版本号 %d 不是标准SOCKS5版本号 %d，尝试继续处理",
			firstByte, SOCKS5_VERSION)
	}

	// 读取客户端支持的认证方法数量
	methodsCountByte := make([]byte, 1)
	if _, err := io.ReadFull(clientConn, methodsCountByte); err != nil {
		log.Printf("[SOCKS5] 读取认证方法数量失败: %v", err)
		return
	}

	// 读取认证方法列表
	nmethods := int(methodsCountByte[0])
	log.Printf("[SOCKS5] 认证方法数量: %d", nmethods)

	if nmethods == 0 {
		log.Printf("[SOCKS5] 客户端未提供认证方法，使用无认证方式")
		// 告诉客户端我们使用无认证
		if _, err := clientConn.Write([]byte{SOCKS5_VERSION, SOCKS5_AUTH_NONE}); err != nil {
			log.Printf("[SOCKS5] 发送认证响应失败: %v", err)
			return
		}
	} else {
		methods := make([]byte, nmethods)
		if _, err := io.ReadFull(clientConn, methods); err != nil {
			log.Printf("[SOCKS5] 读取认证方法列表失败: %v", err)
			return
		}

		// 检查认证方法，我们优先选择密码认证，其次是无认证
		passwordAuthSupported := false
		noAuthSupported := false
		log.Printf("[SOCKS5] 客户端支持的认证方法: ")
		for i, m := range methods {
			log.Printf("  方法 %d: %d", i, m)
			if m == SOCKS5_AUTH_PASSWORD {
				passwordAuthSupported = true
			} else if m == SOCKS5_AUTH_NONE {
				noAuthSupported = true
			}
		}

		// 优先使用密码认证
		if passwordAuthSupported {
			// 告诉客户端我们使用密码认证
			log.Printf("[SOCKS5] 响应使用密码认证方法")
			if _, err := clientConn.Write([]byte{SOCKS5_VERSION, SOCKS5_AUTH_PASSWORD}); err != nil {
				log.Printf("[SOCKS5] 发送认证响应失败: %v", err)
				return
			}

			// 处理密码认证
			username, _, err := s.handlePasswordAuth(clientConn)
			if err != nil {
				log.Printf("[SOCKS5] 密码认证失败: %v", err)
				return
			}

			log.Printf("[SOCKS5] 用户 '%s' 认证成功", username)

			// 使用用户名作为会话ID
			sessionID := fmt.Sprintf("user-%s", username)

			// 继续处理请求...
			s.handleSocks5Request(clientConn, sessionID)
			return
		} else if noAuthSupported {
			// 告诉客户端我们使用无认证
			log.Printf("[SOCKS5] 响应使用无认证方法")
			if _, err := clientConn.Write([]byte{SOCKS5_VERSION, SOCKS5_AUTH_NONE}); err != nil {
				log.Printf("[SOCKS5] 发送认证响应失败: %v", err)
				return
			}

			// 使用IP地址作为会话ID
			sessionID := s.extractSessionIDFromConn(clientConn)

			// 继续处理请求...
			s.handleSocks5Request(clientConn, sessionID)
			return
		} else {
			// 告诉客户端没有可接受的认证方法
			log.Printf("[SOCKS5] 客户端不支持我们要求的认证方法")
			if _, err := clientConn.Write([]byte{SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE}); err != nil {
				log.Printf("[SOCKS5] 发送认证响应失败: %v", err)
				return
			}
			return
		}
	}

	// 使用IP地址作为会话ID（无认证情况）
	sessionID := s.extractSessionIDFromConn(clientConn)

	// 继续处理请求...
	s.handleSocks5Request(clientConn, sessionID)
}

// 直接连接模式处理函数
func (s *Server) handleSocks5DirectConnect(clientConn net.Conn, dstAddr string, dstPort int) {
	dstAddrPort := fmt.Sprintf("%s:%d", dstAddr, dstPort)

	// 直接连接到目标服务器
	log.Printf("[SOCKS5直连] 正在直接连接到 %s", dstAddrPort)
	targetConn, err := net.Dial("tcp", dstAddrPort)
	if err != nil {
		log.Printf("[SOCKS5直连] 连接到目标 %s 失败: %v", dstAddrPort, err)

		// 发送连接失败响应
		var repCode byte = SOCKS5_REP_HOST_UNREACHABLE
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				repCode = SOCKS5_REP_TTL_EXPIRED
				log.Printf("[SOCKS5直连] 连接超时")
			} else if strings.Contains(opErr.Error(), "connection refused") {
				repCode = SOCKS5_REP_CONNECTION_REFUSED
				log.Printf("[SOCKS5直连] 连接被拒绝")
			} else if strings.Contains(opErr.Error(), "network is unreachable") {
				repCode = SOCKS5_REP_NETWORK_UNREACHABLE
				log.Printf("[SOCKS5直连] 网络不可达")
			}
		}

		log.Printf("[SOCKS5直连] 发送失败响应: %d", repCode)
		s.sendSocks5Response(clientConn, repCode, nil, 0)
		return
	}
	defer targetConn.Close()

	// 发送连接成功响应
	log.Printf("[SOCKS5直连] 成功连接到 %s", dstAddrPort)
	s.sendSocks5Response(clientConn, SOCKS5_REP_SUCCESS, nil, 0)
	log.Printf("[SOCKS5直连] 已发送成功响应给客户端")

	// 开始双向转发数据
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[SOCKS5直连] 开始数据转发")

	// 客户端 -> 目标
	go func() {
		n, err := io.Copy(targetConn, clientConn)
		if err != nil && !isConnectionClosed(err) {
			log.Printf("[SOCKS5直连] 客户端到目标的数据传输错误: %v", err)
		} else {
			log.Printf("[SOCKS5直连] 客户端到目标共传输 %d 字节", n)
		}
		cancel()
	}()

	// 目标 -> 客户端
	go func() {
		n, err := io.Copy(clientConn, targetConn)
		if err != nil && !isConnectionClosed(err) {
			log.Printf("[SOCKS5直连] 目标到客户端的数据传输错误: %v", err)
		} else {
			log.Printf("[SOCKS5直连] 目标到客户端共传输 %d 字节", n)
		}
		cancel()
	}()

	<-ctx.Done()
	log.Printf("[SOCKS5直连] 到 %s 的连接已完成", dstAddrPort)
}

// 通过代理连接模式处理函数
func (s *Server) handleSocks5ProxyConnect(clientConn net.Conn, proxy ProxyInfo, dstAddr string, dstPort int) {
	dstAddrPort := fmt.Sprintf("%s:%d", dstAddr, dstPort)

	// 连接到代理服务器
	log.Printf("[SOCKS5代理] 正在连接到上游SOCKS5代理 %s:%s", proxy.Host, proxy.Port)
	proxyConn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", proxy.Host, proxy.Port))
	if err != nil {
		log.Printf("[SOCKS5代理] 连接到代理 %s:%s 失败: %v", proxy.Host, proxy.Port, err)
		s.sendSocks5Response(clientConn, SOCKS5_REP_NETWORK_UNREACHABLE, nil, 0)
		return
	}
	defer proxyConn.Close()
	log.Printf("[SOCKS5代理] 成功连接到上游SOCKS5代理")

	// 初始握手 - 决定认证方法
	var authMethod byte = SOCKS5_AUTH_NONE

	// 如果代理需要认证
	if proxy.Username != "" && proxy.Password != "" {
		authMethod = SOCKS5_AUTH_PASSWORD
		log.Printf("[SOCKS5代理] 将使用用户名/密码认证方式")
	} else {
		log.Printf("[SOCKS5代理] 将使用无认证方式")
	}

	// 发送版本和认证方法
	log.Printf("[SOCKS5代理] 向代理发送认证方法: %d", authMethod)
	if _, err := proxyConn.Write([]byte{SOCKS5_VERSION, 1, authMethod}); err != nil {
		log.Printf("[SOCKS5代理] 向上游发送SOCKS5认证请求失败: %v", err)
		return
	}

	// 读取代理响应
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, authResp); err != nil {
		log.Printf("[SOCKS5代理] 读取上游SOCKS5认证响应失败: %v", err)
		return
	}
	log.Printf("[SOCKS5代理] 收到代理认证方法响应: 版本=%d, 方法=%d", authResp[0], authResp[1])

	// 如果需要用户名密码认证
	if authResp[1] == SOCKS5_AUTH_PASSWORD {
		if proxy.Username == "" || proxy.Password == "" {
			log.Printf("[SOCKS5代理] 上游SOCKS5代理需要认证但未提供凭据")
			s.sendSocks5Response(clientConn, SOCKS5_REP_CONNECTION_NOT_ALLOWED, nil, 0)
			return
		}

		// 发送用户名密码认证
		// 用户名密码认证格式: VERSION(1) | ULEN(1) | USERNAME | PLEN(1) | PASSWORD
		authPacket := []byte{0x01} // 认证子协议版本 01

		// 添加用户名
		authPacket = append(authPacket, byte(len(proxy.Username)))
		authPacket = append(authPacket, []byte(proxy.Username)...)

		// 添加密码
		authPacket = append(authPacket, byte(len(proxy.Password)))
		authPacket = append(authPacket, []byte(proxy.Password)...)

		log.Printf("[SOCKS5代理] 向代理发送用户名/密码认证")
		if _, err := proxyConn.Write(authPacket); err != nil {
			log.Printf("[SOCKS5代理] 向代理发送认证凭据失败: %v", err)
			return
		}

		// 读取认证响应
		authStatusResp := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, authStatusResp); err != nil {
			log.Printf("[SOCKS5代理] 读取代理认证状态失败: %v", err)
			return
		}

		// 检查认证是否成功 (第二个字节为0表示成功)
		log.Printf("[SOCKS5代理] 认证响应: 版本=%d, 状态=%d", authStatusResp[0], authStatusResp[1])
		if authStatusResp[1] != 0 {
			log.Printf("[SOCKS5代理] 认证失败，状态码: %d", authStatusResp[1])
			s.sendSocks5Response(clientConn, SOCKS5_REP_CONNECTION_NOT_ALLOWED, nil, 0)
			return
		}
		log.Printf("[SOCKS5代理] 认证成功")
	} else if authResp[1] != SOCKS5_AUTH_NONE {
		log.Printf("[SOCKS5代理] 上游SOCKS5代理需要不支持的认证方法: %d", authResp[1])
		s.sendSocks5Response(clientConn, SOCKS5_REP_CONNECTION_NOT_ALLOWED, nil, 0)
		return
	}

	log.Printf("[SOCKS5代理] 与上游代理的SOCKS5握手完成")

	// 发送目标连接请求
	cmd := []byte{SOCKS5_VERSION, SOCKS5_CMD_CONNECT, SOCKS5_RESERVED}

	// 添加地址类型
	var addrType byte
	var addrBytes []byte

	if net.ParseIP(dstAddr).To4() != nil {
		// IPv4
		addrType = SOCKS5_ADDR_IPV4
		addrBytes = net.ParseIP(dstAddr).To4()
		log.Printf("[SOCKS5代理] 目标地址类型: IPv4")
	} else if net.ParseIP(dstAddr).To16() != nil {
		// IPv6
		addrType = SOCKS5_ADDR_IPV6
		addrBytes = net.ParseIP(dstAddr).To16()
		log.Printf("[SOCKS5代理] 目标地址类型: IPv6")
	} else {
		// 域名
		addrType = SOCKS5_ADDR_DOMAIN
		addrBytes = append([]byte{byte(len(dstAddr))}, []byte(dstAddr)...)
		log.Printf("[SOCKS5代理] 目标地址类型: 域名")
	}

	cmd = append(cmd, addrType)
	cmd = append(cmd, addrBytes...)

	// 添加端口
	cmd = append(cmd, byte(dstPort>>8), byte(dstPort&0xff))

	log.Printf("[SOCKS5代理] 通过代理向目标 %s 发送连接请求", dstAddrPort)
	if _, err := proxyConn.Write(cmd); err != nil {
		log.Printf("[SOCKS5代理] 向上游发送SOCKS5请求失败: %v", err)
		return
	}

	// 读取代理响应
	resp := make([]byte, 4)
	if _, err := io.ReadFull(proxyConn, resp); err != nil {
		log.Printf("[SOCKS5代理] 读取上游SOCKS5响应失败: %v", err)
		return
	}

	log.Printf("[SOCKS5代理] 收到代理响应: 版本=%d, 状态=%d, 保留=%d, 地址类型=%d",
		resp[0], resp[1], resp[2], resp[3])

	if resp[1] != SOCKS5_REP_SUCCESS {
		log.Printf("[SOCKS5代理] 上游SOCKS5代理返回错误: %d", resp[1])
		s.sendSocks5Response(clientConn, resp[1], nil, 0)
		return
	}

	// 读取地址类型
	addrType = resp[3]
	log.Printf("[SOCKS5代理] 代理返回的地址类型: %d", addrType)

	// 跳过地址和端口
	switch addrType {
	case SOCKS5_ADDR_IPV4:
		skipBytes := make([]byte, 4+2) // IPv4 + port
		io.ReadFull(proxyConn, skipBytes)
		log.Printf("[SOCKS5代理] 跳过IPv4地址和端口")
	case SOCKS5_ADDR_DOMAIN:
		lenByte := make([]byte, 1)
		io.ReadFull(proxyConn, lenByte)
		skipBytes := make([]byte, int(lenByte[0])+2) // domain + port
		io.ReadFull(proxyConn, skipBytes)
		log.Printf("[SOCKS5代理] 跳过域名(长度:%d)和端口", lenByte[0])
	case SOCKS5_ADDR_IPV6:
		skipBytes := make([]byte, 16+2) // IPv6 + port
		io.ReadFull(proxyConn, skipBytes)
		log.Printf("[SOCKS5代理] 跳过IPv6地址和端口")
	}

	// 向客户端发送成功响应
	log.Printf("[SOCKS5代理] 向客户端发送成功响应")
	s.sendSocks5Response(clientConn, SOCKS5_REP_SUCCESS, nil, 0)

	log.Printf("[SOCKS5代理] 开始客户端和代理之间的数据传输")
	// 开始双向转发数据
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// 客户端 -> 代理
		n, err := io.Copy(proxyConn, clientConn)
		if err != nil && !isConnectionClosed(err) {
			log.Printf("[SOCKS5代理] SOCKS5客户端到代理的数据传输错误: %v", err)
		} else {
			log.Printf("[SOCKS5代理] 客户端到代理共传输 %d 字节", n)
		}
		cancel()
	}()

	go func() {
		// 代理 -> 客户端
		n, err := io.Copy(clientConn, proxyConn)
		if err != nil && !isConnectionClosed(err) {
			log.Printf("[SOCKS5代理] SOCKS5代理到客户端的数据传输错误: %v", err)
		} else {
			log.Printf("[SOCKS5代理] 代理到客户端共传输 %d 字节", n)
		}
		cancel()
	}()

	<-ctx.Done()
	log.Printf("[SOCKS5代理] 到 %s 的SOCKS5连接已完成", dstAddrPort)
}

func (s *Server) sendSocks5Response(conn net.Conn, status byte, ip net.IP, port uint16) {
	resp := []byte{SOCKS5_VERSION, status, SOCKS5_RESERVED}

	// 默认使用IPv4地址 0.0.0.0
	if ip == nil {
		resp = append(resp, SOCKS5_ADDR_IPV4)
		resp = append(resp, []byte{0, 0, 0, 0}...)
	} else if ipv4 := ip.To4(); ipv4 != nil {
		resp = append(resp, SOCKS5_ADDR_IPV4)
		resp = append(resp, ipv4...)
	} else {
		resp = append(resp, SOCKS5_ADDR_IPV6)
		resp = append(resp, ip.To16()...)
	}

	// 添加端口
	resp = append(resp, byte(port>>8), byte(port&0xff))

	conn.Write(resp)
}

func (s *Server) handleHttpProxy(clientConn net.Conn, req *http.Request) {
	// 提取用户认证信息
	var sessionID string

	// 从Proxy-Authorization头中提取用户名作为会话ID
	authHeader := req.Header.Get("Proxy-Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		auth := strings.TrimPrefix(authHeader, "Basic ")
		if decoded, err := base64.StdEncoding.DecodeString(auth); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 && parts[0] != "" {
				username := parts[0]
				sessionID = fmt.Sprintf("user-%s", username)
				log.Printf("HTTP请求: 从认证头提取用户名: '%s'", username)
			}
		}
	}

	// 如果没有从认证头中提取到用户名，使用IP地址作为会话ID
	if sessionID == "" {
		clientIP := req.RemoteAddr
		if ip, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = ip
		}
		sessionID = fmt.Sprintf("ip-%s", clientIP)
		log.Printf("HTTP请求: 使用IP作为会话ID: '%s'", sessionID)
	}

	log.Printf("HTTP请求会话ID: [%s], 目标: %s", sessionID, req.URL.String())

	// 获取或创建会话
	session := s.getOrCreateSession(sessionID)
	proxy := session.httpProxy

	// 如果会话没有分配到HTTP代理，则获取一个新的
	if proxy.Host == "" {
		proxy = s.getNextAvailableHttpProxy()
		if proxy.Host != "" {
			// 更新会话中的代理
			s.sessionsMutex.Lock()
			session.httpProxy = proxy
			s.sessions[sessionID] = session
			s.sessionsMutex.Unlock()
			log.Printf("HTTP请求为会话 [%s] 分配了新的HTTP代理: %s", sessionID, proxy.String())
		}
	}

	if proxy.Host == "" {
		log.Println("没有可用的HTTP代理")
		resp := &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(clientConn)
		return
	}

	log.Printf("HTTP请求 %s, 使用会话 [%s] 的HTTP代理 %s", req.URL.String(), sessionID, proxy.String())

	// 连接到上游代理服务器
	proxyReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		log.Printf("Failed to create proxy request: %v", err)
		return
	}

	// 复制原始请求头
	for key, values := range req.Header {
		// 不转发Proxy-Authorization头，我们用自己的认证
		if strings.ToLower(key) == "proxy-authorization" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// 添加代理认证
	if proxy.Username != "" && proxy.Password != "" {
		auth := proxy.Username + ":" + proxy.Password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		proxyReq.Header.Set("Proxy-Authorization", basicAuth)
	}

	// 使用HTTP客户端发送请求
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil, // 不使用系统代理
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("Failed to send request to proxy: %v", err)
		errResp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		errResp.Write(clientConn)
		return
	}
	defer resp.Body.Close()

	// 将响应发送回客户端
	if err := resp.Write(clientConn); err != nil {
		if !isConnectionClosed(err) {
			log.Printf("Failed to write response to client: %v", err)
		}
	}
}

func (s *Server) handleHttpsProxy(clientConn net.Conn, req *http.Request) {
	// 提取用户认证信息
	var sessionID string

	// 从Proxy-Authorization头中提取用户名作为会话ID
	authHeader := req.Header.Get("Proxy-Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		auth := strings.TrimPrefix(authHeader, "Basic ")
		if decoded, err := base64.StdEncoding.DecodeString(auth); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 && parts[0] != "" {
				username := parts[0]
				sessionID = fmt.Sprintf("user-%s", username)
				log.Printf("HTTPS连接: 从认证头提取用户名: '%s'", username)
			}
		}
	}

	// 如果没有从认证头中提取到用户名，使用IP地址作为会话ID
	if sessionID == "" {
		clientIP := req.RemoteAddr
		if ip, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = ip
		}
		sessionID = fmt.Sprintf("ip-%s", clientIP)
		log.Printf("HTTPS连接: 使用IP作为会话ID: '%s'", sessionID)
	}

	log.Printf("HTTPS连接会话ID: [%s], 目标: %s", sessionID, req.Host)

	// 获取或创建会话
	session := s.getOrCreateSession(sessionID)
	proxy := session.httpProxy

	// 如果会话没有分配到HTTP代理，则获取一个新的
	if proxy.Host == "" {
		proxy = s.getNextAvailableHttpProxy()
		if proxy.Host != "" {
			// 更新会话中的代理
			s.sessionsMutex.Lock()
			session.httpProxy = proxy
			s.sessions[sessionID] = session
			s.sessionsMutex.Unlock()
			log.Printf("HTTPS连接为会话 [%s] 分配了新的HTTP代理: %s", sessionID, proxy.String())
		}
	}

	if proxy.Host == "" {
		log.Println("没有可用的HTTP代理")
		clientConn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		return
	}

	log.Printf("HTTPS连接 %s, 使用会话 [%s] 的HTTP代理 %s", req.Host, sessionID, proxy.String())

	// 连接到代理服务器
	proxyConn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", proxy.Host, proxy.Port))
	if err != nil {
		log.Printf("Failed to connect to proxy %s:%s: %v", proxy.Host, proxy.Port, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer proxyConn.Close()

	// 发送CONNECT请求到代理
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", req.Host)
	connectReq += fmt.Sprintf("Host: %s\r\n", req.Host)

	// 添加代理认证
	if proxy.Username != "" && proxy.Password != "" {
		auth := proxy.Username + ":" + proxy.Password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		connectReq += fmt.Sprintf("Proxy-Authorization: %s\r\n", basicAuth)
	}

	connectReq += "\r\n"

	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		log.Printf("Failed to send CONNECT request: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// 读取代理服务器的响应
	resp := make([]byte, 1024)
	n, err := proxyConn.Read(resp)
	if err != nil {
		log.Printf("Failed to read proxy response: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// 检查代理响应是否成功
	if !strings.Contains(string(resp[:n]), "200") {
		log.Printf("Proxy connection failed: %s", string(resp[:n]))
		clientConn.Write(resp[:n])
		return
	}

	// 发送成功的CONNECT响应给客户端
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 开始双向转发数据
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// 客户端 -> 代理
		_, err := io.Copy(proxyConn, clientConn)
		if err != nil && !isConnectionClosed(err) {
			log.Printf("Error copying client to proxy: %v", err)
		}
		cancel()
	}()

	go func() {
		// 代理 -> 客户端
		_, err := io.Copy(clientConn, proxyConn)
		if err != nil && !isConnectionClosed(err) {
			log.Printf("Error copying proxy to client: %v", err)
		}
		cancel()
	}()

	<-ctx.Done()
	log.Printf("HTTPS连接 %s 已完成", req.Host)
}

// isConnectionClosed 检查错误是否表示连接已关闭
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.EOF) {
		return true
	}

	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Err.Error() == "use of closed network connection"
	}

	return strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "broken pipe")
}

// getNextHttpProxy 获取下一个HTTP代理
func (s *Server) getNextHttpProxy() ProxyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.httpProxies) == 0 {
		return ProxyInfo{}
	}

	if s.config.Server.Mode == "cycle" {
		s.httpProxyIndex = (s.httpProxyIndex + 1) % len(s.httpProxies)
		return s.httpProxies[s.httpProxyIndex]
	}

	// 负载均衡模式（这里简单实现为选择第一个）
	return s.httpProxies[0]
}

// getNextSocks5Proxy 获取下一个SOCKS5代理
func (s *Server) getNextSocks5Proxy() ProxyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.socks5Proxies) == 0 {
		return ProxyInfo{}
	}

	if s.config.Server.Mode == "cycle" {
		s.socks5ProxyIndex = (s.socks5ProxyIndex + 1) % len(s.socks5Proxies)
		return s.socks5Proxies[s.socks5ProxyIndex]
	}

	// 负载均衡模式（这里简单实现为选择第一个）
	return s.socks5Proxies[0]
}

// 保留旧的getNextProxy方法以保持兼容性
func (s *Server) getNextProxy() ProxyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.proxyList) == 0 {
		return ProxyInfo{}
	}

	if s.config.Server.Mode == "cycle" {
		s.currentIdx = (s.currentIdx + 1) % len(s.proxyList)
		return s.proxyList[s.currentIdx]
	}

	// 负载均衡模式
	return s.proxyList[s.currentIdx]
}

func (s *Server) Stop() {
	close(s.stopChan)
	s.mu.Lock()
	defer s.mu.Unlock()

	for conn := range s.clients {
		conn.Close()
	}
	s.clients = make(map[net.Conn]struct{})
}

func (s *Server) UpdateProxyList(proxies []ProxyInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.proxyList = proxies
	s.currentIdx = 0

	// 按类型分类代理
	s.httpProxies = []ProxyInfo{}
	s.socks5Proxies = []ProxyInfo{}

	for _, proxy := range proxies {
		if proxy.Type == ProxyTypeSOCKS5 {
			s.socks5Proxies = append(s.socks5Proxies, proxy)
		} else {
			s.httpProxies = append(s.httpProxies, proxy)
		}
	}

	s.httpProxyIndex = 0
	s.socks5ProxyIndex = 0

	log.Printf("Updated proxy list: %d HTTP proxies, %d SOCKS5 proxies",
		len(s.httpProxies), len(s.socks5Proxies))
}

// 处理SOCKS5密码认证
func (s *Server) handlePasswordAuth(conn net.Conn) (string, string, error) {
	// 读取版本和用户名长度
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", fmt.Errorf("读取认证头失败: %v", err)
	}

	// 认证子版本应该是0x01
	if header[0] != 0x01 {
		return "", "", fmt.Errorf("不支持的认证子版本: %d", header[0])
	}

	// 读取用户名
	usernameLen := int(header[1])
	if usernameLen == 0 {
		return "", "", fmt.Errorf("用户名长度为0")
	}

	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return "", "", fmt.Errorf("读取用户名失败: %v", err)
	}

	// 读取密码长度
	passwordLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLenBuf); err != nil {
		return "", "", fmt.Errorf("读取密码长度失败: %v", err)
	}

	passwordLen := int(passwordLenBuf[0])
	if passwordLen == 0 {
		return "", "", fmt.Errorf("密码长度为0")
	}

	// 读取密码
	passwordBytes := make([]byte, passwordLen)
	if _, err := io.ReadFull(conn, passwordBytes); err != nil {
		return "", "", fmt.Errorf("读取密码失败: %v", err)
	}

	usernameStr := string(username)
	passwordStr := string(passwordBytes)

	// 我们接受任何用户名/密码组合
	log.Printf("[SOCKS5] 收到用户认证: 用户名='%s', 密码='%s'", usernameStr, passwordStr)

	// 发送认证成功响应 (0x01 0x00)
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return "", "", fmt.Errorf("发送认证成功响应失败: %v", err)
	}

	return usernameStr, passwordStr, nil
}

// 处理SOCKS5请求
func (s *Server) handleSocks5Request(clientConn net.Conn, sessionID string) {
	// 读取客户端请求
	header := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		log.Printf("[SOCKS5] 读取请求头失败: %v", err)
		return
	}
	log.Printf("[SOCKS5] 收到请求头: 版本=%d, 命令=%d, 保留=%d, 地址类型=%d",
		header[0], header[1], header[2], header[3])

	// 如果请求头的版本不是SOCKS5，我们尝试继续处理
	if header[0] != SOCKS5_VERSION {
		log.Printf("[SOCKS5] 警告：请求头版本 %d 不是标准SOCKS5版本号 %d，尝试继续处理",
			header[0], SOCKS5_VERSION)
	}

	// 只支持CONNECT命令
	if header[1] != SOCKS5_CMD_CONNECT {
		// 不支持的命令
		log.Printf("[SOCKS5] 不支持的命令: %d", header[1])
		s.sendSocks5Response(clientConn, SOCKS5_REP_COMMAND_NOT_SUPPORTED, nil, 0)
		return
	}

	// 解析目标地址
	var dstAddr string
	switch header[3] {
	case SOCKS5_ADDR_IPV4:
		// IPv4地址
		addr := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			log.Printf("[SOCKS5] 读取IPv4地址失败: %v", err)
			return
		}
		dstAddr = net.IP(addr).String()
		log.Printf("[SOCKS5] 目标IPv4地址: %s", dstAddr)

	case SOCKS5_ADDR_DOMAIN:
		// 域名
		lenDomain := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, lenDomain); err != nil {
			log.Printf("[SOCKS5] 读取域名长度失败: %v", err)
			return
		}

		domain := make([]byte, int(lenDomain[0]))
		if _, err := io.ReadFull(clientConn, domain); err != nil {
			log.Printf("[SOCKS5] 读取域名失败: %v", err)
			return
		}
		dstAddr = string(domain)
		log.Printf("[SOCKS5] 目标域名: %s (长度: %d)", dstAddr, lenDomain[0])

	case SOCKS5_ADDR_IPV6:
		// IPv6地址
		addr := make([]byte, 16)
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			log.Printf("[SOCKS5] 读取IPv6地址失败: %v", err)
			return
		}
		dstAddr = net.IP(addr).String()
		log.Printf("[SOCKS5] 目标IPv6地址: %s", dstAddr)

	default:
		log.Printf("[SOCKS5] 不支持的地址类型: %d", header[3])
		s.sendSocks5Response(clientConn, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED, nil, 0)
		return
	}

	// 读取端口
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBytes); err != nil {
		log.Printf("[SOCKS5] 读取端口失败: %v", err)
		return
	}
	dstPort := int(portBytes[0])<<8 | int(portBytes[1])
	log.Printf("[SOCKS5] 目标端口: %d", dstPort)

	// 连接到目标
	dstAddrPort := fmt.Sprintf("%s:%d", dstAddr, dstPort)
	log.Printf("[SOCKS5] 会话 [%s] 连接请求目标: %s", sessionID, dstAddrPort)

	// 总是使用代理模式，DirectConnect设置将被忽略
	// 获取或创建会话
	session := s.getOrCreateSession(sessionID)
	proxy := session.socks5Proxy

	// 如果会话没有分配到SOCKS5代理，则获取一个新的
	if proxy.Host == "" {
		proxy = s.getNextAvailableSocks5Proxy()
		if proxy.Host != "" {
			// 更新会话中的代理
			s.sessionsMutex.Lock()
			session.socks5Proxy = proxy
			s.sessions[sessionID] = session
			s.sessionsMutex.Unlock()
			log.Printf("[SOCKS5] 为会话 [%s] 分配了新的SOCKS5代理: %s", sessionID, proxy.String())
		}
	}

	if proxy.Host == "" {
		log.Println("[SOCKS5] 没有可用的SOCKS5代理")
		s.sendSocks5Response(clientConn, SOCKS5_REP_SERVER_FAILURE, nil, 0)
		return
	}

	log.Printf("[SOCKS5] 会话 [%s] 使用SOCKS5代理: %s", sessionID, proxy.String())
	s.handleSocks5ProxyConnect(clientConn, proxy, dstAddr, dstPort)
}

// getNextAvailableSocks5Proxy 获取下一个可用的SOCKS5代理，优先选择未被使用的代理
func (s *Server) getNextAvailableSocks5Proxy() ProxyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.socks5Proxies) == 0 {
		return ProxyInfo{}
	}

	// 找出当前正在使用的所有SOCKS5代理
	inUseProxies := make(map[string]int) // key: 代理地址，value: 使用次数
	s.sessionsMutex.RLock()
	for _, session := range s.sessions {
		if session.socks5Proxy.Host != "" {
			key := session.socks5Proxy.String()
			inUseProxies[key]++
		}
	}
	s.sessionsMutex.RUnlock()

	// 找到使用次数最少的代理（包括0次）
	var leastUsedProxy ProxyInfo
	minUsageCount := 999999

	// 先尝试找未使用的代理
	for _, proxy := range s.socks5Proxies {
		key := proxy.String()
		count := inUseProxies[key]

		// 如果找到未使用的代理，直接返回
		if count == 0 {
			log.Printf("[SOCKS5] 找到未使用的代理: %s", key)
			return proxy
		}

		// 记录使用次数最少的代理
		if count < minUsageCount {
			minUsageCount = count
			leastUsedProxy = proxy
		}
	}

	// 如果所有代理都已使用，返回使用次数最少的代理
	if leastUsedProxy.Host != "" {
		log.Printf("[SOCKS5] 所有代理都在使用中，复用使用次数最少的代理: %s (使用 %d 次)",
			leastUsedProxy.String(), minUsageCount)
		return leastUsedProxy
	}

	// 如果没有可用代理，使用轮询方式
	log.Printf("[SOCKS5] 无法优化分配，使用轮询方式分配代理")
	s.socks5ProxyIndex = (s.socks5ProxyIndex + 1) % len(s.socks5Proxies)
	return s.socks5Proxies[s.socks5ProxyIndex]
}

// getNextAvailableHttpProxy 获取下一个可用的HTTP代理，优先选择未被使用的代理
func (s *Server) getNextAvailableHttpProxy() ProxyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.httpProxies) == 0 {
		return ProxyInfo{}
	}

	// 找出当前正在使用的所有HTTP代理
	inUseProxies := make(map[string]int) // key: 代理地址，value: 使用次数
	s.sessionsMutex.RLock()
	for _, session := range s.sessions {
		if session.httpProxy.Host != "" {
			key := session.httpProxy.String()
			inUseProxies[key]++
		}
	}
	s.sessionsMutex.RUnlock()

	// 找到使用次数最少的代理（包括0次）
	var leastUsedProxy ProxyInfo
	minUsageCount := 999999

	// 先尝试找未使用的代理
	for _, proxy := range s.httpProxies {
		key := proxy.String()
		count := inUseProxies[key]

		// 如果找到未使用的代理，直接返回
		if count == 0 {
			log.Printf("找到未使用的HTTP代理: %s", key)
			return proxy
		}

		// 记录使用次数最少的代理
		if count < minUsageCount {
			minUsageCount = count
			leastUsedProxy = proxy
		}
	}

	// 如果所有代理都已使用，返回使用次数最少的代理
	if leastUsedProxy.Host != "" {
		log.Printf("所有HTTP代理都在使用中，复用使用次数最少的代理: %s (使用 %d 次)",
			leastUsedProxy.String(), minUsageCount)
		return leastUsedProxy
	}

	// 如果没有可用代理，使用轮询方式
	log.Printf("无法优化分配，使用轮询方式分配HTTP代理")
	s.httpProxyIndex = (s.httpProxyIndex + 1) % len(s.httpProxies)
	return s.httpProxies[s.httpProxyIndex]
}

// 从TCP连接中提取会话ID（主要用于SOCKS5协议）
func (s *Server) extractSessionIDFromConn(conn net.Conn) string {
	// 默认使用客户端IP作为会话ID
	clientIP := "unknown"
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	// 生成包含客户端IP的默认会话ID
	defaultSessionID := fmt.Sprintf("ip-%s", clientIP)
	log.Printf("[SOCKS5] 使用IP作为会话ID: '%s'", defaultSessionID)
	return defaultSessionID
}

// 获取或创建一个会话
func (s *Server) getOrCreateSession(sessionID string) sessionInfo {
	s.sessionsMutex.RLock()
	session, exists := s.sessions[sessionID]
	s.sessionsMutex.RUnlock()

	if exists {
		// 更新最后访问时间
		s.sessionsMutex.Lock()
		session.lastAccess = time.Now()
		s.sessions[sessionID] = session
		s.sessionsMutex.Unlock()
		log.Printf("使用现有会话 [%s]，上次访问时间: %s", sessionID, session.lastAccess.Format("2006-01-02 15:04:05"))
		return session
	}

	// 创建新会话
	newSession := sessionInfo{
		created:    time.Now(),
		lastAccess: time.Now(),
	}

	// 保存会话
	s.sessionsMutex.Lock()
	s.sessions[sessionID] = newSession
	s.sessionsMutex.Unlock()

	log.Printf("创建新会话 [%s]", sessionID)

	return newSession
}

// 清理过期会话
func (s *Server) cleanupSessions() {
	ticker := time.NewTicker(time.Minute * 5) // 每5分钟检查一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			var expiredSessions []string
			var expiration time.Duration = 30 * time.Minute // 默认30分钟

			// 获取配置中的会话过期时间
			if s.config.Server.SessionExpirationMinutes > 0 {
				expiration = time.Duration(s.config.Server.SessionExpirationMinutes) * time.Minute
			}

			s.sessionsMutex.RLock()
			totalSessions := len(s.sessions)
			for id, session := range s.sessions {
				// 会话过期时间
				if now.Sub(session.lastAccess) > expiration {
					expiredSessions = append(expiredSessions, id)
				}
			}
			s.sessionsMutex.RUnlock()

			if len(expiredSessions) > 0 {
				s.sessionsMutex.Lock()
				for _, id := range expiredSessions {
					delete(s.sessions, id)
				}
				s.sessionsMutex.Unlock()

				log.Printf("已清理 %d 个过期会话（超过%d分钟未活动），当前剩余 %d 个会话",
					len(expiredSessions), int(expiration.Minutes()), totalSessions-len(expiredSessions))
			} else if totalSessions > 0 {
				log.Printf("当前共有 %d 个活跃会话，无过期会话", totalSessions)
			}

		case <-s.stopChan:
			return
		}
	}
}
