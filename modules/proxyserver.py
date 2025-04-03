import asyncio, httpx, logging, re, socket, struct, time, base64, random, os
from modules.modules import get_message, load_ip_list
from asyncio import TimeoutError
from itertools import cycle
from config import getip
from configparser import ConfigParser
from modules.user_ip_manager import UserIPManager


def load_proxies(file_path='ip.txt'):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if '://' in line]

def validate_proxy(proxy):
    pattern = re.compile(r'^(?P<scheme>socks5|http|https)://(?:(?P<auth>[^@]+)@)?(?P<host>[^:]+):(?P<port>\d+)$')
    match = pattern.match(proxy)
    if not match:
        return False
    
    port = int(match.group('port'))
    return 0 < port < 65536

class AsyncProxyServer:
    def __init__(self, config):
        self.config = config
        self._init_config_values(config)
        self._init_server_state()
        self._init_connection_settings()
        self.proxy_failure_lock = asyncio.Lock()

    def _init_config_values(self, config):
        self.port = int(config.get('port', '1080'))
        self.mode = config.get('mode', 'cycle')
        self.interval = int(config.get('interval', '300'))
        self.language = config.get('language', 'cn')
        self.use_getip = config.get('use_getip', 'False').lower() == 'true'
        self.check_proxies = config.get('check_proxies', 'True').lower() == 'true'
        
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.proxy_username = config.get('proxy_username', '')
        self.proxy_password = config.get('proxy_password', '')
        
        self.users = {}
        if 'Users' in config:
            self.users = dict(config['Users'].items())
        self.auth_required = bool(self.users)
        
        # 用户IP管理配置
        self.use_session_ip = config.get('use_session_ip', 'False').lower() == 'true'
        self.session_duration = int(config.get('session_duration', '1800'))  # 默认30分钟
        self.ip_pool_file = config.get('ip_pool_file', '')
        
        # 如果启用会话IP管理，初始化UserIPManager
        if self.use_session_ip:
            self.user_ip_manager = UserIPManager(
                ip_pool_file=self.ip_pool_file if self.ip_pool_file else None,
                session_duration=self.session_duration
            )
        
        self.proxy_file = os.path.join('config', os.path.basename(config.get('proxy_file', 'ip.txt')))
        self.whitelist_file = os.path.join('config', os.path.basename(config.get('whitelist_file', 'whitelist.txt')))
        self.blacklist_file = os.path.join('config', os.path.basename(config.get('blacklist_file', 'blacklist.txt')))
        self.ip_auth_priority = config.get('ip_auth_priority', 'whitelist')
        
        self.test_url = config.get('test_url', 'https://www.baidu.com')
        self.whitelist = load_ip_list(self.whitelist_file)
        self.blacklist = load_ip_list(self.blacklist_file)
        
        if self.use_getip:
            self.getip_url = config.get('getip_url', '')
            
        self.switching_proxy = False
        self.last_switch_attempt = 0
        self.switch_cooldown = 5  
        self.proxy_check_cache = {}
        self.last_check_time = {}
        self.proxy_check_ttl = 60
        self.check_cooldown = 10
        self.connected_clients = set()
        self.last_proxy_failure_time = 0  
        self.proxy_failure_cooldown = 3  

    def _init_server_state(self):
        self.running = False
        self.stop_server = False
        self.server_instance = None
        self.tasks = set()
        self.last_switch_time = time.time()
        self.proxy_cycle = None
        self.current_proxy = None
        self.proxies = []
        self.known_clients = set()
        
        if not self.use_getip:
            self.proxies = self._load_file_proxies()
            if self.proxies:
                self.proxy_cycle = cycle(self.proxies)
                self.current_proxy = next(self.proxy_cycle)

    def _init_connection_settings(self):
        self.buffer_size = 8192
        self.connection_timeout = 30
        self.read_timeout = 60
        self.max_concurrent_requests = 1000
        self.request_semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        self.connection_pool = {}
        self.max_pool_size = 500 
        self.client_pool = {}
        self.client_pool_lock = asyncio.Lock() 
        self.proxy_pool = {} 
        self.active_connections = set() 

    def _update_config_values(self, new_config):
        self._init_config_values(new_config)
        self.last_switch_time = time.time()
        
        self.last_switch_attempt = 0

    def _handle_mode_change(self):
        
        self.last_switch_attempt = 0
        
        if self.use_getip:
            self.proxies = []
            self.proxy_cycle = None
            self.current_proxy = None
            logging.info(get_message('api_mode_notice', self.language))
        else:
            logging.info(f"切换到{'负载均衡' if self.mode == 'loadbalance' else '循环模式'}模式，从 {self.proxy_file} 加载代理列表")
            self.proxies = self._load_file_proxies()
            logging.info(f"加载到 {len(self.proxies)} 个代理")
            
            if self.proxies:
                self.proxy_cycle = cycle(self.proxies)
                self.current_proxy = next(self.proxy_cycle)
                logging.info(f"当前使用代理: {self.current_proxy}")
                
                if self.check_proxies and self.mode != 'loadbalance':  
                    try:
                        
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            asyncio.create_task(self._check_proxies_wrapper())
                        else:
                            loop.run_until_complete(self._check_proxies())
                    except Exception as e:
                        logging.error(f"检查代理时出错: {str(e)}")
            else:
                logging.error(f"从文件 {self.proxy_file} 加载代理失败，请检查文件是否存在且包含有效代理")

    async def _check_proxies_wrapper(self):
        """包装 _check_proxies 方法，用于在已运行的事件循环中调用"""
        await self._check_proxies()

    def _reload_proxies(self):
        
        self.last_switch_attempt = 0
        
        logging.info(f"重新加载代理列表文件 {self.proxy_file}")
        self.proxies = self._load_file_proxies()
        logging.info(f"加载到 {len(self.proxies)} 个代理")
        
        if self.proxies:
            self.proxy_cycle = cycle(self.proxies)
            self.current_proxy = next(self.proxy_cycle)
            logging.info(f"当前使用代理: {self.current_proxy}")
            
            if self.check_proxies:
                try:
                    
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(self._check_proxies_wrapper())
                    else:
                        loop.run_until_complete(self._check_proxies())
                except Exception as e:
                    logging.error(f"检查代理时出错: {str(e)}")
        else:
            logging.error(f"从文件 {self.proxy_file} 加载代理失败，请检查文件是否存在且包含有效代理")

    async def _check_proxies(self):
        from modules.modules import check_proxies
        valid_proxies = await check_proxies(self.proxies, test_url=self.test_url)
        if valid_proxies:
            self.proxies = valid_proxies
            self.proxy_cycle = cycle(valid_proxies)
            self.current_proxy = next(self.proxy_cycle)

    def _load_file_proxies(self):
        try:
            proxy_file = os.path.join('config', os.path.basename(self.proxy_file))
            if os.path.exists(proxy_file):
                with open(proxy_file, 'r', encoding='utf-8') as f:
                    proxies = [line.strip() for line in f if line.strip()]
                return proxies
            else:
                logging.error(get_message('proxy_file_not_found', self.language, proxy_file))
                return []
        except Exception as e:
            logging.error(get_message('load_proxy_file_error', self.language, str(e)))
            return []

    async def start(self):
        if not self.running:
            self.stop_server = False
            self.running = True
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                sock.bind(('0.0.0.0', self.port))
                
                loop = asyncio.get_event_loop()
                if hasattr(loop, 'set_default_executor'):
                    import concurrent.futures
                    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(32, os.cpu_count() * 4))
                    loop.set_default_executor(executor)
                
                server = await asyncio.start_server(
                    self.handle_client,
                    sock=sock,
                    backlog=2048,      
                    limit=32768,       
                )
                
                self.server_instance = server
                logging.info(get_message('server_running', self.language, '0.0.0.0', self.port))
                
                self.tasks.add(asyncio.create_task(self.cleanup_clients()))
                self.tasks.add(asyncio.create_task(self._cleanup_pool()))
                self.tasks.add(asyncio.create_task(self.cleanup_disconnected_ips()))
                
                # 如果启用了会话IP管理，添加定期清理过期会话的任务
                if self.use_session_ip:
                    self.tasks.add(asyncio.create_task(self._cleanup_expired_sessions()))
                
                if hasattr(os, 'sched_setaffinity'):
                    try:
                        os.sched_setaffinity(0, range(os.cpu_count()))
                    except:
                        pass
                
                async with server:
                    await server.serve_forever()
                    
            except Exception as e:
                if not self.stop_server:
                    logging.error(get_message('server_start_error', self.language, str(e)))
            finally:
                self.running = False
                self.server_instance = None

    async def stop(self):
        if self.running:
            self.stop_server = True
            if self.server_instance:
                self.server_instance.close()
                await self.server_instance.wait_closed()
                self.server_instance = None
            
            for task in self.tasks:
                task.cancel()
            if self.tasks:
                await asyncio.gather(*self.tasks, return_exceptions=True)
            self.tasks.clear()
            
            self.running = False
            logging.info(get_message('server_shutting_down', self.language))

    async def get_next_proxy(self):
        try:
            current_time = time.time()
            
            
            if self.mode == 'loadbalance' and self.proxies:
                if not self.switching_proxy:
                    try:
                        self.switching_proxy = True
                        self.last_switch_attempt = current_time  
                        
                        if not self.use_getip:
                            
                            if not self.proxy_cycle:
                                self.proxy_cycle = cycle(self.proxies)
                            self.current_proxy = next(self.proxy_cycle)
                            logging.info(f"负载均衡模式选择代理: {self.current_proxy}")
                        else:
                            
                            await self.get_proxy()
                    finally:
                        self.switching_proxy = False
                return self.current_proxy
            
            
            if self.switching_proxy or (current_time - self.last_switch_attempt < self.switch_cooldown):
                return self.current_proxy
            
            if self.interval > 0 and current_time - self.last_switch_time >= self.interval or \
               (self.use_getip and not self.current_proxy):
                try:
                    self.switching_proxy = True
                    self.last_switch_attempt = current_time
                    old_proxy = self.current_proxy
                    
                    await self.get_proxy()

                finally:
                    self.switching_proxy = False
            
            return self.current_proxy
                    
        except Exception as e:
            logging.error(get_message('proxy_switch_error', self.language, str(e)))
            self.switching_proxy = False
            return self.current_proxy

    async def _load_getip_proxy(self):
        valid_proxies = []
        for _ in range(4):
            new_ip = getip.newip()
            if validate_proxy(new_ip):
                valid_proxies.append(new_ip)
                break
        else:
            logging.error(get_message('multiple_proxy_fail', self.language))
            exit(1)
        return valid_proxies[0]

    def time_until_next_switch(self):
        return float('inf') if self.mode == 'loadbalance' else max(0, self.interval - (time.time() - self.last_switch_time))

    def check_ip_auth(self, ip):
        try:
            if not self.whitelist and not self.blacklist:
                return True

            if self.ip_auth_priority == 'whitelist':
                if self.whitelist:
                    if ip in self.whitelist:
                        return True
                    return False
                if self.blacklist:
                    return ip not in self.blacklist
                return True
            else:
                if ip in self.blacklist:
                    return False
                if self.whitelist:
                    return ip in self.whitelist
                return True
        except Exception as e:
            logging.error(get_message('whitelist_error', self.language, str(e)))
            return False

    def _authenticate(self, headers):
        """验证用户身份，支持用户名密码和会话ID认证"""
        if not self.auth_required:
            return True
            
        auth_header = headers.get('Proxy-Authorization', '')
        if not auth_header:
            logging.debug("Missing Proxy-Authorization header")
            return False
            
        try:
            auth_type, auth_data = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                logging.debug(f"Unsupported auth type: {auth_type}")
                return False
                
            # 解码认证数据
            auth_decoded = base64.b64decode(auth_data).decode('utf-8')
            
            # 支持两种认证方式: 1. 用户名-参数格式  2. 用户名:密码格式
            if self.use_session_ip and '-' in auth_decoded:
                # 使用新的参数解析方法
                username, params = self.user_ip_manager.parse_auth_params(auth_decoded)
                
                # 验证用户名是否在用户列表中
                if not username or username not in self.users:
                    logging.debug(f"User not found or invalid: {username}")
                    return False
                
                # 提取会话ID (如果存在)
                session_id = self.user_ip_manager.get_session_id_from_params(username, params)
                
                if not session_id and 'session_id' in params:
                    # 兼容旧方式，如果没有组合会话ID但有session_id参数
                    session_id = f"{username}_{params['session_id']}"
                
                if session_id:
                    # 为该会话分配一个IP（或获取已分配的IP）
                    user_ip = self.user_ip_manager.get_user_ip(username, session_id)
                    logging.info(f"用户 {username} 认证字符串 [{auth_decoded}] 参数 {params} 会话ID [{session_id}] 使用IP: {user_ip}")
                    
                    # 认证成功
                    return True
                else:
                    logging.debug(f"No session_id parameter found in auth string: {auth_decoded}")
            
            # 标准用户名密码认证
            if ':' in auth_decoded:
                username, password = auth_decoded.split(':', 1)
                if username in self.users and self.users[username] == password:
                    return True
                else:
                    logging.debug(f"Invalid credentials for user: {username}")
            
            return False
                
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return False

    async def _close_connection(self, writer):
        try:
            if writer and not writer.is_closing():
                writer.write_eof()
                await writer.drain()
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            pass

    async def handle_client(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        peername = writer.get_extra_info('peername')
        if peername:
            self.active_connections.add(peername)
        try:
            peername = writer.get_extra_info('peername')
            if peername:
                client_ip = peername[0]
                if not self.check_ip_auth(client_ip):
                    logging.warning(get_message('unauthorized_ip', self.language, client_ip))
                    writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                    await writer.drain()
                    return
                
            first_byte = await reader.read(1)
            if not first_byte:
                return
                
            if first_byte == b'\x05':
                await self.handle_socks5_connection(reader, writer)
            else:
                await self._handle_client_impl(reader, writer, first_byte)
                
        except Exception as e:
            logging.error(get_message('client_handle_error', self.language, e))
        finally:
            if peername:
                self.active_connections.discard(peername)
            await self._close_connection(writer)
            self.tasks.remove(task)

    async def _pipe(self, reader, writer):
        try:
            while True:
                try:
                    data = await reader.read(self.buffer_size)
                    if not data:
                        break
                    try:
                        writer.write(data)
                        await writer.drain()
                    except (ConnectionError, ConnectionResetError):
                        
                        await self.handle_proxy_failure()
                        break
                except (ConnectionError, ConnectionResetError):
                    
                    await self.handle_proxy_failure()
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            
            await self.handle_proxy_failure()
            pass
        finally:
            await self._close_connection(writer)

    def _split_proxy_auth(self, proxy_addr):
        match = re.match(r'((?P<username>.+?):(?P<password>.+?)@)?(?P<host>.+)', proxy_addr)
        if match:
            username = match.group('username')
            password = match.group('password')
            host = match.group('host')
            if username and password:
                return f"{username}:{password}", host
        return None, proxy_addr

    async def _create_client(self, proxy):
        proxy_type, proxy_addr = proxy.split('://')
        proxy_auth = None
        
        if '@' in proxy_addr:
            auth, proxy_addr = proxy_addr.split('@')
            proxy_auth = auth
        
        if proxy_auth:
            proxy_url = f"{proxy_type}://{proxy_auth}@{proxy_addr}"
        else:
            proxy_url = f"{proxy_type}://{proxy_addr}"
            
        import logging as httpx_logging
        httpx_logging.getLogger("httpx").setLevel(logging.WARNING)
        httpx_logging.getLogger("hpack").setLevel(logging.WARNING)
        httpx_logging.getLogger("h2").setLevel(logging.WARNING)
            
        return httpx.AsyncClient(
            proxies={"all://": proxy_url},
            limits=httpx.Limits(
                max_keepalive_connections=100,
                max_connections=1000,
                keepalive_expiry=30
            ),
            timeout=30.0,
            http2=True,
            verify=False,
            follow_redirects=True
        )

    async def _cleanup_connections(self):
        current_time = time.time()
        expired_keys = [
            key for key, client in self.connection_pool.items()
            if current_time - client._last_used > 30
        ]
        for key in expired_keys:
            client = self.connection_pool.pop(key)
            await client.aclose()

    async def handle_socks5_connection(self, reader, writer):
        try:
            nmethods = ord(await reader.readexactly(1))
            await reader.readexactly(nmethods)

            writer.write(b'\x05\x02' if self.auth_required else b'\x05\x00')
            await writer.drain()

            if self.auth_required:
                auth_version = await reader.readexactly(1)
                if auth_version != b'\x01':
                    writer.close()
                    return
                
                ulen = ord(await reader.readexactly(1))
                username = await reader.readexactly(ulen)
                plen = ord(await reader.readexactly(1))
                password = await reader.readexactly(plen)

                username = username.decode()
                password = password.decode()
                
                if username in self.users and self.users[username] == password:
                    peername = writer.get_extra_info('peername')
                    if peername:
                        client_ip = peername[0]
                        client_key = (client_ip, username)
                        if client_key not in self.known_clients:
                            self.known_clients.add(client_key)
                            logging.info(get_message('new_client_connect', self.language, client_ip, f"{username}:{password}"))
                else:
                    writer.write(b'\x01\x01')
                    await writer.drain()
                    writer.close()
                    return

                writer.write(b'\x01\x00')
                await writer.drain()

            version, cmd, _, atyp = struct.unpack('!BBBB', await reader.readexactly(4))
            if cmd != 1: 
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

            if atyp == 1: 
                dst_addr = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                addr_len = ord(await reader.readexactly(1))
                dst_addr = (await reader.readexactly(addr_len)).decode()
            elif atyp == 4: 
                dst_addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

            dst_port = struct.unpack('!H', await reader.readexactly(2))[0]

            max_retries = 1
            retry_count = 0
            last_error = None

            while retry_count < max_retries:
                try:
                    proxy = await self.get_next_proxy()
                    if not proxy:
                        raise Exception("No proxy available")

                    proxy_type, proxy_addr = proxy.split('://')
                    proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
                    proxy_host, proxy_port = proxy_host_port.split(':')
                    proxy_port = int(proxy_port)

                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(proxy_host, proxy_port),
                        timeout=10
                    )

                    if proxy_type == 'socks5':
                        await self._initiate_socks5(remote_reader, remote_writer, dst_addr, dst_port)
                    elif proxy_type in ['http', 'https']:
                        await self._initiate_http(remote_reader, remote_writer, dst_addr, dst_port, proxy_auth)

                    writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()

                    await asyncio.gather(
                        self._pipe(reader, remote_writer),
                        self._pipe(remote_reader, writer)
                    )
                    
                    return

                except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError) as e:
                    last_error = e
                    logging.warning(get_message('request_retry', self.language, max_retries - retry_count - 1))
                    await self.handle_proxy_failure()
                    retry_count += 1
                    if retry_count < max_retries:
                        await asyncio.sleep(1)
                        continue
                    
                except Exception as e:
                    last_error = e
                    logging.error(get_message('socks5_connection_error', self.language, str(e)))
                    await self.handle_proxy_failure()
                    retry_count += 1
                    if retry_count < max_retries:
                        await asyncio.sleep(1)
                        continue

            #if last_error:
                #logging.error(get_message('all_retries_failed', self.language, str(last_error)))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

        except Exception as e:
            logging.error(get_message('socks5_connection_error', self.language, str(e)))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

    async def _initiate_socks5(self, remote_reader, remote_writer, dst_addr, dst_port):
        try:
            auth = None
            proxy_type, proxy_addr = self.current_proxy.split('://')
            if '@' in proxy_addr:
                auth, _ = proxy_addr.split('@')

            if auth:
                remote_writer.write(b'\x05\x02\x00\x02')
            else:
                remote_writer.write(b'\x05\x01\x00')
                
            await remote_writer.drain()
            
            try:
                auth_method = await asyncio.wait_for(
                    remote_reader.readexactly(2),
                    timeout=10
                )
                if auth_method[0] != 0x05:
                    raise Exception("Invalid SOCKS5 proxy response")
                    
                if auth_method[1] == 0x02 and auth:
                    username, password = auth.split(':')
                    auth_packet = bytes([0x01, len(username)]) + username.encode() + bytes([len(password)]) + password.encode()
                    remote_writer.write(auth_packet)
                    await remote_writer.drain()
                    
                    auth_response = await asyncio.wait_for(
                        remote_reader.readexactly(2),
                        timeout=10
                    )
                    if auth_response[1] != 0x00:
                        raise Exception("Authentication failed")

                if isinstance(dst_addr, str):
                    remote_writer.write(b'\x05\x01\x00\x03' + len(dst_addr).to_bytes(1, 'big') + 
                                      dst_addr.encode() + dst_port.to_bytes(2, 'big'))
                else:
                    remote_writer.write(b'\x05\x01\x00\x01' + socket.inet_aton(dst_addr) + 
                                      dst_port.to_bytes(2, 'big'))
                
                await remote_writer.drain()
                
                response = await asyncio.wait_for(
                    remote_reader.readexactly(4),
                    timeout=10
                )
                if response[1] != 0x00:
                    error_codes = {
                        0x01: "General failure",
                        0x02: "Connection not allowed",
                        0x03: "Network unreachable",
                        0x04: "Host unreachable",
                        0x05: "Connection refused",
                        0x06: "TTL expired",
                        0x07: "Command not supported",
                        0x08: "Address type not supported"
                    }
                    error_msg = error_codes.get(response[1], f"Unknown error code {response[1]}")
                    raise Exception(f"Connection failed: {error_msg}")

                if response[3] == 0x01:
                    await asyncio.wait_for(
                        remote_reader.readexactly(6),
                        timeout=10
                    )
                elif response[3] == 0x03:  
                    domain_len = (await asyncio.wait_for(
                        remote_reader.readexactly(1),
                        timeout=10
                    ))[0]
                    await asyncio.wait_for(
                        remote_reader.readexactly(domain_len + 2),
                        timeout=10
                    )
                elif response[3] == 0x04: 
                    await asyncio.wait_for(
                        remote_reader.readexactly(18),
                        timeout=10
                    )
                else:
                    raise Exception(f"Unsupported address type: {response[3]}")
                    
            except asyncio.TimeoutError:
                raise Exception("SOCKS5 proxy response timeout")
            except Exception as e:
                raise Exception(f"SOCKS5 protocol error: {str(e)}")
                
        except Exception as e:
            if isinstance(e, asyncio.TimeoutError):
                raise Exception("SOCKS5 connection timeout")
            elif "Connection refused" in str(e):
                raise Exception("SOCKS5 connection refused")
            else:
                raise Exception(f"SOCKS5 initialization failed: {str(e)}")

    async def _initiate_http(self, remote_reader, remote_writer, dst_addr, dst_port, proxy_auth):
        connect_request = f'CONNECT {dst_addr}:{dst_port} HTTP/1.1\r\nHost: {dst_addr}:{dst_port}\r\n'
        if proxy_auth:
            connect_request += f'Proxy-Authorization: Basic {base64.b64encode(proxy_auth.encode()).decode()}\r\n'
        connect_request += '\r\n'
        remote_writer.write(connect_request.encode())
        await remote_writer.drain()
        
        while True:
            line = await remote_reader.readline()
            if line == b'\r\n':
                break

    async def _handle_client_impl(self, reader, writer, first_byte):
        try:
            peername = writer.get_extra_info('peername')
            client_info = f"{peername[0]}:{peername[1]}" if peername else "未知客户端"
            
            if peername:
                client_ip = peername[0]
                if not self.check_ip_auth(client_ip):
                    logging.warning(get_message('unauthorized_ip', self.language, client_ip))
                    writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                    await writer.drain()
                    return

            request_line = first_byte + await reader.readline()
            if not request_line:
                return

            try:
                method, path, _ = request_line.decode('utf-8', errors='ignore').split()
            except (ValueError, UnicodeDecodeError) as e:
                return

            headers = {}
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    break
                if line == b'':
                    return
                try:
                    name, value = line.decode('utf-8', errors='ignore').strip().split(': ', 1)
                    headers[name.lower()] = value
                except ValueError:
                    continue

            if self.auth_required:
                auth_result = self._authenticate(headers)
                if not auth_result:
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                    await writer.drain()
                    return
                elif isinstance(auth_result, tuple):
                    username, password = auth_result
                    peername = writer.get_extra_info('peername')
                    if peername:
                        client_ip = peername[0]
                        client_key = (client_ip, username)
                        if client_key not in self.known_clients:
                            self.known_clients.add(client_key)
                            logging.info(get_message('new_client_connect', self.language, client_ip, f"{username}:{password}"))

            # 检查认证并获取会话ID和参数
            is_authenticated, session_id, params = await self._authenticate_with_session(headers)
            if not is_authenticated:
                writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                await writer.drain()
                return

            if method == 'CONNECT':
                await self._handle_connect(path, reader, writer, session_id, params)
            else:
                await self._handle_request(method, path, headers, reader, writer)

        except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
            return
        except asyncio.CancelledError:
            return
        except Exception as e:
            if not isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError, 
                                asyncio.CancelledError, asyncio.TimeoutError)):
                logging.error(get_message('client_request_error', self.language, str(e)))

    async def _handle_request(self, method, path, headers, reader, writer):
        """处理HTTP请求"""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        
        # 检查认证并获取会话ID和参数
        is_authenticated, session_id, params = await self._authenticate_with_session(headers)
        if not is_authenticated:
            response = (
                'HTTP/1.1 407 Proxy Authentication Required\r\n'
                'Proxy-Authenticate: Basic realm="ProxyCt"\r\n'
                'Content-Length: 0\r\n'
                '\r\n'
            )
            writer.write(response.encode())
            await writer.drain()
            return
        
        # 根据请求方法处理
        if method == 'CONNECT':
            await self._handle_connect(path, reader, writer, session_id, params)
        else:
            # 获取代理（可能是会话特定的）
            if self.use_session_ip and session_id:
                proxy = await self.get_session_proxy(session_id, client_ip, params)
            else:
                proxy = await self.get_proxy()
            
            if not proxy:
                response = 'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'
                writer.write(response.encode())
                await writer.drain()
                return

            async with self.request_semaphore:
                max_retries = 1 
                retry_count = 0
                last_error = None
                
                while retry_count < max_retries:
                    try:
                        client = await self._get_client(proxy)
                        
                        proxy_headers = headers.copy()
                        proxy_type, proxy_addr = proxy.split('://')
                        if '@' in proxy_addr:
                            auth, _ = proxy_addr.split('@')
                            auth_header = f'Basic {base64.b64encode(auth.encode()).decode()}'
                            proxy_headers['Proxy-Authorization'] = auth_header

                        try:
                            async with client.stream(
                                method,
                                path,
                                headers=proxy_headers,
                                content=reader,
                                timeout=30.0
                            ) as response:
                                writer.write(f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n'.encode())
                                
                                for header_name, header_value in response.headers.items():
                                    if header_name.lower() not in ('transfer-encoding', 'connection'):
                                        writer.write(f'{header_name}: {header_value}\r\n'.encode())
                                writer.write(b'\r\n')
                                
                                try:
                                    async for chunk in response.aiter_bytes(chunk_size=self.buffer_size):
                                        if not chunk:
                                            break
                                        try:
                                            writer.write(chunk)
                                            if len(chunk) >= self.buffer_size:
                                                await writer.drain()
                                        except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
                                            return
                                        except Exception:
                                            break 

                                    await writer.drain()
                                except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
                                    return 
                                except Exception:
                                    pass
                                
                                return

                        except httpx.RequestError:
                            await self.handle_proxy_failure()
                            last_error = "Request Error"
                            retry_count += 1
                            if retry_count < max_retries:
                                logging.warning(get_message('request_retry', self.language, max_retries - retry_count))
                                await asyncio.sleep(1)
                                continue
                            # 达到最大重试次数
                            break
                        except Exception as e:
                            if isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError)):
                                await self.handle_proxy_failure()
                                last_error = str(e)
                                retry_count += 1
                                if retry_count < max_retries:
                                    logging.warning(get_message('request_retry', self.language, max_retries - retry_count))
                                    await asyncio.sleep(1)
                                    continue
                                # 达到最大重试次数
                                break
                            writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                            await writer.drain()
                            return

                    except httpx.HTTPError:
                        await self.handle_proxy_failure()
                        last_error = "HTTP Error"
                        retry_count += 1
                        if retry_count < max_retries:
                            logging.warning(get_message('request_retry', self.language, max_retries - retry_count))
                            await asyncio.sleep(1)
                            continue
                        # 达到最大重试次数
                        break
                    except Exception as e:
                        if isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError)):
                            await self.handle_proxy_failure()
                            last_error = str(e)
                            retry_count += 1
                            if retry_count < max_retries:
                                logging.warning(get_message('request_retry', self.language, max_retries - retry_count))
                                await asyncio.sleep(1)
                                continue
                            # 达到最大重试次数
                            break
                        writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                        await writer.drain()
                        return

                # 如果到达这里，表示达到最大重试次数并且失败
                if last_error:
                    logging.error(get_message('all_retries_failed', self.language, last_error))
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()

    async def _handle_connect(self, path, reader, writer, session_id=None, params=None):
        """处理CONNECT请求"""
        try:
            host, port = path.split(':', 1)
            port = int(port)
            
            client_addr = writer.get_extra_info('peername')
            client_ip = client_addr[0] if client_addr else 'unknown'
            
            # 获取代理（可能是会话特定的）
            if self.use_session_ip and session_id:
                proxy = await self.get_session_proxy(session_id, client_ip, params)
            else:
                proxy = await self.get_proxy()
            
            if not proxy:
                response = 'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'
                writer.write(response.encode())
                await writer.drain()
                return

            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)
            
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_host, proxy_port),
                timeout=10
            )

            if proxy_type == 'http':
                connect_headers = [f'CONNECT {host}:{port} HTTP/1.1', f'Host: {host}:{port}']
                if proxy_auth:
                    auth_header = f'Proxy-Authorization: Basic {base64.b64encode(proxy_auth.encode()).decode()}'
                    connect_headers.append(auth_header)
                connect_request = '\r\n'.join(connect_headers) + '\r\n\r\n'
                remote_writer.write(connect_request.encode())
                await remote_writer.drain()
                response = await remote_reader.readline()
                if not response.startswith(b'HTTP/1.1 200'):
                    
                    await self.handle_proxy_failure()
                    last_error = f"Bad Gateway: {response.decode('utf-8', errors='ignore')}"
                    writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    await writer.drain()
                    return
                while (await remote_reader.readline()) != b'\r\n':
                    pass
            elif proxy_type == 'socks5':
                remote_writer.write(b'\x05\x01\x00')
                await remote_writer.drain()
                if (await remote_reader.read(2))[1] == 0:
                    remote_writer.write(b'\x05\x01\x00\x03' + len(host).to_bytes(1, 'big') + host.encode() + port.to_bytes(2, 'big'))
                await remote_writer.drain()
                if (await remote_reader.read(10))[1] != 0:
                    
                    await self.handle_proxy_failure()
                    last_error = "SOCKS5 connection failed"
                    writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    await writer.drain()
                    return
            else:
                raise Exception("Unsupported proxy type")

            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            await asyncio.gather(
                self._pipe(reader, remote_writer),
                self._pipe(remote_reader, writer)
            )
            
            return
            
        except Exception as e:
            logging.error(get_message('connect_error', self.language, str(e)))
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            await writer.drain()

    async def _authenticate_with_session(self, headers):
        """从认证头中提取会话ID和其他参数"""
        if not self.auth_required:
            return True, None, {}
            
        auth_header = headers.get('Proxy-Authorization', '')
        if not auth_header:
            return False, None, {}
            
        try:
            auth_type, auth_data = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False, None, {}
                
            # 解码认证数据
            auth_decoded = base64.b64decode(auth_data).decode('utf-8')
            
            # 检查是否包含参数分隔符
            if self.use_session_ip and '-' in auth_decoded:
                # 解析参数
                username, params = self.user_ip_manager.parse_auth_params(auth_decoded)
                
                # 验证用户名
                if not username or username not in self.users:
                    return False, None, {}
                
                # 获取会话ID
                session_id = self.user_ip_manager.get_session_id_from_params(username, params)
                
                if not session_id and 'session_id' in params:
                    # 兼容旧方式
                    session_id = f"{username}_{params['session_id']}"
                
                return True, session_id, params
            
            # 如果是标准用户名:密码格式
            if ':' in auth_decoded:
                username, password = auth_decoded.split(':', 1)
                if username in self.users and self.users[username] == password:
                    return True, None, {}
            
            # 认证失败或不包含会话信息
            return False, None, {}
                
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return False, None, {}

    async def get_session_proxy(self, session_id, client_ip=None, params=None):
        """
        基于会话ID获取代理IP
        
        Args:
            session_id: 用户会话ID
            client_ip: 客户端IP地址，用于日志
            params: 可选的参数字典，包含其他从认证中解析的参数
            
        Returns:
            str: 分配给会话的代理IP
        """
        if not self.use_session_ip or not hasattr(self, 'user_ip_manager'):
            return await self.get_proxy()
            
        # 如果session_id为空，使用默认代理
        if not session_id:
            return await self.get_proxy()
        
        # 不需要再解析session_id，因为现在它已经是处理过的格式
        # 从session_id中提取用户名（如果有必要）
        username = session_id.split("_")[0] if "_" in session_id else ""
            
        # 获取分配给此会话的IP
        session_ip = self.user_ip_manager.get_user_ip(username, session_id)
        
        if client_ip:
            if params:
                logging.info(f"客户端 {client_ip} 的会话 [{session_id}] 参数 {params} 使用IP: {session_ip}")
            else:
                logging.info(f"客户端 {client_ip} 的会话 [{session_id}] 使用IP: {session_ip}")
            
        # 返回形如 http://IP:PORT 的代理地址
        proxy_type = "http"  # 默认使用HTTP代理类型
        proxy_port = "8080"  # 默认端口
        
        # 如果当前代理不为空，可以从中提取代理类型
        if self.current_proxy:
            match = re.match(r'^(https?|socks5)://', self.current_proxy)
            if match:
                proxy_type = match.group(1)
                
            # 尝试提取端口
            port_match = re.search(r':(\d+)$', self.current_proxy)
            if port_match:
                proxy_port = port_match.group(1)
        
        return f"{proxy_type}://{session_ip}:{proxy_port}"

    async def handle_proxy_failure(self):
        
        if not self.check_proxies:
            return
            
        
        current_time = time.time()
        if current_time - self.last_proxy_failure_time < self.proxy_failure_cooldown:
            return
            
        
        if self.switching_proxy:
            return
            
        try:
            if not self.proxy_failure_lock.locked():
                async with self.proxy_failure_lock:
                    if (current_time - self.last_proxy_failure_time < self.proxy_failure_cooldown or 
                        self.switching_proxy):
                        return
                        
                    
                    self.last_proxy_failure_time = current_time
                    
                    try:
                        is_valid = await self.check_current_proxy()
                        
                        if not is_valid:
                            #logging.warning(get_message('proxy_failure', self.language, self.current_proxy))
                            await self.switch_proxy()
                    except Exception as e:
                        logging.error(get_message('proxy_check_error', self.language, str(e)))
        except Exception as e:
            logging.error(f"代理失败处理出错: {str(e)}")

    async def switch_proxy(self):
        try:
            current_time = time.time()
            
            
            if current_time - self.last_switch_attempt < self.switch_cooldown:
                return False
                
            
            if self.switching_proxy:
                return False
                
            self.switching_proxy = True
            self.last_switch_attempt = current_time
            old_proxy = self.current_proxy
            
            temp_current_proxy = self.current_proxy
            
            await self.get_proxy()
            
            
            if temp_current_proxy != self.current_proxy:
                self._log_proxy_switch(old_proxy, self.current_proxy)
                
                self.last_proxy_failure_time = current_time
                return True
                
            return False
            
        except Exception as e:
            logging.error(get_message('proxy_switch_error', self.language, str(e)))
            return False
        finally:
            
            self.switching_proxy = False

    async def check_current_proxy(self):
        try:
            proxy = self.current_proxy
            if not proxy:
                return False
                
            current_time = time.time()

            
            if not self.check_proxies:
                return True

            
            if proxy in self.last_check_time:
                if current_time - self.last_check_time[proxy] < self.check_cooldown:
                    return self.proxy_check_cache.get(proxy, (current_time, True))[1]

            if proxy in self.proxy_check_cache:
                cache_time, is_valid = self.proxy_check_cache[proxy]
                if current_time - cache_time < self.proxy_check_ttl:
                    return is_valid

            self.last_check_time[proxy] = current_time
            test_url = self.config.get('test_url', 'https://www.baidu.com')
            
            
            try:
                from modules.modules import check_proxy
                
                is_valid = await check_proxy(proxy, test_url)
                logging.warning(f"代理检查结果: {proxy} - {'有效' if is_valid else '无效'}")
            except Exception as e:
                logging.error(f"代理检测错误: {proxy} - {str(e)}")
                is_valid = False
                
            
            self.proxy_check_cache[proxy] = (current_time, is_valid)
            return is_valid

        except Exception as e:
            logging.error(f"代理检测异常: {str(e)}")
            if 'proxy' in locals():
                self.proxy_check_cache[proxy] = (current_time, False)
            return False

    def _clean_proxy_cache(self):
        current_time = time.time()
        self.proxy_check_cache = {
            proxy: (cache_time, is_valid)
            for proxy, (cache_time, is_valid) in self.proxy_check_cache.items()
            if current_time - cache_time < self.proxy_check_ttl
        }
        self.last_check_time = {
            proxy: check_time
            for proxy, check_time in self.last_check_time.items()
            if current_time - check_time < self.proxy_check_ttl
        }

    def initialize_proxies(self):
        if hasattr(self, 'proxies') and self.proxies:
            self.proxy_cycle = cycle(self.proxies)
            return
            
        if self.use_getip:
            logging.info("API模式，将在请求时动态获取代理")
            return
            
        try:
            logging.info(f"从文件 {self.proxy_file} 加载代理列表")
            self.proxies = self._load_file_proxies()
            logging.info(f"加载到 {len(self.proxies)} 个代理")
            
            if self.proxies:
                self.proxy_cycle = cycle(self.proxies)
                self.current_proxy = next(self.proxy_cycle)
                logging.info(f"初始代理: {self.current_proxy}")
        except Exception as e:
            logging.error(f"初始化代理列表失败: {str(e)}")

    async def cleanup_disconnected_ips(self):
        while True:
            try:
                active_ips = {addr[0] for addr in self.active_connections}
                self.connected_clients = active_ips
            except Exception as e:
                logging.error(get_message('cleanup_error', self.language, str(e)))
            await asyncio.sleep(30)

    def is_docker():
        return os.path.exists('/.dockerenv')

    async def get_proxy_status(self):
        if self.mode == 'loadbalance':
            return f"{get_message('current_proxy', self.language)}: {self.current_proxy}"
        else:
            time_left = self.time_until_next_switch()
            if time_left == float('inf'):
                return f"{get_message('current_proxy', self.language)}: {self.current_proxy}"
            else:
                return f"{get_message('current_proxy', self.language)}: {self.current_proxy} | {get_message('next_switch', self.language)}: {time_left:.1f}{get_message('seconds', self.language)}"


    async def _get_proxy_connection(self, proxy):
        if proxy in self.proxy_pool:
            conn = self.proxy_pool[proxy]
            if not conn.is_closed:
                conn._last_used = time.time()
                return conn
                
        proxy_type, proxy_addr = proxy.split('://')
        if '@' in proxy_addr:
            auth, addr = proxy_addr.split('@')
            username, password = auth.split(':')
        else:
            username = self.username
            password = self.password
            addr = proxy_addr
            
        host, port = addr.split(':')
        port = int(port)
        
        if proxy_type in ('socks5', 'socks4'):
            conn = await self._create_socks_connection(
                host, port, username, password, 
                proxy_type == 'socks5'
            )
        else:
            conn = await self._create_http_connection(
                host, port, username, password
            )
            
        if len(self.proxy_pool) < self.max_pool_size:
            conn._last_used = time.time()
            self.proxy_pool[proxy] = conn
            
        return conn
        
    async def _create_socks_connection(self, host, port, username, password, is_socks5):
        reader, writer = await asyncio.open_connection(
            host, port, 
            limit=self.buffer_size
        )
        
        if is_socks5:
            writer.write(b'\x05\x02\x00\x02' if username else b'\x05\x01\x00')
            await writer.drain()
            
            version, method = await reader.readexactly(2)
            if version != 5:
                raise Exception('Invalid SOCKS version')
                
            if method == 2 and username:
                auth = bytes([1, len(username)]) + username.encode() + \
                       bytes([len(password)]) + password.encode()
                writer.write(auth)
                await writer.drain()
                
                auth_version, status = await reader.readexactly(2)
                if status != 0:
                    raise Exception('Authentication failed')
                    
        return reader, writer
        
    async def _create_http_connection(self, host, port, username, password):
        reader, writer = await asyncio.open_connection(
            host, port,
            limit=self.buffer_size
        )
        
        if username:
            auth = base64.b64encode(f'{username}:{password}'.encode()).decode()
            writer.write(f'Proxy-Authorization: Basic {auth}\r\n'.encode())
            await writer.drain()
            
        return reader, writer
        
    async def _cleanup_pool(self):
        while True:
            try:
                
                def is_expired(conn):
                    return hasattr(conn, 'is_closed') and conn.is_closed
                
                to_remove = []
                for proxy, conn in list(self.proxy_pool.items()):
                    if is_expired(conn):
                        to_remove.append(proxy)
                
                for proxy in to_remove:
                    if proxy in self.proxy_pool:
                        del self.proxy_pool[proxy]
            except Exception as e:
                logging.error(f'连接池清理错误: {e}')
            await asyncio.sleep(60)

    def _log_proxy_switch(self, old_proxy, new_proxy):
        if old_proxy != new_proxy:
            old_proxy = old_proxy if old_proxy else get_message('no_proxy', self.language)
            new_proxy = new_proxy if new_proxy else get_message('no_proxy', self.language)
            
            current_time = time.time()
            if not hasattr(self, '_last_log_time') or \
               not hasattr(self, '_last_log_content') or \
               current_time - self._last_log_time > 1 or \
               self._last_log_content != f"{old_proxy} -> {new_proxy}":
                logging.info(get_message('proxy_switch', self.language, old_proxy, new_proxy))
                self._last_log_time = current_time
                self._last_log_content = f"{old_proxy} -> {new_proxy}"

    async def _validate_proxy(self, proxy):
        if not proxy:
            return False
            
        
        if not self.check_proxies:
            return True
            
        try:
            if not validate_proxy(proxy):
                logging.warning(get_message('proxy_invalid', self.language, proxy))
                return False
                
            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(proxy_host, proxy_port),
                    timeout=5
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                return True
            except:
                return False
                
        except Exception as e:
            logging.error(get_message('proxy_check_failed', self.language, proxy, str(e)))
            return False

    async def get_proxy(self):
        """获取一个代理（根据配置使用不同的方式）"""
        if self.use_getip:
            # 使用API获取IP
            return await self._load_getip_proxy()
        elif self.mode == 'loadbalance':
            # 负载均衡模式：随机选择代理
            if not self.proxies:
                return None
            return random.choice(self.proxies)
        else:
            # 循环模式：依次使用代理列表中的代理
            current_time = time.time()
            if current_time - self.last_switch_time >= self.interval and not self.switching_proxy:
                # 是时候切换到下一个代理
                async with self.proxy_failure_lock:
                    if current_time - self.last_switch_time >= self.interval and not self.switching_proxy:
                        self.switching_proxy = True
                        try:
                            await self.switch_proxy()
                        finally:
                            self.switching_proxy = False
            
            return self.current_proxy

    async def cleanup_clients(self):
        while True:
            try:
                async with self.client_pool_lock:
                    current_time = time.time()
                    expired_proxies = [
                        proxy for proxy, (_, last_used) in self.client_pool.items()
                        if current_time - last_used > 30
                    ]
                    for proxy in expired_proxies:
                        client, _ = self.client_pool[proxy]
                        await client.aclose()
                        del self.client_pool[proxy]
            except Exception as e:
                logging.error(f"清理客户端池错误: {str(e)}")
            await asyncio.sleep(30)

    def get_active_connections(self):
        active = []
        for task in self.tasks:
            if not task.done():
                try:
                    coro = task.get_coro()
                    if coro.__qualname__.startswith('AsyncProxyServer.handle_client'):
                        writer = coro.cr_frame.f_locals.get('writer')
                        if writer:
                            peername = writer.get_extra_info('peername')
                            if peername:
                                active.append(peername)
                except Exception:
                    continue
        return active

    async def _cleanup_expired_sessions(self):
        """定期清理过期的会话"""
        while not self.stop_server:
            try:
                # 每10分钟清理一次过期会话
                await asyncio.sleep(600)
                if self.use_session_ip:
                    self.user_ip_manager.cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"清理过期会话时出错: {str(e)}")
                await asyncio.sleep(60)  # 出错后等待一分钟再试

    async def _get_client(self, proxy):
        """获取一个HTTPX客户端实例，用于发送HTTP请求"""
        async with self.client_pool_lock:
            current_time = time.time()
            if proxy in self.client_pool:
                client, last_used = self.client_pool[proxy]
                if current_time - last_used < 30 and not client.is_closed:
                    self.client_pool[proxy] = (client, current_time)
                    return client
                else:
                    await client.aclose()
                    del self.client_pool[proxy]

            try:
                client = await self._create_client(proxy)
                if len(self.client_pool) >= self.max_pool_size:
                    oldest_proxy = min(self.client_pool, key=lambda x: self.client_pool[x][1])
                    old_client, _ = self.client_pool[oldest_proxy]
                    await old_client.aclose()
                    del self.client_pool[oldest_proxy]
                
                self.client_pool[proxy] = (client, current_time)
                return client
            except Exception as e:
                logging.error(f"创建客户端失败: {str(e)}")
                raise
