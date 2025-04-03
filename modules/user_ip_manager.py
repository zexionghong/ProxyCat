import time
import random
import logging
import os
import json
from typing import Dict, Tuple, Optional, List

class UserIPManager:
    def __init__(self, ip_pool_file: str = None, session_duration: int = 1800):
        """
        初始化用户IP管理器
        
        Args:
            ip_pool_file: IP池文件路径，如果提供，将从文件加载IP池
            session_duration: 会话持续时间（秒），默认30分钟
        """
        self.user_sessions = {}  # 用户会话信息: {session_id: (ip, timestamp)}
        self.user_mappings = {}  # 用户名到会话ID的映射: {username: set(session_ids)}
        self.session_duration = session_duration  # 默认30分钟
        self.ip_pool = []
        
        # 如果提供了IP池文件，加载IP
        if ip_pool_file and os.path.exists(ip_pool_file):
            self._load_ip_pool(ip_pool_file)
            
        # 如果没有IP池或IP池为空，使用默认IP池
        if not self.ip_pool:
            self._generate_default_ip_pool()
            
        # 尝试从持久化文件加载会话数据
        self._load_sessions()
            
    def _load_ip_pool(self, file_path: str) -> None:
        """从文件加载IP池"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                ips = [line.strip() for line in f if line.strip()]
                if ips:
                    self.ip_pool = ips
                    logging.info(f"从 {file_path} 加载了 {len(ips)} 个IP")
        except Exception as e:
            logging.error(f"加载IP池文件失败: {str(e)}")
            
    def _generate_default_ip_pool(self) -> None:
        """生成默认IP池（10.0.0.0/24网段的随机IP）"""
        for i in range(1, 255):
            self.ip_pool.append(f"10.0.0.{i}")
        random.shuffle(self.ip_pool)
        logging.info(f"生成了默认IP池，共 {len(self.ip_pool)} 个IP")
        
    def _get_random_ip(self) -> str:
        """从IP池中随机获取一个IP"""
        if not self.ip_pool:
            # 如果IP池为空，生成一个随机IP
            octets = [str(random.randint(1, 254)) for _ in range(4)]
            return ".".join(octets)
        return random.choice(self.ip_pool)
        
    def parse_auth_header(self, auth_header: str) -> Tuple[str, str]:
        """
        解析形如 'xxx-session_id-abc' 的认证头
        
        Args:
            auth_header: 认证头字符串
            
        Returns:
            Tuple[str, str]: (username, session_id)
            其中session_id是用户名和原始会话ID的组合，格式为：username_session_value
        """
        parts = auth_header.split('-')
        if len(parts) >= 3 and parts[1] == 'session_id':
            username = parts[0]
            session_value = parts[2]
            # 返回用户名和组合的会话ID（用户名_会话值）
            return username, f"{username}_{session_value}"
        else:
            # 如果格式不符合要求，返回空值
            return "", ""
            
    def parse_auth_params(self, auth_header: str) -> Tuple[str, Dict[str, str]]:
        """
        从认证字符串中解析用户名和所有参数
        认证字符串格式为: username-key1-value1-key2-value2...
        
        Args:
            auth_header: 认证头字符串
            
        Returns:
            Tuple[str, Dict[str, str]]: (username, params_dict)
            其中username是第一个部分，params_dict是一个包含所有参数的字典
        """
        parts = auth_header.split('-')
        if len(parts) < 1:
            return "", {}
            
        # 第一个部分是用户名
        username = parts[0]
        
        # 解析参数
        params = {}
        i = 1
        while i < len(parts) - 1:
            key = parts[i]
            value = parts[i + 1]
            params[key] = value
            i += 2
            
        # 日志记录解析到的参数
        logging.debug(f"从认证字符串 '{auth_header}' 解析出用户名: {username}, 参数: {params}")
        
        return username, params
    
    def get_session_id_from_params(self, username: str, params: Dict[str, str]) -> str:
        """
        从参数字典中获取会话ID
        如果存在session_id参数，返回组合的会话ID（用户名_会话值）
        
        Args:
            username: 用户名
            params: 参数字典
            
        Returns:
            str: 组合的会话ID，如果没有session_id参数则返回空字符串
        """
        if 'session_id' in params:
            return f"{username}_{params['session_id']}"
        return ""
        
    def get_user_ip(self, username: str, session_id: str) -> str:
        """
        获取用户IP，如果会话已过期或不存在，则分配新IP
        
        Args:
            username: 用户名
            session_id: 会话ID
            
        Returns:
            str: 分配给用户的IP地址
        """
        current_time = time.time()
        
        # 更新用户到会话的映射
        if username not in self.user_mappings:
            self.user_mappings[username] = set()
        self.user_mappings[username].add(session_id)
        
        # 检查会话是否存在且未过期
        if session_id in self.user_sessions:
            ip, timestamp = self.user_sessions[session_id]
            # 如果会话未过期，返回现有IP
            if current_time - timestamp < self.session_duration:
                # 更新时间戳
                self.user_sessions[session_id] = (ip, current_time)
                return ip
        
        # 分配新IP
        new_ip = self._get_random_ip()
        self.user_sessions[session_id] = (new_ip, current_time)
        
        # 持久化会话数据
        self._save_sessions()
        
        return new_ip
        
    def cleanup_expired_sessions(self) -> None:
        """清理过期的会话"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, (ip, timestamp) in self.user_sessions.items():
            if current_time - timestamp > self.session_duration:
                expired_sessions.append(session_id)
                
        # 删除过期会话
        for session_id in expired_sessions:
            if session_id in self.user_sessions:
                del self.user_sessions[session_id]
                
        # 更新用户到会话的映射
        for username, sessions in list(self.user_mappings.items()):
            self.user_mappings[username] = {s for s in sessions if s in self.user_sessions}
            if not self.user_mappings[username]:
                del self.user_mappings[username]
                
        # 如果有清理，持久化会话数据
        if expired_sessions:
            self._save_sessions()
            logging.info(f"清理了 {len(expired_sessions)} 个过期会话")
            
    def _save_sessions(self) -> None:
        """保存会话数据到文件"""
        try:
            # 创建要保存的数据结构
            session_data = {
                "user_sessions": {sid: [ip, ts] for sid, (ip, ts) in self.user_sessions.items()},
                "user_mappings": {u: list(s) for u, s in self.user_mappings.items()}
            }
            
            # 确保目录存在
            os.makedirs('logs', exist_ok=True)
            
            # 保存到文件
            with open('logs/user_sessions.json', 'w', encoding='utf-8') as f:
                json.dump(session_data, f)
        except Exception as e:
            logging.error(f"保存会话数据失败: {str(e)}")
            
    def _load_sessions(self) -> None:
        """从文件加载会话数据"""
        try:
            if os.path.exists('logs/user_sessions.json'):
                with open('logs/user_sessions.json', 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                    
                    # 加载用户会话
                    for sid, [ip, ts] in session_data.get("user_sessions", {}).items():
                        self.user_sessions[sid] = (ip, ts)
                        
                    # 加载用户映射
                    for username, sessions in session_data.get("user_mappings", {}).items():
                        self.user_mappings[username] = set(sessions)
                        
                    logging.info(f"从文件加载了 {len(self.user_sessions)} 个会话")
                    
                    # 加载后立即清理过期会话
                    self.cleanup_expired_sessions()
        except Exception as e:
            logging.error(f"加载会话数据失败: {str(e)}") 