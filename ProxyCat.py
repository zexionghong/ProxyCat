from wsgiref import headers
from modules.modules import ColoredFormatter, load_config, DEFAULT_CONFIG, check_proxies, check_for_updates, get_message, load_ip_list, print_banner, logos
import threading, argparse, logging, asyncio, time, socket, signal, sys, os
from concurrent.futures import ThreadPoolExecutor
from modules.proxyserver import AsyncProxyServer
from colorama import init, Fore, Style
from itertools import cycle
from tqdm import tqdm
import base64
from configparser import ConfigParser

init(autoreset=True)

def setup_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    formatter = ColoredFormatter(log_format)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[console_handler])

def update_status(server):
    def print_proxy_info():
        status = f"{get_message('current_proxy', server.language)}: {server.current_proxy}"
        logging.info(status)

    def reload_server_config(new_config):
        old_use_getip = server.use_getip
        old_mode = server.mode
        old_port = int(server.config.get('port', '1080'))
        
        server.config.update(new_config)
        server._update_config_values(new_config)
        
        if old_use_getip != server.use_getip or old_mode != server.mode:
            server._handle_mode_change()
        
        if old_port != server.port:
            logging.info(get_message('port_changed', server.language, old_port, server.port))

    config_file = 'config/config.ini'
    ip_file = server.proxy_file
    last_config_modified_time = os.path.getmtime(config_file) if os.path.exists(config_file) else 0
    last_ip_modified_time = os.path.getmtime(ip_file) if os.path.exists(ip_file) else 0
    display_level = int(server.config.get('display_level', '1'))
    is_docker = os.path.exists('/.dockerenv')
    
    while True:
        try:
            if os.path.exists(config_file):
                current_config_modified_time = os.path.getmtime(config_file)
                if current_config_modified_time > last_config_modified_time:
                    logging.info(get_message('config_file_changed', server.language))
                    new_config = load_config(config_file)
                    reload_server_config(new_config)
                    last_config_modified_time = current_config_modified_time
                    continue
            
            if os.path.exists(ip_file) and not server.use_getip:
                current_ip_modified_time = os.path.getmtime(ip_file)
                if current_ip_modified_time > last_ip_modified_time:
                    logging.info(get_message('proxy_file_changed', server.language))
                    server._reload_proxies()
                    last_ip_modified_time = current_ip_modified_time
                    continue

            if display_level == 0:
                if not hasattr(server, 'last_proxy') or server.last_proxy != server.current_proxy:
                    print_proxy_info()
                    server.last_proxy = server.current_proxy
                time.sleep(1)
                continue

            if server.mode == 'loadbalance':
                if display_level >= 1:
                    print_proxy_info()
                time.sleep(5)
                continue

            time_left = server.time_until_next_switch()
            if time_left == float('inf'):
                if display_level >= 1:
                    print_proxy_info()
                time.sleep(5)
                continue
            
            if not hasattr(server, 'last_proxy') or server.last_proxy != server.current_proxy:
                print_proxy_info()
                server.last_proxy = server.current_proxy
                server.previous_proxy = server.current_proxy

            total_time = int(server.interval)
            elapsed_time = total_time - int(time_left)
            
            if display_level >= 1:
                if elapsed_time > total_time:
                    if hasattr(server, 'progress_bar'):
                        if not is_docker:
                            server.progress_bar.n = total_time
                            server.progress_bar.refresh()
                            server.progress_bar.close()
                        delattr(server, 'progress_bar')
                    if hasattr(server, 'last_update_time'):
                        delattr(server, 'last_update_time')
                    time.sleep(0.5)
                    continue
                
                if is_docker:
                    if not hasattr(server, 'last_update_time') or \
                       (time.time() - server.last_update_time >= (5 if display_level == 1 else 1) and elapsed_time <= total_time):
                        if display_level >= 2:
                            logging.info(f"{get_message('next_switch', server.language)}: {time_left:.0f} {get_message('seconds', server.language)} ({elapsed_time}/{total_time})")
                        else:
                            logging.info(f"{get_message('next_switch', server.language)}: {time_left:.0f} {get_message('seconds', server.language)}")
                        server.last_update_time = time.time()
                else:
                    if not hasattr(server, 'progress_bar'):
                        server.progress_bar = tqdm(
                            total=total_time,
                            desc=f"{Fore.YELLOW}{get_message('next_switch', server.language)}{Style.RESET_ALL}",
                            bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} ' + get_message('seconds', server.language),
                            colour='green'
                        )
                    
                    server.progress_bar.n = min(elapsed_time, total_time)
                    server.progress_bar.refresh()
                
        except Exception as e:
            if display_level >= 2:
                logging.error(f"Status update error: {e}")
            elif display_level >= 1:
                logging.error(get_message('status_update_error', server.language))
        time.sleep(1)

async def handle_client_wrapper(server, reader, writer, clients):
    task = asyncio.create_task(server.handle_client(reader, writer))
    clients.add(task)
    try:
        await task
    except Exception as e:
        logging.error(get_message('client_handle_error', server.language, e))
    finally:
        clients.remove(task)

async def run_server(server):
    try:
        await server.start()
    except asyncio.CancelledError:
        logging.info(get_message('server_closing', server.language))
    except Exception as e:
        if not server.stop_server:
            logging.error(f"Server error: {e}")
    finally:
        await server.stop()

async def run_proxy_check(server):
    if server.config.get('check_proxies', 'False').lower() == 'true':
        logging.info(get_message('proxy_check_start', server.language))
        valid_proxies = await check_proxies(server.proxies, server.test_url)
        if valid_proxies:
            server.proxies = valid_proxies
            server.proxy_cycle = cycle(valid_proxies)
            server.current_proxy = next(server.proxy_cycle)
            logging.info(get_message('valid_proxies', server.language, valid_proxies))
        else:
            logging.error(get_message('no_valid_proxies', server.language))
    else:
        logging.info(get_message('proxy_check_disabled', server.language))


if __name__ == '__main__':
    setup_logging()
    parser = argparse.ArgumentParser(description=logos())
    parser.add_argument('-c', '--config', default='config/config.ini', help='配置文件路径')
    args = parser.parse_args()
    config = load_config(args.config)
    server = AsyncProxyServer(config)
    print_banner(config)
    asyncio.run(check_for_updates(config.get('language', 'cn').lower()))
    if not config.get('use_getip', 'False').lower() == 'true':
        asyncio.run(run_proxy_check(server))
    else:
        logging.info(get_message('api_mode_notice', server.language))
    
    status_thread = threading.Thread(target=update_status, args=(server,), daemon=True)
    status_thread.start()
    
    cleanup_thread = threading.Thread(target=lambda: asyncio.run(server.cleanup_clients()), daemon=True)
    cleanup_thread.start()
    
    try:
        asyncio.run(run_server(server))
    except KeyboardInterrupt:
        logging.info(get_message('user_interrupt', server.language))
