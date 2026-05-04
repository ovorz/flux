import asyncio
from collections import defaultdict
import os
from pathlib import Path
import random
import signal
import socket
from datetime import datetime
from multiprocessing import Process
from levin_async.utils import generate_random_ip
import uvloop
from loguru import logger
import hashlib
from io import BytesIO

try:
    from Crypto.Hash import keccak
except Exception:
    keccak = None

import levin_async
import levin_async.constants
from levin_async.reader import LevinReader
from controller import config


class MonerodForwarder:
    """
    维护一条到指定 monerod P2P 端口的持久连接。
    首次转发时自动建立 TCP 连接并完成 Levin 握手；
    连接断开后下次转发时自动重连。
    """

    CONNECT_TIMEOUT = 10.0   # 连接 / 握手超时（秒）

    def __init__(self, host: str, port: int, network_id: bytes, logger):
        self.host = host
        self.port = port
        self.network_id = network_id
        self.logger = logger
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._lock = asyncio.Lock()       # 保护连接状态的读写
        self._write_lock = asyncio.Lock() # 保护 _writer 的并发写入
        self._connected = False
        self._peer_id = random.getrandbits(64).to_bytes(8, 'little')
        self._drain_task: asyncio.Task | None = None

    async def _connect_and_handshake(self):
        """建立 TCP 连接并完成 Levin 握手（已持锁时调用）。"""
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.CONNECT_TIMEOUT
            )

            # 构造并发送握手请求
            hs_bucket = levin_async.Bucket.create_handshake_request(
                my_port=0,
                network_id=self.network_id,
                peer_id=self._peer_id,
                block_height=levin_async.constants.BLOCK_HEIGHT
            )
            # create_handshake_request 返回的 bucket.payload_section 是 bytes；
            # 调用 payload() 方法取到 bytes。
            self._writer.write(hs_bucket.header() + hs_bucket.payload())
            await self._writer.drain()

            # 接收握手响应
            sig = await asyncio.wait_for(
                self._reader.readexactly(8), timeout=self.CONNECT_TIMEOUT
            )
            resp = await asyncio.wait_for(
                levin_async.Bucket.from_buffer(signature=sig, sock=self._reader),
                timeout=self.CONNECT_TIMEOUT
            )
            if resp.command.value != 1001:
                raise RuntimeError(
                    f"期望握手响应(1001)，实际收到: {resp.command.value}"
                )

            self._connected = True
            self.logger.info(
                f"[Forwarder] 已连接到 monerod {self.host}:{self.port}，握手成功"
            )
            # 启动后台任务持续排空 monerod 发来的数据（timed_sync 等），
            # 防止 TCP 接收缓冲区填满导致窗口归零、连接卡死。
            self._drain_task = asyncio.create_task(
                self._drain_incoming(), name=f"forwarder-drain-{self.host}"
            )
        except Exception as e:
            self._connected = False
            if self._writer:
                try:
                    self._writer.close()
                except Exception:
                    pass
            self._reader = None
            self._writer = None
            self.logger.warning(
                f"[Forwarder] 连接 monerod {self.host}:{self.port} 失败: {e}"
            )
            raise

    async def _drain_incoming(self):
        """持续解析 monerod 主动发来的 Levin 包，并对 timed_sync 请求作出响应以维持连接。"""
        try:
            while True:
                # 读取 8 字节 Levin 签名
                sig = await self._reader.readexactly(8)
                if not sig:
                    self.logger.warning("[Forwarder] monerod 关闭了连接（drain EOF）")
                    self._connected = False
                    break

                bucket = await levin_async.Bucket.from_buffer(
                    signature=sig, sock=self._reader
                )

                cmd = bucket.command.value

                if bucket.flags == levin_async.constants.LEVIN_PACKET_REQUEST and cmd == 1002:
                    # timed_sync 请求：回复一个标准响应
                    resp = levin_async.Bucket.create_timed_sync_response(
                        my_port=0,
                        network_id=self.network_id,
                        peer_id=self._peer_id,
                        malicious_peerlist=[],
                        block_height=levin_async.constants.BLOCK_HEIGHT
                    )
                    raw = resp.header() + resp.payload()
                    async with self._write_lock:
                        self._writer.write(raw)
                        await self._writer.drain()
                    self.logger.debug("[Forwarder] 已回复 monerod timed_sync 请求")

                elif bucket.flags == levin_async.constants.LEVIN_PACKET_REQUEST and cmd == 1003:
                    # ping 请求
                    resp = levin_async.Bucket.create_ping_response(peer_id=self._peer_id)
                    raw = resp.header() + resp.payload()
                    async with self._write_lock:
                        self._writer.write(raw)
                        await self._writer.drain()
                    self.logger.debug("[Forwarder] 已回复 monerod ping 请求")

                else:
                    # 其他命令（响应、通知等）一律忽略
                    self.logger.debug(f"[Forwarder] 忽略 monerod 发来的命令: {cmd}")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.warning(f"[Forwarder] drain 任务异常: {e}，连接将在下次转发时重建")
            self._connected = False

    async def forward(self, raw_data: bytes, tx_hashes: str = ""):
        """将原始 Levin 数据包转发给 monerod。fire-and-forget 友好（可用 create_task 调用）。"""
        async with self._lock:
            if not self._connected or self._writer is None:
                try:
                    await self._connect_and_handshake()
                except Exception:
                    self.logger.warning(
                        "[Forwarder] 跳过本次转发，目标 monerod 不可达"
                    )
                    return
            try:
                async with self._write_lock:
                    self._writer.write(raw_data)
                    await self._writer.drain()
                local_ep = self._writer.get_extra_info("sockname")
                peer_ep = self._writer.get_extra_info("peername")
                src_ip = config.PROBE_NODE[0] if getattr(config, "PROBE_NODE", None) else (local_ep[0] if local_ep else "unknown")
                src_port = local_ep[1] if local_ep else "unknown"
                local_ep_str = f"{src_ip}:{src_port}"
                peer_ep_str = f"{peer_ep[0]}:{peer_ep[1]}" if peer_ep else f"{self.host}:{self.port}"
                self.logger.info(
                    f"[Forwarder] 已转发 2002 NEW_TRANSACTION → "
                    f"dst={peer_ep_str}, src={local_ep_str}, size={len(raw_data)} bytes"
                )
            except Exception as e:
                self.logger.warning(
                    f"[Forwarder] 转发失败: {e}，断开连接，下次重连"
                )
                self._connected = False
                try:
                    self._writer.close()
                except Exception:
                    pass
                self._reader = None
                self._writer = None
                if self._drain_task and not self._drain_task.done():
                    self._drain_task.cancel()
                self._drain_task = None

    async def close(self):
        """关闭与 monerod 的转发连接。"""
        async with self._lock:
            self._connected = False
            if self._drain_task and not self._drain_task.done():
                self._drain_task.cancel()
                try:
                    await self._drain_task
                except asyncio.CancelledError:
                    pass
            self._drain_task = None
            if self._writer:
                try:
                    self._writer.close()
                    await self._writer.wait_closed()
                except Exception:
                    pass
                self._reader = None
                self._writer = None
            self.logger.info("[Forwarder] 转发连接已关闭")


class NodeListener:
    def __init__(self, port: int):
        log_dir = Path("log")
        log_dir.mkdir(exist_ok=True)
        logger.remove()
        logger.add(log_dir / f"node_listener_{port}.log", rotation="50 MB", retention="7 days", enqueue=True)
        self.port = port
        self.logger = logger
        self._shutdown_event = asyncio.Event()
        self.servers = []
        self.round_num = 0
        self.network_id = config.NETWORK_ID

        self.target_peer_ping_response_times = {}
        self.local_ips = defaultdict(set)
        self.target_peer_lock = asyncio.Lock()

        # 转发器：将 2002 消息转发到目标 monerod
        if config.FORWARD_MONEROD_HOST:
            self.forwarder: MonerodForwarder | None = MonerodForwarder(
                host=config.FORWARD_MONEROD_HOST,
                port=config.FORWARD_MONEROD_P2P_PORT,
                network_id=self.network_id,
                logger=self.logger,
            )
            self.logger.info(
                f"转发器已配置: 2002 消息将转发至 "
                f"{config.FORWARD_MONEROD_HOST}:{config.FORWARD_MONEROD_P2P_PORT}"
            )
        else:
            self.forwarder = None

    async def _graceful_shutdown(self):
        self.logger.info("收到终止信号，开始优雅关闭...")
        await self.shutdown()


    async def start_server(self):
        # 设置信号处理
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(
                signal.SIGINT, 
                lambda: asyncio.create_task(self._graceful_shutdown())
            )
            loop.add_signal_handler(
                signal.SIGTERM,
                lambda: asyncio.create_task(self._graceful_shutdown())
            )
        except NotImplementedError:
            # Windows兼容性处理
            pass

        try:
            # 创建socket并设置端口复用选项
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # 设置SO_REUSEPORT以允许握手程序和监听器共享端口
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                self.logger.info(f"监听器启用SO_REUSEPORT for port {self.port}")
            else:
                self.logger.error(f"系统不支持SO_REUSEPORT，无法与握手程序共享端口 {self.port}")
                raise RuntimeError("需要SO_REUSEPORT支持才能与握手程序并行运行")
            
            sock.bind(("0.0.0.0", self.port))
            sock.listen(5000)
            sock.setblocking(False)
            
            server = await asyncio.start_server(
                self.handle_connection,
                sock=sock
            )
            self.servers.append(server)
            self.logger.info(f"Server started on port {self.port}: {server.sockets[0].getsockname()}")
            await self._shutdown_event.wait()
        except Exception as e:
            self.logger.error(f"Server error: {str(e)}")

    async def handle_connection(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        server_addr = writer.get_extra_info('sockname')
        if client_addr is None:
            return

        try:
            # 记录所有连接，但只处理来自目标IP的请求
            self.logger.debug(f"Received connection from {client_addr}")
            
            # 如果不是目标IP，记录但不处理
            if client_addr[0] not in config.target_ip_list:
                self.logger.debug(f"Ignoring connection from non-target IP: {client_addr[0]}")
                return

            while not self._shutdown_event.is_set() and not reader.at_eof():
                buffer = await reader.read(8)
                if not buffer:
                    break

                if not buffer.startswith(bytes(levin_async.constants.LEVIN_SIGNATURE)):
                    self.logger.warning(f"Invalid Levin header from {client_addr}")
                    break

                bucket = await levin_async.Bucket.from_buffer(signature=buffer, sock=reader)
                if bucket is None:
                    break

                # 无论 flags 是 request 还是 notification，2002 都直接转发原始 Levin 包
                if bucket.command == 2002:
                    raw_fwd = bucket.header() + bucket.payload
                    self.logger.info(
                        f"Received 2002 (NEW_TRANSACTION) from {client_addr}, "
                        f"server: [{server_addr[0]}], payload_size={len(bucket.payload)}"
                    )
                    if self.forwarder is not None:
                        asyncio.create_task(self.forwarder.forward(raw_fwd))
                    else:
                        self.logger.warning("Forwarder not configured, skip forwarding 2002")
                    continue

                if bucket.flags == levin_async.constants.LEVIN_PACKET_REQUEST:
                    response = await self._process_bucket(bucket, server_addr, client_addr)
                    if response:
                        writer.write(response.header() + response.payload())
                        await writer.drain()
                        # 记录响应的命令类型
                        if bucket.command == 1001:
                            command_name = "1001 handshake"
                        elif bucket.command == 1002:
                            command_name = "1002 timed_sync"
                        elif bucket.command == 1003:
                            command_name = "1003 ping"
                        else:
                            command_name = f"{bucket.command}"
                        self.logger.info(f"client: [{client_addr}], server: [{server_addr[0]}] Sent {command_name} response")                
                        async with self.target_peer_lock:
                            current_time = datetime.now().timestamp()
                            entry = self.target_peer_ping_response_times.get(client_addr[0], {
                                'first_seen': current_time,
                                'last_seen': current_time,
                                'count': 0,
                                'errors': []
                            })
                            entry['last_seen'] = current_time
                            self.local_ips[client_addr[0]].add(server_addr[0])
                            entry['count'] = len(self.local_ips[client_addr[0]])
                            self.target_peer_ping_response_times[client_addr[0]] = entry
                        await asyncio.sleep(5)
                else:
                    # 处理通知类消息（不需要响应）
                    if bucket.command == 2001:
                        self.logger.info(f"Received 2001 (NEW_BLOCK) message from {client_addr}, server: [{server_addr[0]}]")

        except Exception as e:
            error_msg = f"Connection error: {client_addr} - {str(e)}"
            self.logger.warning(error_msg)
            await self._record_error(client_addr, error_msg)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                self.logger.error(f"Error closing connection: {str(e)}")

    async def generate_random_ip(self):
        # 生成四个随机整数作为IP地址的四个部分
        ip_parts = [random.randint(0, 255) for _ in range(4)]

        # 将四个部分连接成IP地址字符串
        ip_address = ".".join(map(str, ip_parts))

        return ip_address
    
    async def _process_bucket(self, bucket, server_addr, client_addr):
        try:
            peer_id_bytes=config.addr_peerid_map.get((config.PROBE_NODE[0], server_addr[1]), random.getrandbits(64))
            if bucket.command == 1001:
                # 处理握手请求 (HANDSHAKE_REQUEST)
                # peer_id_bytes = (11300175395242703804).to_bytes(8, 'little')
                return levin_async.Bucket.create_handshake_response(
                    my_port=server_addr[1],  # 使用服务器监听端口
                    network_id=self.network_id,
                    peer_id=peer_id_bytes,
                    peerlist=[],  # 返回空的 peerlist
                    block_height=levin_async.constants.BLOCK_HEIGHT
                )
            elif bucket.command == 1002:
                # 处理定时同步请求 (TIMED_SYNC_REQUEST)
                # peer_id_bytes = (11300175395242703804).to_bytes(8, 'little')
            
                ip_list = []
                for i in range(250):
                    ip_list.append((await self.generate_random_ip(), 28086))

                return levin_async.Bucket.create_timed_sync_response(
                    my_port=server_addr[1],  # 使用服务器监听端口
                    network_id=self.network_id,
                    peer_id=peer_id_bytes,
                    malicious_peerlist=ip_list,
                    block_height=levin_async.constants.BLOCK_HEIGHT
                )
            
            elif bucket.command == 1003:
                # 处理 ping 请求
                # 将int类型的peer_id转换为bytes
                # peer_id_bytes = (11300175395242703804).to_bytes(8, 'little')
                return levin_async.Bucket.create_ping_response(
                    peer_id=peer_id_bytes,
                )
            elif bucket.command == 2002:
                # 2002 在 handle_connection 中统一直接转发，这里不再做 hash/解析
                return None
            else:
                return None
        except Exception as e:
            error_msg = f"[{client_addr}] Command {bucket.command} failed: {str(e)}"
            self.logger.error(error_msg)
            await self._record_error(client_addr, error_msg)
            return None

    async def _record_error(self, client_addr, error_msg):
        async with self.target_peer_lock:
            entry = self.target_peer_ping_response_times.get(client_addr[0], {
                'first_seen': None,
                'last_seen': None,
                'count': 0,
                'errors': []
            })
            entry['errors'].append(error_msg)
            self.target_peer_ping_response_times[client_addr[0]] = entry


    async def shutdown(self):
        self.logger.info("Shutting down...")
        self._shutdown_event.set()

        # 关闭转发连接
        if self.forwarder is not None:
            await self.forwarder.close()

        
        # 关闭所有服务器
        close_tasks = []
        for server in self.servers:
            server.close()
            close_tasks.append(server.wait_closed())
        
        # 取消所有任务
        for task in asyncio.all_tasks():
            if task is not asyncio.current_task():
                task.cancel()
        

        try:
            await asyncio.wait_for(
                asyncio.gather(*close_tasks, return_exceptions=True),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            self.logger.warning("服务器关闭超时")
        
        await self.save_to_csv()
        
        self.logger.info("所有服务已关闭")


    async def save_to_csv(self, data=None):
        """保存数据到CSV文件"""
        try:
            import csv
            if data is None:
                async with self.target_peer_lock:
                    data = dict(self.target_peer_ping_response_times)
            filename = 'target_peer_ping_response_times.csv'
            file_exists = os.path.isfile(filename)
            with open(filename, 'a', newline='') as csvfile:
                fieldnames = ['round_num', 'ip', 'first_seen', 'last_seen', 'count', 'errors']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                if not file_exists:
                    writer.writeheader()  # 仅首次写入表头
                for client_ip, entry in data.items():
                    writer.writerow({
                        'round_num': self.round_num,
                        'ip': client_ip,
                        'first_seen': entry.get('first_seen', ''),
                        'last_seen': entry.get('last_seen', ''),
                        'count': entry.get('count', 0),
                        'errors': '; '.join(entry.get('errors', []))
                    })
            self.logger.info(f"数据已保存到 {filename}")
        except Exception as e:
            self.logger.error(f"保存CSV失败: {str(e)}")

def start_worker(proc_id: int, p2p_port: int):
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        node = NodeListener(port=p2p_port)
        loop.run_until_complete(node.start_server())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        print(f"进程 {proc_id} 已完全退出")


def main():

    workers = []

    # 改为遍历本地端口列表，而不是遍历目标节点或单一基准端口
    for idx, p2p_port in enumerate(config.LOCAL_P2P_PORT_LIST):
        p = Process(target=start_worker, args=(idx, p2p_port))
        p.start()
        workers.append(p)
    try:
        for p in workers:
            p.join()
    except KeyboardInterrupt:
        print("\n主进程收到Ctrl+C，等待子进程退出...")
        for p in workers:
            p.join()

if __name__ == "__main__":
    main()