import random
import socket
import struct
import time
from pathlib import Path
from datetime import datetime

# 生成当前日期
def generate_current_date() -> str:
    """生成当前日期，格式为 YYYY-MM-DD"""
    current_date = datetime.now().strftime('%Y-%m-%d')
    return current_date

# 生成当前日期和时间，精确到微秒
def generate_current_time() -> str:
    """生成当前日期+时间，格式为 YYYY-MM-DD HH:MM:SS.microseconds"""
    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S') + f".{datetime.now().microsecond // 1000:03d}"
    return current_datetime

# 获取当前项目的根目录
def get_project_root_path() -> str:
    """获取整个项目的根目录"""
    current_path = Path(__file__).resolve()
    return current_path.parent.parent.__str__()

# 随机生成一个ip地址的字符串
def generate_fake_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

# 将ip地址转为10进制
def ip_str_to_int(ip: str):
    packed_ip = socket.inet_aton(ip)
    return struct.unpack("!I", packed_ip)[0]

# 将10进制ip地址转为ip地址字符串(修正版)
def int_to_ip_str(ip: int):
    # 将原始整数的字节序颠倒
    ip_bytes = struct.pack("!I", ip)  # 网络字节序(大端)打包
    ip_bytes_reversed = ip_bytes[::-1] # 字节序颠倒
    ip_int_reversed = struct.unpack("!I", ip_bytes_reversed)[0] # 转回整数
    return socket.inet_ntoa(struct.pack("!I", ip_int_reversed))

# 将ip地址的四个部分逆置
def reverse_ipv4(ip: str):
    parts = ip.split('.')
    reverse_parts = reversed(parts)
    reversed_ip = '.'.join(reverse_parts)
    return reversed_ip

# 给定number，生成对应数量的IP地址列表
def generate_fake_ip_list(number: int) -> list:
    ip_list = []
    for i in range(number):
        ip_str = generate_fake_ip()
        ip_list.append(ip_str)
        # ip_str_reverse = reverse_ipv4(ip_str)
        # print(str(ip_str_to_int(ip_str_reverse)) + ",    // " + ip_str)
    return ip_list

# 生成随机的ip地址（字符串类型）
def generate_random_ip():
    # 生成四个随机整数作为IP地址的四个部分
    ip_parts = [random.randint(0, 255) for _ in range(4)]

    # 将四个部分连接成IP地址字符串
    ip_address = ".".join(map(str, ip_parts))

    return ip_address

def generate_random_ip_list(ip_nums: int) -> list:
    ip_list = []
    for i in range(ip_nums):
        ip_list.append((generate_random_ip(), 28086))
    return ip_list

# 时间等待函数，输入时间(秒)
def time_ticker(seconds: int):
    while seconds:
        mins, secs = divmod(seconds, 60)
        timeformat = '{:02d}:{:02d}'.format(mins, secs)
        print(timeformat, end='\r')
        time.sleep(1)
        seconds -= 1

if __name__ == "__main__":
    print(generate_current_time())