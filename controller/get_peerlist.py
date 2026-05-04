import asyncio
import logging
import time
import socket
from typing import Set, Optional

import levin_async
import levin_async.constants
from controller import config

# ====================== 配置常量 ======================
TIMEOUT_TCP = 2                            # TCP连接超时时间（秒）
TIMEOUT_TIMED_SYNC = 4                    # 定时同步超时时间
MAX_RETRY   = 3

# ====================== 核心逻辑 ======================
async def get_peerlist(
    ip: str,
    port: int,
    local_addr = (config.BIND_IP, 0)    # 使用配置的BIND_IP，因为现在的门罗币实现中已经只允许来自同一个IP地址的一个传入连接了。https://github.com/monero-project/monero/commit/7e766e13c3790856fee440dcf8d47dab0bed5ea6
) -> Optional[Set[str]]:
    """
    处理单个节点连接
    Args:
        ip: 目标节点IP
        port: 目标节点端口
        local_addr: 可选的本地地址元组 (local_ip, local_port)
    返回: 白名单集合或None（如果失败）
    """
    logger = logging.getLogger(f"node_{ip}_{port}")
    whitelist_set = set()
    writer = None
    start_time = time.time()

    try:
        # ----------------- TCP连接阶段 -----------------
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=ip, 
                    port=port,
                    local_addr=local_addr
                ),
                timeout=TIMEOUT_TCP
            )
        except (ConnectionRefusedError, socket.gaierror) as e:
            raise ConnectionError(f"连接失败: {str(e)}") from e
        except OSError as e:
            logger.error(f"OSError详情: type={type(e)}, errno={e.errno}, strerror={e.strerror}, args={e.args}, repr={repr(e)}")
            if e.errno == 10049:  # WinError 10049: 地址无效
                logger.warning(f"绑定到 {local_addr[0]} 失败，尝试不指定本地地址")
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host=ip, 
                        port=port
                    ),
                    timeout=TIMEOUT_TCP
                )
            else:
                raise RuntimeError(f"tcp绑定错误: {str(e)}") from e
        except Exception as e:
            raise RuntimeError(f"tcp未知连接错误: {str(e)}") from e

        # ---------------- 先发送50个 timed_sync ----------------
        for _ in range(60):
            try:
                timed_sync_bucket = levin_async.Bucket.create_timed_sync_request(
                    network_id=config.NETWORK_ID,
                    peer_id=0,
                    block_height=levin_async.constants.BLOCK_HEIGHT
                )
                writer.write(timed_sync_bucket.header() + timed_sync_bucket.payload())
            except (BrokenPipeError, ConnectionResetError) as e:
                raise ConnectionError(f"同步时连接中断: {str(e)}") from e
            except Exception as e:
                raise RuntimeError(f"未知连接错误: {str(e)}") from e

        try:
            await writer.drain()
        except Exception as e:
            raise Exception(f"写入失败: {str(e)}") from e

        # ---------------- 然后读取50次响应 ----------------
        for _ in range(60):
            try:
                buffer = await asyncio.wait_for(
                    reader.readexactly(8),
                    timeout=TIMEOUT_TIMED_SYNC
                )
                if not buffer:
                    raise Exception("空响应")
                if not buffer.startswith(bytes(levin_async.constants.LEVIN_SIGNATURE)):
                    raise Exception("签名无效")

                bucket = await asyncio.wait_for(
                    levin_async.Bucket.from_buffer(signature=buffer, sock=reader),
                    timeout=30
                )

                if bucket.command == 1002 and bucket.flags == levin_async.constants.LEVIN_PACKET_RESPONSE:
                    peers = bucket.get_peers()
                    if peers:
                        whitelist_set.update(f"{peer['ip'].ip}:{peer['port'].value}" for peer in peers)
                # if len(whitelist_set) >= 1000:
                #     break
            except asyncio.TimeoutError as e:
                if len(whitelist_set) >= 1000:
                    break
                raise Exception(f"[{ip}:{port}] 第 {_+1} 个同步响应超时") from e
            except asyncio.IncompleteReadError as e:
                if len(whitelist_set) >= 1000:
                    break
                if len(e.partial) == 0 and reader.at_eof():
                    raise ConnectionError(f"第 {_+1} 个同步响应时连接被关闭，未读取到任何数据")
                else:
                    raise Exception(f"数据不足，仅收到 {len(e.partial)} 字节")
            except Exception as e:
                if len(whitelist_set) >= 1000:
                    break
                raise Exception(f"[{ip}:{port}] 第 {_+1} 个同步响应异常: {str(e)}") from e


        # ---------------- 成功返回 ----------------
        end_time = time.time()
        total_time = end_time - start_time
        whitelist_set_remove_mapped_ipv6 = remove_mapped_ipv6_addresses(whitelist_set)
        logger.info(f"[{ip}:{port}] success to get peerlist, time: {round(total_time, 1)}, whitelist_set_size: {len(whitelist_set)}, after remove mapped ipv6 size: {len(whitelist_set_remove_mapped_ipv6)}")
        return whitelist_set_remove_mapped_ipv6

    except asyncio.TimeoutError as e:
        error_type = "Timeout"
        error_detail = f"全局操作超时:{ip}:{port}"
    except ConnectionError as e:
        error_type = "ConnectionError"
        error_detail = f"{ip}:{port}, {str(e)}"
    except Exception as e:
        error_type = "UnexpectedError"
        error_detail = f"{ip}:{port}, {str(e)}"
    finally:
        if writer and not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"Close error: {ip}:{port}, {str(e)}")

    # ---------------- 错误返回 ----------------
    end_time = time.time()
    total_time = end_time - start_time
    logger.info(f"[{ip}:{port}] fail to get peerlist, time: {round(total_time, 1)}, whitelist_set_size: {len(whitelist_set)}, error: {error_type}, error_detail: {error_detail}")
    return None

def remove_mapped_ipv6_addresses(whitelist_set):
    return {item for item in whitelist_set if not item.startswith("::ffff:")}

def test_remove_mapped_ipv6_addresses():
    whitelist_set = {
        "1.1.1.1:18080",
        "1.1.1.2:18080",
        "::ffff:1.1.1.3:18080",      # IPv6 映射地址，删除
        "[2001:db8::1]:18080",       # 标准 IPv6，保留
        "not-an-ip"                  # 非法格式，保留
    }

    filtered = remove_mapped_ipv6_addresses(whitelist_set)
    print(filtered)

# ====================== 多进程封装 ======================
async def async_get_list(
    ip: str, 
    port: int,
) -> Optional[Set[str]]:
    """
    调用 get_peerlist 获取节点白名单。
    Args:
        ip: 目标节点IP
        port: 目标节点端口
    若返回 None 则最多重试 `max_retry` 次并指数退避。
    成功返回 set[str]；失败则返回 None。
    """
    logger = logging.getLogger(f"node_{ip}_{port}")
    attempt = 0
    while attempt <= MAX_RETRY:
        result = await get_peerlist(ip, port)

        # 成功获得白名单
        if result is not None:
            return result

        # 已达最大重试次数
        if attempt == MAX_RETRY:
            break

        attempt += 1
        await asyncio.sleep(1)

    # 所有尝试都失败
    logger.warning(f"[{ip}:{port}] 重试 {MAX_RETRY} 次后仍未获得白名单")
    return None

async def main():
    """
    主测试函数，用于测试从多个节点获取对等节点列表
    """
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("main")

    # 测试节点列表
    #test_nodes = [('192.99.8.110', 28080), ('103.244.206.122', 28080), ('167.114.18.32', 28080), ('88.99.195.15', 28080), ('170.17.141.244', 28080), ('18.132.93.91', 28080), ('37.187.74.171', 28080), ('88.99.173.38', 28080), ('176.9.0.187', 28080), ('155.138.134.171', 28080), ('125.229.105.12', 28080), ('45.87.251.141', 28080), ('88.198.199.23', 28080), ('67.145.128.190', 28080), ('58.87.95.60', 28094), ('81.70.23.5', 28090), ('86.48.1.16', 28080), ('58.87.95.60', 28100), ('58.87.95.60', 28091), ('58.87.95.60', 28096), ('50.27.106.111', 28080), ('123.100.144.46', 28080), ('58.87.95.60', 28093), ('58.87.95.60', 28095), ('104.207.151.173', 28080), ('84.32.188.191', 28080), ('194.87.28.21', 28080), ('58.87.95.60', 28102), ('23.137.57.100', 28080), ('88.217.40.6', 28080), ('58.87.95.60', 28097), ('58.87.95.60', 28098), ('58.87.95.60', 28092), ('96.10.28.146', 28080), ('58.87.95.60', 28099), ('58.87.95.60', 28101), ('197.232.65.203', 28080), ('194.163.165.110', 28080), ('138.201.206.164', 28080), ('198.12.124.71', 28080), ('66.42.99.190', 28080), ('174.138.187.242', 28080), ('194.35.13.195', 28080), ('89.233.104.112', 28080), ('51.171.102.66', 28080)]
    test_nodes = [("49.233.169.195", 28285)]

    # 创建任务列表
    tasks = [async_get_list(ip, port) for ip, port in test_nodes]

    # 并发执行所有任务
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果
        for (ip, port), result in zip(test_nodes, results):
            if isinstance(result, Exception):
                logger.error(f"节点 {ip}:{port} 发生错误: {str(result)}")
            elif result is None:
                logger.warning(f"节点 {ip}:{port} 未返回对等节点列表")
            else:
                logger.info(f"节点 {ip}:{port} 成功返回 {len(result)} 个对等节点")
                
    except Exception as e:
        logger.error(f"执行过程中发生错误: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())

