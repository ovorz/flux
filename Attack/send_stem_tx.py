import configparser
import os
import sys
import time


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# Make imports work regardless of current working directory.
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from rpc.wallet import Wallet
    from rpc.daemon import Daemon
except ImportError:  # Fallback if running in an environment where Attack is a package
    from Attack.rpc.wallet import Wallet
    from Attack.rpc.daemon import Daemon


def _now_str() -> str:
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


def _today_str() -> str:
    return time.strftime('%Y-%m-%d', time.localtime())


def _append_log(log_file_path: str, line: str) -> None:
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    with open(log_file_path, 'a', encoding='utf-8') as f:
        f.write(line)

def send_stem_transaction_once(
    *,
    wallet: Wallet,
    daemon: Daemon,
    recipient_address: str,
    amount_atomic: int,
    target_node: str,
    log_file_path: str,
):
    destinations = [{"amount": amount_atomic, "address": recipient_address}]

    print("正在创建交易...")
    transfer_result = wallet.transfer(destinations=destinations, do_not_relay=True, get_tx_hex=True)

    tx_hex = None
    tx_hash = None
    if isinstance(transfer_result, dict):
        # 不同 monero-wallet-rpc 版本/参数下字段名可能不同：常见是 tx_blob，也可能是 tx_hex。
        tx_hex = transfer_result.get('tx_hex') or transfer_result.get('tx_blob')
        tx_hash = transfer_result.get('tx_hash')

    if not transfer_result or not tx_hex:
        print("创建交易失败。请检查您的钱包RPC服务和配置。")
        print("返回结果:", transfer_result)
        if isinstance(transfer_result, dict) and 'error' in transfer_result:
            err = transfer_result.get('error', {})
            if err.get('code') == -4 and 'output distribution' in str(err.get('message', '')).lower():
                print("提示：这通常表示 wallet-rpc 连接不到可用的 monerod，或该 monerod 禁止/无法提供输出分布查询。")
                print("请在配置文件的 [DAEMON_RPC] 中填写一个你自己可控且已同步的 monerod RPC（推荐本机 127.0.0.1:18081）。")
        return

    if tx_hash:
        print(f"交易创建成功，tx_hash: {tx_hash}")
        _append_log(log_file_path, f"[{_now_str()}] create tx_hash={tx_hash} target={target_node}\n")
    print(f"raw tx(hex) 前64位: {tx_hex[:64]}...")

    print("正在将交易发送到目标节点...")
    # 注意：do_not_relay=True 会导致交易不被转发（不是 stem）。
    # 是否走 stem/fluff 由目标节点的 Dandelion++ 状态机决定。
    send_result = daemon.send_raw_transaction(tx_as_hex=tx_hex, do_not_relay=False)

    if send_result and send_result.get('status', '') == 'OK':
        print("交易已成功提交到目标节点（后续是否 stem/fluff 由该节点决定）。")
        if tx_hash:
            _append_log(log_file_path, f"[{_now_str()}] send OK tx_hash={tx_hash} target={target_node}\n")
    else:
        print("交易发送失败。")
        print("返回结果:", send_result)
        if tx_hash:
            _append_log(log_file_path, f"[{_now_str()}] send FAILED tx_hash={tx_hash} target={target_node} res={send_result}\n")


def send_stem_transaction_every_minute():
    # 读取配置文件
    config = configparser.ConfigParser()
    config_path = os.path.join(SCRIPT_DIR, 'config', 'stem_tx_config.ini')
    read_files = config.read(config_path, encoding='utf-8')
    if not read_files:
        print("未读取到配置文件。")
        print(f"期望路径: {config_path}")
        print(f"当前工作目录: {os.getcwd()}")
        print("请确认 Attack/config/stem_tx_config.ini 存在，并用该脚本自带的路径读取。")
        return

    required_sections = {'TARGET_NODE', 'WALLET_RPC', 'TRANSACTION'}
    missing_sections = [s for s in required_sections if s not in config]
    if missing_sections:
        print(f"配置文件缺少 section: {missing_sections}")
        print(f"请检查配置文件内容: {config_path}")
        return

    daemon_rpc_ip = None
    daemon_rpc_port = None
    daemon_trusted = None
    if 'DAEMON_RPC' in config:
        daemon_rpc_ip = config['DAEMON_RPC'].get('ip', '').strip() or None
        daemon_rpc_port_raw = config['DAEMON_RPC'].get('port', '').strip()
        daemon_rpc_port = int(daemon_rpc_port_raw) if daemon_rpc_port_raw else None
        daemon_trusted_raw = config['DAEMON_RPC'].get('trusted', '').strip().lower()
        daemon_trusted = daemon_trusted_raw in {'1', 'true', 'yes', 'y', 'on'} if daemon_trusted_raw else None

    # 目标节点信息
    target_node_ip = config['TARGET_NODE']['ip']
    target_node_rpc_port = int(config['TARGET_NODE']['rpc_port'])

    # 钱包RPC服务信息
    wallet_rpc_ip = config['WALLET_RPC']['ip']
    wallet_rpc_port = int(config['WALLET_RPC']['port'])
    wallet_rpc_user = config['WALLET_RPC']['user']
    wallet_rpc_password = config['WALLET_RPC']['password']

    # 交易信息
    recipient_address = config['TRANSACTION']['recipient_address']
    amount_xmr = float(config['TRANSACTION']['amount_xmr'])
    amount_atomic = int(amount_xmr * 1E12)

    # 检查配置信息是否完整
    if not all([wallet_rpc_ip, wallet_rpc_port, recipient_address, amount_xmr]):
        print("请在 config/stem_tx_config.ini 文件中填写完整的钱包和交易信息。")
        return

    try:
        wallet = Wallet(ip=wallet_rpc_ip, port=wallet_rpc_port, rpc_user=wallet_rpc_user, rpc_password=wallet_rpc_password)

        # 显式指定 wallet-rpc 要连接的 monerod；否则它可能连到一个不可用/不允许查询的 daemon。
        if daemon_rpc_ip and daemon_rpc_port:
            set_daemon_params = {
                'address': f"{daemon_rpc_ip}:{daemon_rpc_port}",
            }
            if daemon_trusted is not None:
                set_daemon_params['trusted'] = daemon_trusted
            set_daemon_res = wallet.makeReq('set_daemon', set_daemon_params)
            if isinstance(set_daemon_res, dict) and 'error' in set_daemon_res:
                print("wallet-rpc set_daemon 失败：")
                print(set_daemon_res)
                return
    except Exception as e:
        print(f"连接钱包RPC或创建交易时出错: {e}")
        return

    try:
        daemon = Daemon(ip=target_node_ip, port=target_node_rpc_port)
    except Exception as e:
        print(f"连接目标节点 RPC 时出错: {e}")
        return

    print(f"目标节点: {target_node_ip}:{target_node_rpc_port}")
    print("开始循环：每 60 秒发送 1 笔交易（Ctrl+C 退出）")

    log_file_path = os.path.join(PROJECT_ROOT, 'Data', _today_str(), 'send_stem_tx.log')
    target_node = f"{target_node_ip}:{target_node_rpc_port}"
    _append_log(log_file_path, f"[{_now_str()}] start target={target_node} recipient={recipient_address} amount_atomic={amount_atomic}\n")
    print(f"日志文件: {log_file_path}")

    # while True:
    i = 0
    while i < 1:
        i += 1
        try:
            send_stem_transaction_once(
                wallet=wallet,
                daemon=daemon,
                recipient_address=recipient_address,
                amount_atomic=amount_atomic,
                target_node=target_node,
                log_file_path=log_file_path,
            )
        except KeyboardInterrupt:
            print("\n已退出。")
            _append_log(log_file_path, f"[{_now_str()}] exit\n")
            return
        except Exception as e:
            print(f"本轮发送出现异常: {e}")
            _append_log(log_file_path, f"[{_now_str()}] exception target={target_node} err={e}\n")

        time.sleep(60)


if __name__ == "__main__":
    send_stem_transaction_every_minute()
