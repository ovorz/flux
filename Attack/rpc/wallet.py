import requests
from requests.auth import HTTPDigestAuth
import json
from json import JSONDecodeError
import urllib3
from pprint import pprint

class Wallet:

    http = urllib3.PoolManager()

    destination = {
        "amount": None,
        "address": None,
    }

    XMR = int(1E12)

    def __init__(self, ip, port, rpc_user, rpc_password) -> None:
        self.ip = ip
        self.port = port
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.url = "http://" + ip + ":" + str(port) + "/json_rpc"
        self.auto_refresh()
        print("Auto refresh wallet OK.")
    
    def makeReq(self, method, params):
        data = {
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        }
        headers = {"Content-Type": "application/json"}
        try:
            resp = requests.post(url=self.url, data=json.dumps(data), headers=headers, auth=HTTPDigestAuth(username=self.rpc_user,password=self.rpc_password))
        except Exception as e:
            print(e)
            resp.close()
            return None
        try:
            result = json.loads(resp.text)
            if "result" in result:
                return result["result"]
            elif 'error' in result:
                return result
        except Exception as e:
            print(e)
            resp.close()
            return None
    
    def makeReq_v2(self, method, params):
        data = {
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        }
        headers = {"Content-Type": "application/json"}
        resp = self.http.request("POST", self.url, body=json.dumps(params).encode('utf-8'), headers=headers)
        try:
            result = json.loads(resp.data)
            resp.close()
            return result
        except JSONDecodeError:
            print("JSONDecodeError")
            return None
        
    def auto_refresh(self):
        params = {
            "enable": True,
            "period": 2,
        }
        return self.makeReq_v2("auto_refresh", params=params)
    
    def transfer(self, destinations: list, # 主要的参数
                #  account_index: int = 0, subaddr_indices: [int] = [], # 花费位置选择
                #  prioriry: int = 0, mixin: int = 0, ring_size: int = 16, unlock_time: int = 0, # 其他参数设置
                unlock_time: int = 0,
                get_tx_key: bool = False, do_not_relay: bool = False, get_tx_hex: bool = False, get_tx_metadata: bool = False):
        params = {
            "destinations": destinations,
            "get_tx_key": get_tx_key,
            "unlock_time": unlock_time,
            "do_not_relay": do_not_relay,
            "get_tx_hex": get_tx_hex,
            "get_tx_metadata": get_tx_metadata
        }
        return self.makeReq("transfer", params=params)
    
    def relay_tx(self, hex: str):
        params = {
            "hex": hex
        }
        return self.makeReq("relay_tx", params)
    
    def get_balance(self, account_index: int = 0):
        params = {
            "account_index": account_index
        }
        return self.makeReq("get_balance", params)
    
    def incoming_transfers(self, transfer_type: str = "available", account_index: int = 0):
        params = {
            "transfer_type": transfer_type,
            "account_index": account_index
        }
        return self.makeReq("incoming_transfers", params)
    

    def sweep_single(
        self, address: str, key_image: str, outputs: int = 1, unlock_time: int = 0,
        do_not_relay: bool = False, get_tx_hex: bool = False, get_tx_metadata: bool = False
    ):
        params = {
            "address": address,
            "key_image": key_image,
            "outputs": outputs,
            "unlock_time": unlock_time,
            "do_not_relay": do_not_relay,
            "get_tx_hex": get_tx_hex,
            "get_tx_metadata": get_tx_metadata
        }
        return self.makeReq("sweep_single", params)

    # 将所有的unspent outputs发往一个地址
    def sweep_all(
        self, address: str, account_index = 0, 
        do_not_relay: bool = False, get_tx_hex: bool = False, get_tx_metadata: bool = False
    ):
        params = {
            "address": address,
            "account_index": account_index,
            "do_not_relay": do_not_relay,
            "get_tx_hex": get_tx_hex,
            "get_tx_metadata": get_tx_metadata
        }
        return self.makeReq("sweep_all", params)
    
    def refresh(self, start_height: int):
        params = {
            "start_height": start_height,
        }
        return self.makeReq("refresh", params)