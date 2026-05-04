import requests
from requests.auth import HTTPDigestAuth
import json
from json import JSONDecodeError
import urllib3

class Daemon:

    http = urllib3.PoolManager()
    
    def __init__(self, ip, port, rpc_user = "", rpc_password = "") -> None:
        self.ip = ip
        self.port = port
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.url = "http://" + ip + ":" + str(port)

    def makeJsonRpcReq(self, method, params):
        data = {
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        }
        headers = {"Content-Type": "application/json"}
        resp = requests.post(url=self.url + "/json_rpc", data=json.dumps(data), headers=headers, auth=HTTPDigestAuth(username=self.rpc_user,password=self.rpc_password))
        result = json.loads(resp.text)["result"]
        resp.close()
        return result
    
    def makeOtherReq(self, method, params):
        headers = {"Content-Type": "application/json"}
        resp = requests.post(url=self.url + "/" + method, data=json.dumps(params), headers=headers, auth=HTTPDigestAuth(username=self.rpc_user, password=self.rpc_password))
        while True:
            try:
                result = json.loads(resp.text)
                resp.close()
                return result
            except JSONDecodeError:
                print("JSONDecodeError")
                continue
    
    def makeOtherReq_v2(self, method, params):
        headers = {"Content-Type": "application/json"}
        resp = self.http.request("POST", self.url + "/" + method, body=json.dumps(params).encode('utf-8'), headers=headers)
        try:
            result = json.loads(resp.data)
            resp.close()
            return result
        except JSONDecodeError:
            print("JSONDecodeError")
            return None

    def send_raw_transaction(self, tx_as_hex: str, do_not_relay: bool = False):
        params = {
            # "ip": "",
            "tx_as_hex": tx_as_hex,
            "do_not_relay": do_not_relay
        }
        return self.makeOtherReq("send_raw_transaction", params=params)
    
    def get_peer_list(self):
        return self.makeOtherReq("get_peer_list", params={})
    
    def get_block_count(self):
        params = {}
        return self.makeJsonRpcReq("get_block_count", params)