import time
import requests
import redis

r = redis.Redis(
    host="127.0.0.1",
    port=6379,
    password="2024111",
    decode_responses=True
)

RPC_URL = "http://127.0.0.1:18285/json_rpc"

payload = {
    "jsonrpc": "2.0",
    "id": "0",
    "method": "get_last_block_header"
}

headers = {
    "Content-Type": "application/json"
}

while True:
    try:
        resp = requests.post(RPC_URL, json=payload, headers=headers)
        data = resp.json()

        block_header = data["result"]["block_header"]

        # 转换 bool → string
        for k, v in block_header.items():
            if isinstance(v, bool):
                block_header[k] = str(v)

        r.hset("monero", mapping=block_header)

        print("Updated height:", block_header["height"])

    except Exception as e:
        print("Error:", e)

    time.sleep(1)
