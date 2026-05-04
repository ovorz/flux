from time import time
import random
from io import BytesIO
from collections import OrderedDict

from levin.constants import *
from levin.ctypes import *
from levin.utils import ip2int


class Section:
    def __init__(self):
        self.entries = OrderedDict()

    def add(self, key: str, entry: object):
        self.entries[key] = entry

    def __len__(self):
        return len(self.entries.keys())

    @classmethod
    def from_byte_array(cls, buffer: BytesIO):
        from levin.reader import LevinReader

        x = LevinReader(buffer)
        section = x.read_payload()
        return section

    @classmethod
    def handshake_request(cls, my_port: int, network_id: bytes, peer_id: bytes):
        if network_id == NETWORK_ID_MAINNET:
            genesis_hash = GENESIS_HASH_MAINNET
        elif network_id == NETWORK_ID_TESTNET:
            genesis_hash = GENESIS_HASH_TESTNET

        section = cls()

        # node_data
        node_data = Section()
        node_data.add("my_port", c_uint32(my_port))
        node_data.add("network_id", c_string(network_id))
        node_data.add("peer_id", c_uint64(peer_id))
        node_data.add("support_flags", P2P_SUPPORT_FLAGS)
        section.add("node_data", node_data)

        # payload_data
        payload_data = Section()
        payload_data.add("cumulative_difficulty", c_uint64(0))
        payload_data.add("cumulative_difficulty_top64", c_uint64(0))
        payload_data.add("current_height", c_uint64(0))
        payload_data.add("top_id", c_string(genesis_hash))
        payload_data.add("top_version", c_ubyte(1))

        section.add("payload_data", payload_data)
        return section

    @classmethod
    def handshake_response(
        cls, my_port: int, network_id: bytes, peer_id: bytes, peerlist: list
    ):
        if network_id == NETWORK_ID_MAINNET:
            genesis_hash = GENESIS_HASH_MAINNET
        elif network_id == NETWORK_ID_TESTNET:
            genesis_hash = GENESIS_HASH_TESTNET

        section = cls()

        # local_peerlist_new
        local_peerlist_new = []
        for malicious_node in peerlist:
            m_ip = c_uint32(ip2int(malicious_node[0]))
            m_port = c_uint16(malicious_node[1])
            peer = Section()
            adr = Section()
            addr = Section()
            addr.add("m_ip", m_ip)
            addr.add("m_port", m_port)
            type = c_ubyte(1)
            adr.add("addr", addr)
            adr.add("type", type)
            peer.add("adr", adr)
            peer.add("id", c_uint64(random.getrandbits(64)))
            local_peerlist_new.append(peer)

        section.add("local_peerlist_new", local_peerlist_new)

        # node_data
        node_data = Section()
        node_data.add("my_port", c_uint32(my_port))
        node_data.add("network_id", c_string(network_id))
        node_data.add("peer_id", c_uint64(peer_id))
        node_data.add("support_flags", P2P_SUPPORT_FLAGS)
        section.add("node_data", node_data)

        # payload_data
        payload_data = Section()
        payload_data.add("cumulative_difficulty", c_uint64(0))
        payload_data.add("cumulative_difficulty_top64", c_uint64(0))
        payload_data.add("current_height", c_uint64(0))
        payload_data.add("top_id", c_string(genesis_hash))
        payload_data.add("top_version", c_ubyte(1))
        section.add("payload_data", payload_data)
        # 创建并添加peerlist
        return section

    @classmethod
    def timed_sync_request(cls, network_id: bytes, peer_id: bytes):
        if network_id == NETWORK_ID_MAINNET:
            genesis_hash = GENESIS_HASH_MAINNET
        elif network_id == NETWORK_ID_TESTNET:
            genesis_hash = GENESIS_HASH_TESTNET

        section = cls()

        # payload_data
        payload_data = Section()
        payload_data.add("cumulative_difficulty", c_uint64(0))
        payload_data.add("cumulative_difficulty_top64", c_uint64(0))
        payload_data.add("current_height", c_uint64(0))
        payload_data.add("top_id", c_string(genesis_hash))
        payload_data.add("top_version", c_ubyte(1))
        section.add("payload_data", payload_data)
        return section

    @classmethod
    def timed_sync_response(
        cls,
        my_port: int = None,
        network_id: bytes = None,
        peer_id: bytes = None,
        malicious_peerlist: list = None,
    ):
        if network_id == NETWORK_ID_MAINNET:
            genesis_hash = GENESIS_HASH_MAINNET
        elif network_id == NETWORK_ID_TESTNET:
            genesis_hash = GENESIS_HASH_TESTNET
        if not peer_id:
            peer_id = random.getrandbits(64)

        section = cls()

        local_peerlist_new = []
        for malicious_node in malicious_peerlist:
            m_ip = c_uint32(ip2int(malicious_node[0]))
            m_port = c_uint16(malicious_node[1])
            peer = Section()
            adr = Section()
            addr = Section()
            addr.add("m_ip", m_ip)
            addr.add("m_port", m_port)
            type = c_ubyte(1)
            adr.add("addr", addr)
            adr.add("type", type)
            peer.add("adr", adr)
            peer.add("id", c_uint64(random.getrandbits(64)))
            local_peerlist_new.append(peer)

        section.add("local_peerlist_new", local_peerlist_new)

        # add "node_data" key
        node_data = Section()
        node_data.add("my_port", c_uint32(my_port))
        node_data.add("network_id", c_string(network_id))
        node_data.add("peer_id", c_uint64(peer_id))
        node_data.add("support_flags", P2P_SUPPORT_FLAGS)
        section.add("node_data", node_data)

        # add "payload_data" key
        payload_data = Section()
        payload_data.add("cumulative_difficulty", c_uint64(0))
        payload_data.add("cumulative_difficulty_top64", c_uint64(0))
        payload_data.add("current_height", c_uint64(0))
        payload_data.add("top_id", c_string(genesis_hash))
        payload_data.add("top_version", c_ubyte(1))
        section.add("payload_data", payload_data)
        return section
    
    @classmethod
    def ping_response(cls, peer_id: bytes):
        section = cls()
        section.add("peer_id", c_uint64(peer_id))
        section.add("status", c_string(b"\x4f\x4b"))
        return section

    @classmethod
    def create_flags_response(cls):
        section = cls()
        section.add("support_flags", P2P_SUPPORT_FLAGS)
        return section

    @classmethod
    def stat_info_request(cls, peer_id: bytes = None):
        if not peer_id:
            peer_id = random.getrandbits(64)

        signature = bytes.fromhex(
            "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"
        )

        section = cls()
        proof_of_trust = Section()
        proof_of_trust.add("peer_id", c_uint64(peer_id))
        proof_of_trust.add("time", c_uint64(int(time())))
        proof_of_trust.add("sign", c_string(signature))

        section.add("proof_of_trust", proof_of_trust)

        return section

    def __bytes__(self):
        from levin.writer import LevinWriter

        writer = LevinWriter()
        buffer = writer.write_payload(self)
        buffer.seek(0)
        return buffer.read()
