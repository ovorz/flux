import logging
import sys
import struct
import socket
from io import BytesIO

from levin_sync.section import Section
from levin_sync.constants import *
from levin_sync.exceptions import BadArgumentException
from levin_sync.ctypes import *

log = logging.getLogger()


class Bucket:
    def __init__(self):
        self.signature = LEVIN_SIGNATURE
        if self.signature != LEVIN_SIGNATURE:
            raise BadArgumentException("Bender's nightmare")

        self.cb = None
        self.return_data = None
        self.command = None
        self.return_code = None
        self.flags = None
        self.protocol_version = None
        self.payload_section = None

    @classmethod
    def create_request(
        cls, command: int, payload: bytes = None, section: Section = None
    ):
        bucket = cls()

        bucket.return_data = c_bool(True)
        bucket.command = c_uint32(command)
        bucket.return_code = c_uint32(0)
        bucket.flags = LEVIN_PACKET_REQUEST
        bucket.protocol_version = LEVIN_PROTOCOL_VER_1

        if payload:
            bucket.cb = c_uint64(len(payload))
            bucket.payload_section = payload

        if section:
            bucket.payload_section = bytes(section)
            bucket.cb = c_uint64(len(bucket.payload_section))

        return bucket

    @classmethod
    def create_response(cls, command: int, payload: bytes):
        bucket = cls()
        bucket.payload_section = payload
        bucket.cb = c_uint64(len(payload))
        bucket.return_data = c_bool(False)
        bucket.command = c_uint32(command)
        bucket.return_code = c_uint32(1)
        bucket.flags = LEVIN_PACKET_RESPONSE
        bucket.protocol_version = LEVIN_PROTOCOL_VER_1

        return bucket

    @staticmethod
    def create_handshake_request(
        my_port: int,
        network_id: bytes,
        peer_id: bytes,
        block_height: int = 0,
    ):
        """
        Helper function to create a handshake request. Does not require
        parameters but you can use them to impersonate a legit node.
        :param my_port: defaults to 0
        :param network_id: defaults to mainnet
        :param peer_id:
        :param verbose:
        :return:
        """
        handshake_section = Section.handshake_request(
            peer_id=peer_id, network_id=network_id, my_port=my_port, block_height=block_height
        )
        bucket = Bucket.create_request(
            P2P_COMMAND_HANDSHAKE.value, section=handshake_section
        )

        log.debug(">> created packet '%s'" % P2P_COMMANDS[bucket.command])

        return bucket

    @staticmethod
    def create_handshake_response(
        my_port: int,
        network_id: bytes,
        peer_id: bytes,
        peerlist: list = [],
        block_height: int = 0,
    ):
        handshake_section = Section.handshake_response(
            my_port=my_port, network_id=network_id, peer_id=peer_id, peerlist=peerlist, block_height=block_height
        )

        bucket = Bucket.create_response(
            P2P_COMMAND_HANDSHAKE.value,
            payload=bytes(handshake_section),
        )

        log.debug(
            ">> create handshake response packet '%s'" % P2P_COMMANDS[bucket.command]
        )

        return bucket

    @staticmethod
    def create_timed_sync_request(
        network_id: bytes,
        peer_id: bytes,
        block_height: int = 0,
    ):
        timed_sync_section = Section.timed_sync_request(
            network_id=network_id, peer_id=peer_id, block_height=block_height
        )
        bucket = Bucket.create_request(
            P2P_COMMAND_TIMED_SYNC.value, section=timed_sync_section
        )

        # log.debug(
        #     ">> create timed_sync request packet '%s'" % P2P_COMMANDS[bucket.command]
        # )

        return bucket

    @staticmethod
    def create_timed_sync_response(
        my_port: int,
        network_id: bytes,
        peer_id: bytes,
        malicious_peerlist: list,
        block_height: int = 0,
    ):
        timed_sync_section = Section.timed_sync_response(
            my_port=my_port,
            network_id=network_id,
            peer_id=peer_id,
            malicious_peerlist=malicious_peerlist,
            block_height=block_height,
        )

        bucket = Bucket.create_response(
            P2P_COMMAND_TIMED_SYNC.value,
            payload=bytes(timed_sync_section),
        )
        # log.debug(
        #     ">> create timed_sync response packet '%s'" % P2P_COMMANDS[bucket.command]
        # )

        return bucket

    @staticmethod
    def create_ping_request():
        bucket = Bucket.create_request(P2P_COMMAND_PING.value)
        log.debug(">> create ping request packet '%s'" % P2P_COMMANDS[bucket.command])

        return bucket

    @staticmethod
    def create_ping_response(peer_id: bytes):
        ping_section = Section.ping_response(peer_id=peer_id)
        bucket = Bucket.create_response(
            P2P_COMMAND_PING.value,
            payload=bytes(ping_section)
        )
        log.debug(
            ">> create ping response packet '%s'" % P2P_COMMANDS[bucket.command]
        )
        return bucket

    @staticmethod
    def create_stat_info_request(
        peer_id: bytes = b"\x41\x41\x41\x41\x41\x41\x41\x41",
    ):
        stat_info_section = Section.stat_info_request(peer_id=peer_id)
        log.debug(stat_info_section.entries["proof_of_trust"].entries.keys())
        bucket = Bucket.create_request(
            P2P_COMMAND_REQUEST_STAT_INFO.value, section=stat_info_section
        )

        log.debug(">> created packet '%s'" % P2P_COMMANDS[bucket.command])
        return bucket

    @classmethod
    def from_buffer(cls, signature: c_uint64, sock: socket.socket, recv_buffer: bytearray = None):
        if isinstance(signature, bytes):
            signature = c_uint64(signature)
        bucket = cls()
        bucket.signature = signature

        # 尝试读取头部字段
        try:
            # 使用切片获取数据，而不是直接修改缓冲区
            current_pos = 8  # 跳过signature的8字节
            
            # 读取cb (8字节)
            if len(recv_buffer) < current_pos + 8:
                return None
            bucket.cb = c_uint64.from_buffer(sock, recv_buffer=recv_buffer[current_pos:current_pos+8])
            if bucket.cb is None:
                return None
            current_pos += 8
            # print(f"bucket.cb: {bucket.cb.value}")

            # 读取return_data (1字节)
            if len(recv_buffer) < current_pos + 1:
                return None
            bucket.return_data = c_bool.from_buffer(sock, recv_buffer=recv_buffer[current_pos:current_pos+1])
            if bucket.return_data is None:
                return None
            current_pos += 1
            # print(f"bucket.return_data: {bucket.return_data}")

            # 读取command (4字节)
            if len(recv_buffer) < current_pos + 4:
                return None
            bucket.command = c_uint32.from_buffer(sock, recv_buffer=recv_buffer[current_pos:current_pos+4])
            if bucket.command is None:
                return None
            current_pos += 4
            # print(f"bucket.command: {bucket.command}")

            # 读取return_code (4字节)
            if len(recv_buffer) < current_pos + 4:
                return None
            bucket.return_code = c_int32.from_buffer(sock, recv_buffer=recv_buffer[current_pos:current_pos+4])
            if bucket.return_code is None:
                return None
            current_pos += 4
            # print(f"bucket.return_code: {bucket.return_code}")

            # 读取flags (4字节)
            if len(recv_buffer) < current_pos + 4:
                return None
            bucket.flags = c_uint32.from_buffer(sock, recv_buffer=recv_buffer[current_pos:current_pos+4])
            if bucket.flags is None:
                return None
            current_pos += 4
            # print(f"bucket.flags: {bucket.flags}")

            # 读取protocol_version (4字节)
            if len(recv_buffer) < current_pos + 4:
                return None
            bucket.protocol_version = c_uint32.from_buffer(sock, recv_buffer=recv_buffer[current_pos:current_pos+4])
            if bucket.protocol_version is None:
                return None
            # print(f"bucket.protocol_version: {bucket.protocol_version}")

            # 如果所有字段都成功读取，返回bucket对象
            return bucket

        except BlockingIOError:
            # 数据未就绪，返回None表示需要等待更多数据
            return None
        except Exception as e:
            log.error(f"Error parsing bucket: {str(e)}")
            return None

    def header(self):
        return b"".join(
            (
                bytes(LEVIN_SIGNATURE),
                bytes(self.cb),
                b"\x01" if self.return_data.value else b"\x00",
                bytes(self.command),
                bytes(self.return_code),
                bytes(self.flags),
                bytes(self.protocol_version),
            )
        )

    def payload(self):
        return self.payload_section

    def get_peers(self):
        # helper function to retreive peerlisting where buckets.command was 1001
        if self.command != 1001 and self.command != 1002:
            raise Exception("Only handshake has peerlisting")

        peers = []

        if "local_peerlist_new" not in self.payload_section.entries:
            return

        for peer in [
            e.entries for e in self.payload_section.entries["local_peerlist_new"]
        ]:
            if "adr" not in peer or "addr" not in peer["adr"].entries:
                continue

            addr = peer["adr"].entries["addr"].entries
            ipv4 = True if "m_ip" in addr else False
            if not ipv4 and not "addr" in addr:
                continue

            if ipv4 and len(addr["m_ip"]) == 4:
                m_ip, m_port = addr["m_ip"], addr["m_port"]
                m_ip = c_uint32(m_ip.to_bytes(), endian="big")
            elif len(addr["addr"]) == 16:
                m_ip, m_port = addr["addr"], addr["m_port"]
                m_ip = c_uint64(m_ip, endian="big")
            else:
                continue

            peers.append({"ip": m_ip, "port": m_port})

        return peers

    def get_rpc_port(self) -> int:
        if "node_data" not in self.payload_section.entries:
            return 0
        if "rpc_port" not in self.payload_section.entries["node_data"].entries:
            return 0
        return self.payload_section.entries["node_data"].entries["rpc_port"]

    @classmethod
    def print_bytes_hex(self, data, bytes_per_group=2, groups_per_line=8):
        hex_str = " ".join(["{:02X}".format(b) for b in data])
        grouped_str = " ".join(
            hex_str[i : i + bytes_per_group * 2]
            for i in range(0, len(hex_str), bytes_per_group * 2)
        )
        lines = [
            grouped_str[i : i + groups_per_line * bytes_per_group * 3]
            for i in range(0, len(grouped_str), groups_per_line * bytes_per_group * 3)
        ]
        formatted_output = "\n".join(lines)
        print(formatted_output)
