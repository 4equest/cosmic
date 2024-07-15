import time
import logging
from typing import List, Dict, Union, Optional, Callable
from network_manager import NetworkManager, FlowTable
from scapy.all import IP, TCP, UDP

class NetworkBlocker(NetworkManager):
    def __init__(self,
                 queue_num: int = 0,
                 block_timeout_minutes: int = 1,
                 cosmic_server_port: int = 31014,
                 cosmic_packet_callback = None
                 ):
        """ブロック対象のネットワークフローを管理

        Args:
            queue_num (int, optional): Netfilter queueの番号
            block_timeout_minutes (int, optional): ブロック対象のフローの期限
            cosmic_server_port (int, optional): cosmic serverのポート
            cosmic_packet_callback (_type_, optional): cosmic packetに対するコールバック関数
        """
        
        super().__init__(queue_num)
        self.blocked_flow_table = FlowTable(block_timeout_minutes * 60, name="blocked_flow")
        self.cosmic_server_port = cosmic_server_port
        self.cosmic_packet_callback = cosmic_packet_callback

    def process_packet(self, payload) -> None:
        """ブロック対象のネットワークフローをブロックする また、cosmic packetに対してcallbackを発行

        Args:
            payload : netfilter queueからのパケット
        """
        
        data = payload.get_payload()
        packet = IP(data)
        src_ip = packet.src
        dest_ip = packet.dst
        protocol = packet.proto
        
        if protocol == 6:  # TCP
            dest_port = packet[TCP].dport
        elif protocol == 17:  # UDP
            dest_port = packet[UDP].dport
            if self.cosmic_packet_callback is not None and dest_port == self.cosmic_server_port:
                self.cosmic_packet_callback(packet)
        else:
            dest_port = 0

        key = FlowTable.hash_flow(src_ip, dest_ip, dest_port, protocol)
        if self.blocked_flow_table.has_key(key):
            self.blocked_flow_table.remove_expired_flows(time.time())
            if self.blocked_flow_table.has_key(key):
                logging.info(f"Blocked flow dropped:{src_ip} to {dest_ip}:{dest_port}")
                payload.drop()
                return
                
        payload.accept()
        return
        
    def add_blocked_flow(self, src_ip: str, dest_ip: str, dest_port: int = 80, protocol: int = 6) -> None:
        """フローをブロック対象に追加

        Args:
            src_ip (str): src_ip
            dest_ip (str): dest_ip
            dest_port (int, optional): dest_port. Defaults to 80(HTTP)
            protocol (int, optional): protocol number. Defaults 6(TCP)
        """
        
        key = FlowTable.hash_flow(src_ip, dest_ip, dest_port, protocol)
        self.blocked_flow_table.update_flow(key, 0, time.time(), src_ip = src_ip, dest_ip = dest_ip, dest_port = dest_port, protocol = protocol)

    def has_blocked_flow(self, src_ip: str, dest_ip: str, dest_port: int = 80, protocol: int = 6) -> bool:
        """フローがブロック対象に追加されているか

        Args:
            src_ip (str): src_ip
            dest_ip (str): dest_ip
            dest_port (int, optional): dest_port. Defaults to 80(HTTP)
            protocol (int, optional): protocol number. Defaults 6(TCP)

        Returns:
            bool: フローがブロック対象に追加されているか
        """
        
        key = FlowTable.hash_flow(src_ip, dest_ip, dest_port, protocol)
        return self.blocked_flow_table.has_key(key)
    
    def get_blocked_flows(self) -> List[Dict[str, Union[str, int]]]:
        """ブロック対象のフローを取得

        Returns:
            List[Dict[str, Union[str, int]]]: ブロック対象のフロー({src_ip, dest_ip, dest_port, protocol}の辞書のリスト)
        """
        
        flow_table =  self.blocked_flow_table.get_table()
        result = []
        for key in list(flow_table.keys()):
            result.append({
                "src_ip": flow_table[key]["src_ip"],
                "dest_ip": flow_table[key]["dest_ip"],
                "dest_port": flow_table[key]["dest_port"],
                "protocol": flow_table[key]["protocol"],
            })
            
        return result