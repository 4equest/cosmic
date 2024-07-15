
import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Union, Optional, Callable
from network_manager import NetworkManager, FlowTable
from scapy.all import IP, TCP, UDP, sniff

class NetworkWatcher(NetworkManager):
    def __init__(self,
                 sampling_period: int = 10,
                 flow_timeout: int = 60,
                 update_count_threshold: int = 5,
                 data_size_threshold: int = 1000,
                 update_count_threshold_syn: int = 3):
        """フローを監視し、規定値に達したフローをブロックリクエストリストに追加(ブロックはしないのでnetwork_blockerを利用してください)

        Args:
            sampling_period (int, optional):　パケットのサンプリング間隔
            flow_timeout (int, optional): フローのタイムアウト
            update_count_threshold (int, optional): ブロック対象にする更新回数の閾値
            data_size_threshold (int, optional): ブロック対象にするデータサイズの閾値
            update_count_threshold_syn (int, optional): ブロック対象にするSYNの受信回数の閾値
        """
        
        super().__init__()
        
        self.packet_count = 0
        self.sampling_period = sampling_period
        self.flow_table = FlowTable(flow_timeout, name="main_flow")
        self.flow_table_tcp_syn = FlowTable(flow_timeout, name="syn_flow")
        self.flow_table_selfestablished = FlowTable(flow_timeout, name="self_established")
        self.update_count_threshold = update_count_threshold
        self.data_size_threshold = data_size_threshold
        self.update_count_threshold_syn = update_count_threshold_syn
        
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor()
        
        self.block_request_list = []
        
    def __del__(self):
        pass
    
    def process_packet(self, payload) -> None:
        """パケット内容の監視を行う

        Args:
            payload : netfilter queueからのパケット
        """
        
        if not payload.haslayer(IP):
            return
        
        self.packet_count += 1
        packet = payload[IP]
        src_ip = packet.src
        dest_ip = packet.dst
        protocol = packet.proto
        
        if protocol == 1 or protocol == 89:  # ICMP or OSPFは無視する
            return
        
        current_time = time.time()

        if protocol == 6:  # TCP
            dest_port = packet[TCP].dport
            # TCP SYNパケットの処理
            if packet[TCP].flags == "S":  # SYNフラグのみがある場合
                key = self.flow_table.hash_flow(src_ip, dest_ip, dest_port, protocol)
                if src_ip in self.local_ips:
                    src_port = packet[TCP].sport
                    self.flow_table_selfestablished.update_flow(key, len(payload), current_time, src_ip = src_ip, dest_ip = dest_ip, dest_port = dest_port, protocol = 6)
                    receive_key = self.flow_table.hash_flow(dest_ip, src_ip, src_port, 6)
                    self.flow_table_selfestablished.update_flow(receive_key, len(payload), current_time, src_ip = dest_ip, dest_ip = src_ip, dest_port = src_port, protocol = 6)
                    return
                
                logging.debug(f"TCP SYN:{src_ip} to {dest_ip}:{dest_port}")
                self.flow_table_tcp_syn.update_flow(key, len(payload), current_time, src_ip, dest_ip, dest_port, protocol)
                self.block_request(self.flow_table_tcp_syn, self.update_count_threshold_syn)
                
        elif protocol == 17:  # UDP
            dest_port = packet[UDP].dport
        else:
            dest_port = 0
            
        # 自身のIPアドレスからのパケットは無視
        if packet.src in self.local_ips:
            return
        
        if self.packet_count % self.sampling_period == 0:
            key = self.flow_table.hash_flow(src_ip, dest_ip, dest_port, protocol)
            if self.flow_table_selfestablished.has_key(key):
                logging.debug(f"Self-established TCP flow:{src_ip} to {dest_ip}:{dest_port}")
                return
            
            self.flow_table.update_flow(key, len(payload), current_time, src_ip, dest_ip, dest_port, protocol)
            self.block_request(self.flow_table, self.update_count_threshold)

        return
    
    def block_request(self, flow_table: FlowTable, update_count_threshold: int) -> None:
        """規定値に達したフローをブロックリクエストリストに追加

        Args:
            flow_table (FlowTable): フローテーブル
            update_count_threshold (int): 更新回数の閾値
        """
        
        flows_to_block = flow_table.check_flows(update_count_threshold=update_count_threshold, data_size_threshold=self.data_size_threshold)
        with self.lock:
            for flow in flows_to_block:
                self.block_request_list.append({
                    "src_ip": flow["src_ip"],
                    "dest_ip": flow["dest_ip"],
                    "dest_port": flow["dest_port"],
                    "protocol": flow["protocol"]
                })
                flow_table.delete_flow(flow["key"])
                
            if self.callback and len(self.block_request_list) > 0:
                block_list_copy = self.block_request_list.copy()
                self.block_request_list = []
                self.executor.submit(self.block_request_callback, block_list_copy)
                
                
    def _start(self) -> None:
        """ネットワーク監視を開始"""
        
        self.running = True
        try:
            logging.info("Running the packet watcher loop...")
            sniff(prn=self.process_packet, store=False, stop_filter=(not self.running), count=0)
        except KeyboardInterrupt:
            logging.warning("Interrupted")
        except Exception as e:
            if not self.running:
                logging.error("Capture stopped intentionally.")
            else:
                raise e
        finally:
            self.running = False
            logging.info("Watcher stopped")
            
    def stop(self) -> None:
        """ネットワーク監視を停止"""
        
        logging.info("Stopping the watcher...")
        self.running = False
        
    def block_request_callback(self, block_list: List[Dict[str, Union[str, int]]]) -> None:
        """新規ブロック時のコールバックを非同期で実行

        Args:
            block_list (List[Dict[str, Union[str, int]]]): 新規ブロックリクエストリスト({src_ip, dest_ip, dest_port, protocol}の辞書のリスト)
        """
        
        self.callback(block_list)
        
    def pull_block_request_list(self) -> List[Dict[str, Union[str, int]]]:
        """ブロックリクエストリストを取得して削除

        Returns:
            List[Dict[str, Union[str, int]]]: ブロックリクエストリスト({src_ip, dest_ip, dest_port, protocol}の辞書のリスト)
        """
        
        with self.lock:
            block_list = self.block_request_list
            self.block_request_list = []
        return block_list
    
if __name__ == "__main__":
    
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s|%(levelname)-5s|%(message)s', datefmt='%Y/%m/%d %H:%M:%S')

    queue_num = 0
    sampling_period = 10
    flow_timeout = 60
    update_count_threshold = 5
    data_size_threshold = 1000
    update_count_threshold_syn = 3

    def display_block_request_list(block_request_list: List[Dict[str, Union[str, int]]]) -> None:
        """block_request_listの内容を表示"""
        print("Block Request List:")
        for entry in block_request_list:
            time.sleep(2) # 非同期確認用
            print(f"|src_ip: {entry['src_ip']}, dest_ip: {entry['dest_ip']}, dest_port: {entry['dest_port']}, protocol: {entry['protocol']}")
            
    network_watcher = NetworkWatcher(sampling_period, flow_timeout, update_count_threshold, data_size_threshold, update_count_threshold_syn)
    network_watcher.start(callback=display_block_request_list)

    try:
        while True:
            time.sleep(5)
                    
    except KeyboardInterrupt:
        print("Main thread interrupted")
    finally:
        network_watcher.stop()
