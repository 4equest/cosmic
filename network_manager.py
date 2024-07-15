import time
import netifaces
import json
import hashlib
import threading
import os
import asyncio
import logging
from typing import List, Dict, Union, Optional, Callable
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP

def get_local_ip() -> List[str]:
    """自身のローカルIPアドレスを取得

    Returns:
        List[str]: 自身のローカルIPアドレスリスト
    """
    
    interfaces = netifaces.interfaces()
    local_ips = []
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                local_ips.append(ip)
    return local_ips

class FlowTable:
    def __init__(self, timeout: int = 60, name: str = "flow_table"):
        """フローテーブル

        Args:
            timeout (int, optional): 各フローのタイムアウト秒数
            name (str, optional): フローテーブル名
        """
        
        self.table = {}
        self.timeout = timeout
        self.name = name

    @staticmethod
    def hash_flow(src_ip: str, dest_ip: str, dest_port: int = 80, protocol: int = 6) -> str:
        """フローをハッシュ化"""
        flow_id = f"{src_ip}->{dest_ip}:{dest_port}::{protocol}"
        return hashlib.md5(flow_id.encode()).hexdigest()

    def update_flow(self, key: str, data_size: int, current_time: float, src_ip: str, dest_ip: str, dest_port: int, protocol: int) -> int:
        """フローの更新

        Returns:
            int: 0 ならば新規、1 ならば更新
        """
        
        return_code = 0
        current_time = time.time()
        self.remove_expired_flows(current_time)
        
        if key not in self.table:
            self.table[key] = {
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "total_data_size": data_size,
                "first_seen": current_time,
                "last_seen": current_time,
                "update_count": 1
            }
            logging.debug(f"Flow {self.name} entry {key} created")
            return_code = 1
        else:
            self.table[key]["total_data_size"] += data_size
            self.table[key]["last_seen"] = current_time
            self.table[key]["update_count"] += 1
            logging.debug(f"Flow {self.name} entry {key} updated")
        
        logging.debug(f"Flow table {self.name} updated: {json.dumps(self.table, indent=4)}")
        return return_code

    def remove_expired_flows(self, current_time: float) -> None:
        """タイムアウトしたフローを削除"""
        keys_to_delete = [key for key, value in self.table.items() if current_time - value["last_seen"] > self.timeout]
        for key in keys_to_delete:
            del self.table[key]
            logging.debug(f"Flow {self.name} entry {key} deleted due to timeout")

    def check_flows(self, update_count_threshold: Optional[int] = None, data_size_threshold: Optional[int] = None) -> List[Dict[str, Union[str, int, float]]]:
        """規定値に当てはまるデータをリストで返す"""
        result = []
        for key, value in self.table.items():
            if (update_count_threshold is not None and value["update_count"] >= update_count_threshold) or \
               (data_size_threshold is not None and value["total_data_size"] >= data_size_threshold):
                result.append({"key": key, **value})
        return result
    
    def get_flow(self, key: str) -> Optional[Dict[str, Union[str, int, float]]]:
        """指定されたkeyのフローを取得"""
        if key in self.table:
            return self.table[key].copy()
        else:
            return None
        
    def get_table(self) -> Dict[str, Dict[str, Union[str, int, float]]]:
        """フローテーブルを取得"""
        return self.table.copy()
    
    def has_key(self, key: str) -> bool:
        """指定されたkeyのフローを持っているかどうか"""
        return key in self.table

    def delete_flow(self, key: str) -> None:
        """指定されたkeyのフローを削除"""
        if key in self.table:
            del self.table[key]
            logging.debug(f"Flow {self.name} entry {key} deleted")
class NetworkManager:
    def __init__(self, queue_num: int = 0):
        """ネットワーク管理基底クラス

        Args:
            queue_num (int, optional): netfilter queueの番号
        """
        
        self.queue_num = queue_num
        self.local_ips = get_local_ip()
        self.watcher_thread = None
        self.queue = NetfilterQueue()
        self.running = False
        self.callback = None
        
        
    def __del__(self):
        self.cleanup_iptables()

    def process_packet(self, payload) -> None:
        """パケットを処理

        Args:
            payload (_type_): netfilter queueからのパケット

        Raises:
            NotImplementedError: 未実装エラー
        """
        
        raise NotImplementedError
                
    def start(self, callback: Callable[[List[Dict[str, Union[str, int]]]], None] = None) -> None:
        """ネットワーク監視スレッドを開始

        Args:
            callback (Callable[[List[Dict[str, Union[str, int]]]], None], optional): ネットワーク監視結果をコールバックする関数
        """
        
        self.callback = callback
        watcher_thread = threading.Thread(target=self._start, daemon = True)
        watcher_thread.start()

    def _start(self) -> None:
        """ネットワーク監視を開始"""
        
        self.setup_iptables()
        
        self.queue.bind(self.queue_num, self.process_packet)
        self.running = True
        try:
            logging.info("Running the packet interception loop...")
            self.queue.run()
        except KeyboardInterrupt:
            logging.warning("Interrupted")
        except Exception as e:
            if not self.running:
                logging.error("Queue stopped intentionally.")
            else:
                raise e
        finally:
            self.queue.unbind()
            self.cleanup_iptables()

    def stop(self) -> None:
        """ネットワーク監視を停止"""
        
        logging.info("Stopping Network Manager...")
        self.running = False
        self.cleanup_iptables()
        logging.info("Network Manager stopped")
        
    def setup_iptables(self) -> None:
        """iptablesをセットアップ"""
        
        logging.info("Setting up iptables...")
        os.system(f"iptables -I OUTPUT -j NFQUEUE --queue-num {self.queue_num}")
        os.system(f"iptables -I INPUT -j NFQUEUE --queue-num {self.queue_num}")
        os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}")

    def cleanup_iptables(self) -> None:
        """iptablesをクリーンアップ"""
        
        logging.info("Cleaning up iptables...")
        os.system(f"iptables -D OUTPUT -j NFQUEUE --queue-num {self.queue_num}")
        os.system(f"iptables -D INPUT -j NFQUEUE --queue-num {self.queue_num}")
        os.system(f"iptables -D FORWARD -j NFQUEUE --queue-num {self.queue_num}")

