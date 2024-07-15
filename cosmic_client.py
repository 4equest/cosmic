import socket
import json
import logging
import threading
import time
import os
import subprocess
import asyncio
import argparse
import platform
import threading
from typing import Any, Dict, List, Union
from datetime import datetime
from response_code import ResponseCode
from request_code import RequestCode
from network_watcher import NetworkWatcher
from network_blocker import NetworkBlocker

class CosmicClient:
    def __init__(self, config_path: str):
        """防御対象のサーバーで起動されるクライアント

        Args:
            config_path (str): 設定ファイルのパス
        """
        
        self.load_config(config_path)
        self.setup_logging()
        self.network_watcher = NetworkWatcher(
            sampling_period=self.sampling_period,
            flow_timeout=self.flow_timeout,
            update_count_threshold=self.update_count_threshold,
            data_size_threshold=self.data_size_threshold,
            update_count_threshold_syn=self.update_count_threshold_syn
        )
        
        self.network_watcher.start(callback=self.request_block_request_list)
        
        if self.self_blocking:
            self.network_blocker = NetworkBlocker(
                queue_num=self.queue_num,
                block_timeout_minutes=self.block_timeout_minutes
            )
            self.network_blocker.start()
            
        self.lock = threading.Lock()
        self.MAGIC = b"_COSMIC_"
        
        
    def load_config(self, config_path: str):
        """クライアントの設定を読み込む

        Args:
            config_path (str): クライアントの設定ファイルのパス
        """
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        self.buffer_size = config.get("BUFFER_SIZE", 1024)
        self.log_dir = config.get("LOG_DIR", "client_logs")
        self.server_port = config.get("SERVER_PORT", 31014)
        self.sampling_period = config.get("NetworkWatcher", {}).get("sampling_period", 10)
        self.flow_timeout = config.get("NetworkWatcher", {}).get("flow_timeout", 60)
        self.update_count_threshold = config.get("NetworkWatcher", {}).get("update_count_threshold", 5)
        self.data_size_threshold = config.get("NetworkWatcher", {}).get("data_size_threshold", 1000)
        self.update_count_threshold_syn = config.get("NetworkWatcher", {}).get("update_count_threshold_syn", 3)
        self.self_blocking = config.get("self_blocking", True)
        self.queue_num = config.get("NetworkBlocker", {}).get("queue_num", 0)
        self.block_timeout_minutes = config.get("NetworkBlocker", {}).get("block_timeout_minutes", 5)
        self.log_level = config.get("LOG_LEVEL", "INFO")
        
    def setup_logging(self):
        """ログの設定"""
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        client_log_file = f'{self.log_dir}/client-{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.log'
        logging.basicConfig(level=self.log_level, filename=client_log_file, format='%(asctime)s|%(levelname)-5s|%(message)s', datefmt='%Y/%m/%d %H:%M:%S')

        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(logging.Formatter('%(asctime)s|%(levelname)-5s|%(message)s', datefmt='%H:%M:%S'))
        logging.getLogger().addHandler(console_handler)

    def send_data_to_server(self, ip: str, port: int, data: str) -> Dict[str, Any]:
        """Cosmic Serverにデータを送信

        Args:
            ip (str): Cosmic Server/攻撃者のIPアドレス(経路上のCosmic Serverすべてに通達するため)
            port (int): Comic Serverのポート
            data (str): 送信するデータ

        Returns:
            Dict[str, Any]: Cosmic Serverからのレスポンス
        """
        
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.sendto(self.MAGIC + data.encode('utf-8'), (ip, port))
            logging.info(f"Sent data: {data}")
            
            client.settimeout(1)
            response, addr = client.recvfrom(self.buffer_size, )
            logging.info(f"Received response: {response.decode('utf-8')} IP: {addr[0]}")
            return json.loads(response.decode('utf-8'))
        except socket.timeout:
            logging.error(f"Request timed out: {ip}:{port}")
            return {"status": ResponseCode.TIMEOUT}
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            raise e

    def send_banner_request(self, ip: str, port: int) -> Dict[str, Any]:
        """Cosmic ServerにBANNERリクエストを送信

        Args:
            ip (str): Cosmic server/攻撃者のIPアドレス
            port (int): Cosmic serverのポート

        Returns:
            Dict[str, Any]: Cosmic Serverからのレスポンス
        """
        
        banner_request = json.dumps({"method": RequestCode.BANNER})
        return self.send_data_to_server(ip, port, banner_request)

    def send_add_request(self, ip: str, port: int, attack_info: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Cosmic ServerにADDリクエストを送信

        Args:
            ip (str): Cosmic server/攻撃者のIPアドレス
            port (int): Cosmic serverのポート
            attack_info (List[Dict[str, Any]]): 攻撃情報

        Returns:
            Dict[str, Any]: Cosmic Serverからのレスポンス
        """
        
        add_request = {
            "method": RequestCode.ADD,
            "attack_info": attack_info
        }
        return self.send_data_to_server(ip, port, json.dumps(add_request))

    def send_info_request(self, ip: str, port: int) -> Dict[str, Any]:
        """Cosmic ServerにINFOリクエストを送信

        Args:
            ip (str): Cosmic server/攻撃者のIPアドレス
            port (int): Cosmic serverのポート

        Returns:
            Dict[str, Any]: Cosmic Serverからのレスポンス
        """
        
        info_request = json.dumps({"method": RequestCode.INFO})
        return self.send_data_to_server(ip, port, info_request)

    async def _search_cosmic_server(self, ips: List[str], port: int) -> Dict[str, Dict[str, Any]]:
        """Cosmic Serverを探索(async)

        Args:
            ips (List[str]): 探索するIPアドレスのリスト
            port (int): Cosmic Serverのポート

        Returns:
            Dict[str, Dict[str, Any]]: 探索結果(Cosmic ServerのIPアドレスをkeyとしたBANNER情報)
        """
        
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(None, self.send_banner_request, ip, port) for ip in ips]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        result = {}
        for ip, response in zip(ips, responses):
            if isinstance(response, dict) and response.get("status") == ResponseCode.OK:
                result[ip] = response.get("banner", {})
        return result

    def search_cosmic_server(self, ips: List[str], port: int) -> Dict[str, Dict[str, Any]]:
        """Cosmic Serverを探索

        Args:
            ips (List[str]): 探索するIPアドレスのリスト
            port (int): Cosmic Serverのポート

        Returns:
            Dict[str, Dict[str, Any]]: 探索結果(Cosmic ServerのIPアドレスをkeyとしたBANNER情報)
        """
        return asyncio.run(self._search_cosmic_server(ips, port))

    def traceroute(self, ip: str) -> List[str]:
        """traceroute

        Args:
            ip (str): IPアドレス

        Returns:
            List[str]: traceroute結果のIPアドレスのリスト
        """
        result = subprocess.run(["traceroute", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.split("\n")
        ip_list = []
        for line in output:
            parts = line.split()
            if len(parts) > 2 and "(" in parts[2] and ")" in parts[2]:
                ip_list.append(parts[2].strip("()"))
        return ip_list
    
    def request_block_request_list(self, block_request_list: List[Dict[str, Any]]) -> None:
        """ブロックリクエストリストをCosmic Serverに送信
        
        Args:
            block_request_list (List[Dict[str, Any]]): ブロックリクエストを格納したリスト
            
        """
        
        if self.lock.locked():
            return
        
        with self.lock:
            logging.info(f"Request block request list: {block_request_list}")
            for block_request in block_request_list:
                if self.network_blocker.has_blocked_flow(block_request["src_ip"], block_request["dest_ip"]):
                    self.network_blocker.add_blocked_flow(block_request["src_ip"], block_request["dest_ip"])
                    # continue
                if self.self_blocking:
                    self.network_blocker.add_blocked_flow(block_request["src_ip"], block_request["dest_ip"])
                #traceroute_result = self.traceroute(block_request["src_ip"])
                """
                cosmic_server_list = self.search_cosmic_server(traceroute_result, self.server_port)
                for ip in cosmic_server_list.keys():
                    add_response = self.send_add_request(ip, self.server_port, block_request_list)
                    logging.info(f"Add request response from {ip}: {add_response}")
                """
                # for ip in traceroute_result:
                add_response = self.send_add_request(block_request["src_ip"], self.server_port, block_request_list)
                logging.info(f"Add request response : {add_response}")
                
                """
                for ip in traceroute_result:
                    info_response = self.send_info_request(ip, self.server_port)
                    logging.info(f"request response from {ip}: {info_response}")
                """

    def start(self):
        """Cosmic Client処理を開始"""
        
        try:
            while self.network_watcher.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.network_watcher.stop()
            if self.self_blocking:
                self.network_blocker.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cosmic Client")
    parser.add_argument("--config", type=str, default="client_config.json", help="Path to client config file")
    args = parser.parse_args()

    client = CosmicClient(args.config)
    client.start()
