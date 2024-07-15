import socket
import json
import logging
import time
import os
import threading
import argparse
import platform
from typing import Any, Dict, List, Union
from datetime import datetime, timedelta
from response_code import ResponseCode
from request_code import RequestCode
from network_blocker import NetworkBlocker, FlowTable
from scapy.all import IP, UDP, Raw

class CosmicServer:
    def __init__(self, config_path: str = "server_config.json"):
        """ルーターで起動されるサーバー

        Args:
            config_path (str, optional): 設定ファイルのパス
        """
        
        self.load_config(config_path)
        self.setup_logging()
        self.lock = threading.Lock()
        self.network_blocker = NetworkBlocker(
            queue_num=self.queue_num,
            block_timeout_minutes=self.block_timeout_minutes,
            cosmic_server_port=self.server_port,
            cosmic_packet_callback=self.cosmic_packet_callback
        )
        self.network_blocker.start()
        self.server_socket = None
        self.MAGIC = "_COSMIC_"

    def load_config(self, config_path: str):
        """サーバーの設定を読み込む

        Args:
            config_path (str): 設定ファイルのパス
        """
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        self.buffer_size = config.get("BUFFER_SIZE", 1024)
        self.log_dir = config.get("LOG_DIR", "server_logs")
        self.server_ip = config.get("SERVER_IP", "0.0.0.0")
        self.server_port = config.get("SERVER_PORT", 31014)
        self.queue_num = config.get("queue_num", 0)
        self.block_timeout_minutes = config.get("block_timeout_minutes", 5)
        
    def cosmic_packet_callback(self, packet):
        """CosmicPacketに対するコールバック関数

        Args:
            packet : CosmicPacket
        """
        
        # MAGICが存在すればcosmic packetとして処理する
        packet_data = packet[Raw].load.decode()
        packet_magic = packet_data[:8]
        packet_data = packet_data[8:]
        if packet_magic == self.MAGIC:
            self.handle_client(packet_data, (packet[IP].src, packet[UDP].sport))

    def setup_logging(self):
        """ログを設定する"""
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        hostname = platform.node()
        server_log_file = f'{self.log_dir}/server-{hostname}-{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.log'
        logging.basicConfig(level=logging.DEBUG, filename=server_log_file, format='%(asctime)s|%(levelname)-5s|%(message)s', datefmt='%Y/%m/%d %H:%M:%S')

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter('%(asctime)s|%(levelname)-5s|'+hostname+'|%(message)s', datefmt='%H:%M:%S'))
        logging.getLogger().addHandler(console_handler)

    def handle_banner_request(self, addr: tuple):
        """バナーを返す

        Args:
            addr (tuple): 送信元アドレス
        """
        
        hostname = platform.node()
        response = {
            "status": ResponseCode.OK,
            "banner": {
                "name": hostname,
                "version": "1.0.0",
                "description": "Cosmic Server"
            }
        }
        self.server_socket.sendto(json.dumps(response).encode('utf-8'), addr)

    def handle_add_request(self, addr: tuple, data: Dict[str, Any]):
        """新しい攻撃情報を追加する

        Args:
            addr (tuple): 送信元アドレス
            data (Dict[str, Any]): 攻撃情報(フロー情報)
        """
        
        new_attack_info = data.get("attack_info", [])
        with self.lock:
            for attack in new_attack_info:
                key = FlowTable.hash_flow(attack["src_ip"], attack["dest_ip"])
                existing = self.network_blocker.blocked_flow_table.has_key(key)
                if existing:
                    response = {
                        "status": ResponseCode.ALREADY_BLOCKED,
                        "msg": "Already blocked"
                    }
                    logging.info(f"Already blocked: {attack}")
                    self.server_socket.sendto(json.dumps(response).encode('utf-8'), addr)
                    return
                
                attack["timestamp"] = time.time()
                self.network_blocker.add_blocked_flow(attack["src_ip"], attack["dest_ip"])
            
            response = {
                "status": ResponseCode.OK,
                "msg": "OK"
            }
        logging.info(f"Added new attack: {new_attack_info}")
        self.server_socket.sendto(json.dumps(response).encode('utf-8'), addr)

    def handle_info_request(self, addr: tuple):
        """攻撃情報を返す

        Args:
            addr (tuple): 送信元アドレス
        """
        
        with self.lock:
            response = {
                "status": ResponseCode.OK,
                "attacker_info": self.network_blocker.get_blocked_flows()
            }
        logging.info(f"Info request response: {response}")
        self.server_socket.sendto(json.dumps(response).encode('utf-8'), addr)

    def handle_client(self, data: str, addr: tuple):
        """クライアントからのリクエスト処理

        Args:
            data (str): リクエストデータ
            addr (tuple): 送信元アドレス
        """
        
        try:
            data = json.loads(data)
            method = data.get("method")

            if method == RequestCode.BANNER:
                self.handle_banner_request(addr)
            elif method == RequestCode.ADD:
                self.handle_add_request(addr, data)
            elif method == RequestCode.INFO:
                self.handle_info_request(addr)
            else:
                response = {
                    "status": ResponseCode.INVALID_METHOD,
                    "msg": "Invalid method"
                }
                logging.warning(f"Invalid method: {method}")
                self.server_socket.sendto(json.dumps(response).encode('utf-8'), addr)
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    def start_server(self):
        """Cosmic Serverを起動する"""
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.server_ip, self.server_port))
        
        logging.info(f"Server started at {self.server_ip}:{self.server_port}")

        try:
            while True:
                data, addr = self.server_socket.recvfrom(self.buffer_size)
                logging.info(f"Accepted connection from {addr}")
                threading.Thread(target=self.handle_client, args=(data.decode('utf-8'), addr)).start()
        except KeyboardInterrupt:
            pass
        # except Exception as e:
        #    logging.error(f"An error occurred: {e}")
        finally:
            self.network_blocker.stop()

        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cosmic Server")
    parser.add_argument("--config", type=str, default="server_config.json", help="Path to server config file")
    args = parser.parse_args()

    server = CosmicServer(args.config)
    server.start_server()
