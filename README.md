# cosmic
Network-based DDoS protection. Linux routers PoC.

# 使い方
Debian/Ubuntu環境での[COREemu](https://github.com/coreemu/core)の利用を想定しています。

## ルーター
`server_config.json`の設定を確認後、ルーター内で
```bash
python3 cosmic_server.py
```
で起動できます。

## クライアント(防御対象)
`client_config.json`の設定を確認後、防御対象のサーバー内で
```bash
python3 cosmic_client.py
```
で起動できます。

# Demo
## setup
1. `./scripts/final_1.imn`のネットワークにテスト用の仮想ネットワークがあります。[COREemu](https://github.com/coreemu/core)で読み込んでください。
2. `setup.sh`をCOREemuを動作させているホスト側で実行してください。
3. apacheのenvvars内の各種ファイルの場所を読み書き可能なディレクトリに設定してください。
4. apach2.conf内でServerNameを適当なものに設定してください。
5. クライアント側ノードで`./scripts/start_apache2.sh`か、それと同等のコマンドを実行すればwebサーバーが起動します。
6. `./scripts/final_1_cosmic_start.py`内の`cosmic_command`の値を適切なパスに設定してください。 その後、ホスト側で実行することでCORE内のルーターで`cosmic_server.py`が実行されます。
7. クライアント側ノードで`cosmic_client.py`を実行します。
8. ホスト側で`./scripts/final_1_attack_start.py`を実行すると疑似的な攻撃が開始されます

## video

https://github.com/user-attachments/assets/4f7e0d1d-588c-422a-b956-27de0bb7a4be

