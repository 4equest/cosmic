sudo apt-get update
sudo apt-get install build-essential python3-dev libnetfilter-queue-dev httperf -y
sudo systemctl disable apache2 && sudo systemctl stop apache2
sudo pip install scapy NetfilterQueue netifaces
