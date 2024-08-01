from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import IP, UDP
import sqlite3

unauthorized_network = "192.168.2."
unauthorized_next_ip = 2

def get_ip_for_mac(mac):
    global unauthorized_next_ip
    conn = sqlite3.connect('authorized_devices.db')
    c = conn.cursor()
    c.execute('SELECT expected_network, authorized FROM devices WHERE mac = ?', (mac,))
    result = c.fetchone()
    conn.close()
    if result and result[1] == 1:  # Authorized
        return result[0]
    else:
        ip = unauthorized_network + str(unauthorized_next_ip)
        unauthorized_next_ip += 1
        return ip

def handle_dhcp_packet(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        mac = packet[Ether].src
        ip = get_ip_for_mac(mac)
        dhcp_offer = Ether(src=get_if_hwaddr(conf.iface), dst=mac) / IP(src="192.168.1.1", dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=ip, siaddr="192.168.1.1", chaddr=packet[BOOTP].chaddr) / DHCP(options=[("message-type", "offer"), ("server_id", "192.168.1.1"), ("lease_time", 600), ("subnet_mask", "255.255.255.0"), ("router", "192.168.1.1"), "end"])
        sendp(dhcp_offer, iface=conf.iface)

sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet, iface=conf.iface)