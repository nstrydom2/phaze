from scapy.all import *
from scapy.layers.l2 import ARP

arp_packet = ARP()
print(">>> Before")
arp_packet.display()

arp_packet.pdst = '192.168.43.85' #(say IP address of target machine)
arp_packet.hwsrc = '11:11:11:11:11:11'
arp_packet.psrc = '1.1.1.1'
arp_packet.hwdst = 'ff:ff:ff:ff:ff:ff'

print(">>> After")
arp_packet.display()
