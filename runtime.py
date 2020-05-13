import sys
from proxy import TransparentProxy


try:
    print("[*] Starting transparent proxy...")

    trans_proxy = TransparentProxy('wlan0', '192.168.1.1', '192.168.1.144')
    trans_proxy.process_spooftraffic()
    trans_proxy.sniff_traffic()
except KeyboardInterrupt:
    sys.exit(0)
except Exception as ex:
    sys.exit(1)
finally:
    print("[*] Exiting...")
