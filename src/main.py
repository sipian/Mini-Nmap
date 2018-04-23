import os
import arpPoison

from scapy.all import *
from argparse import ArgumentParser as AP

p = AP()
p.add_argument('--timeout', type=int, default=1000, help='Timeout duration in microseconds')
p.add_argument('--interface', type=str, required=True, help='Interface to use for the experiment')
p.add_argument('--gatewayIP', type=str, required=True, help='Gateway IP address')
p.add_argument('--verbose', action='store_true', help='Toggle to enable full verbosity')
p = p.parse_args()

raise NotImplementedError("In progress")
