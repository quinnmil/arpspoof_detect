#!/usr/bin/#!/usr/bin/env python

import scapy.all as scapy
import argparse

# Create function to pass arguments while calling the program
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Set Interface")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface using -i or --interface options, use --help for more info.")
    return options

def get_mac(ip, interface):
    arp_req = scapy.ARP(pdst=ip)    # get an arp request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    # Set the destination mac address
    arp_broadcast = broadcast/arp_req   # combine the broadcast and request to send to the network
    answered = scapy.srp(arp_broadcast, iface=interface, timeout=1, verbose=False)[0]    # (scapy.srp) send and respond + allow ether frame for the answered resquests
    # return answered[0][1].hwsrc
    mac_address = None
    for element in answered:
        mac_address = element[1].hwsrc
    return mac_address

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)

def process_sniffed_packets(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc, options.interface)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac == response_mac:
                print("[+] Warning! ARP Spoofing  is on - you are under attack!!!")
            else:
                print("[+] ARP spoofing is off - carry on")
        except IndexError:
            pass

options = get_arguments()
sniffer(options.interface)
