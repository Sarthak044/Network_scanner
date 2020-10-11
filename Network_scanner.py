#!/usr/bin/env python
# Algo used 
#Step 1 - Create a arp request to broadcast mac to get ip 
#Step 2 - Send the packet, recieve the respose
#Step 3 - Analyse the response
#Step 4 - Print the result
#For python 3 you have to download the module scapy to run this file(pip install scapy-python3)
#optparse is depreciated to I used argparse.. funtions are the same but names are different 
import argparse
import scapy.all as scapy
from pyfiglet import Figlet

#Banner<DO NOT TOUCH ELSE I WILL FIND YOU AND TICKLE YOU TO DEATH>
fig = Figlet(font='greek')
print(fig.renderText("ProGod404"))
print("ENTER THE RANGE OF IP ADDRESS\n For Example: 192.168.0.255/24")
def get_args():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t", "--target",dest="ip",help= "IP Address range to scan")
    options=parser.parse_args()
    if not options.ip :
        parser.error("ENTER THE IP ADDRESS TO SCAN, USE --help")
    else:
        return options
        

def scan(ip):
    arp = scapy.ARP(pdst=ip)
    broad = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broad = broad/arp
    answer = scapy.srp(arp_broad, timeout=1, verbose=False)[0]
    client_list = []
    for i in answer:
        client_dict = {"IP":i[1].psrc, "MAC": i[1].hwdst}
        client_list.append(client_dict)
    return client_list

def scan_result(result_list):
    print("IP\t\t\tMAC Address\n--------------------------------------")
    for j in result_list:
        print(j["IP"]+ "\t\t" + j["MAC"])
    
options=get_args()
result = scan(options.ip)
scan_result(result)
