import requests
import scapy.all as scapy
from utiliities import red, green, yellow,cyan
import socket

class Network():
    def __init__(self,main_domain=""):
        self.main_domain = main_domain
        self.ip_load_b = {}

    def http_ip_header(self, url, method):
        pass

    def packet_handler(self,packet:scapy.Packet,iface=None,verbose=False):
        if iface is None:
            iface = "wlan0"
        # check the ip at which the computer is connected
        # find out the ip of this 
        ip = scapy.get_if_addr(iface)
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
            if dst == ip:# filter out all packets comming to the ip
                if sport == 443: # filter out packets from webservers
                    try:
                        ip_address_info= socket.gethostbyaddr(src)
                        self.ip_load_b[src]= ip_address_info[0]
                        if verbose:
                            print(f"\t {yellow('IP resolves to :')} {ip_address_info[0]}")
                    except:
                        print("failed to resolve to ip")
                        self.ip_load_b[src]= "unresolved"
                        pass
                    if verbose:
                        print(f"{cyan('Found https packet with source IP')}: {src}")

    def detect_loadbalancer(self,url):
        print(f"{red('This functionality should be run with all browsers closed to make sure the only http taffic coming to the ip is from the GET requests being made by the function')}")
        # sniffer
        sniffer = scapy.AsyncSniffer(prn= self.packet_handler, filter = 'tcp port 80 or tcp port 443 or tcp port 8080',
                               iface = "wlan0")
        sniffer.start()
        idx = 0
        while idx < 3:
            response= requests.get(url=url)
            # print(response.status_code)
            idx += 1
        sniffer.stop()
        repeating_domains= set()
        for domain in list(self.ip_load_b.keys()):
            if domain not in repeating_domains:
                repeating_domains.add(domain)
        if len(repeating_domains) > 1:
            print(f"{red('Load balancer present')}")
            print(f"\t {yellow('Repeating ips::')}")
            [print(f"\t\t{ip} : {self.ip_load_b[ip]}") for ip in repeating_domains]    
        else:
            print(cyan('No repeating ips'))
            [print(f"{cyan(f'all ips resolve to')} : {ip}: {self.ip_load_b[ip]}") for ip in repeating_domains]
            print(f"{cyan('Load balancer likey not present')}")
