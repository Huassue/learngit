#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import * # pylint: disable=unused-wildcard-import
import ipaddress
from queue import Queue

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = {iface.name: iface for iface in net.interfaces()}  # 获取配置的接口信息
        self.arp_cache = {}  # 创建一个空的ARP缓存表
        self.forwarding_table = self.build_forwarding_table()  # 构建转发表
        self.arp_queue = Queue()
        self.arp_request_list = []
        self.cnt = 0

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv  # pylint: disable=unused-variable
        self.cnt += 1
        log_warn(f"{self.cnt}")
        # TODO: your logic here
        # 检查以太网目的地址是否为广播地址或者传入端口的 MAC 地址
        eth_dst = packet.get_header(Ethernet).dst
        # log_warn(f"dst_mac:{eth_dst}")
        if eth_dst != EthAddr("ff:ff:ff:ff:ff:ff") and eth_dst != self.interfaces[ifaceName].ethaddr:
            return  #  如果以太网目的地既不是广播地址，也不是传入端口的MAC地址，路由器应该总是丢弃它，而不是通过查找过程。
        
        vlan = packet.get_header(Vlan)
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)
        if vlan:
            log_warn(f"VLAN ARP packet detected.")
            return 
        elif arp:
            log_warn(f"arp_{arp.operation}  src_ip:{arp.senderprotoaddr}, dst_ip:{arp.targetprotoaddr}， src_mac:{arp.senderhwaddr}, 到达接口:{ifaceName}")
            self.handle_arp(arp, ifaceName)
        elif ipv4:
            log_warn(f"ipv4  src_ip:{packet.get_header(IPv4).src}, dst_ip:{packet.get_header(IPv4).dst}")
            self.handle_ipv4(packet, ifaceName)
            

    def handle_ipv4(self, packet: Packet, ifaceName: str):
        if packet.get_header(IPv4).dst in [iface.ipaddr for name, iface in self.interfaces.items()]:
            return 
        if packet.get_header(IPv4).total_length + packet.get_header(Ethernet).size() != packet.size():
            return
            
        longest_match = None
        longest_prefixlen = 0
        destination_address = packet.get_header(IPv4).dst

        for item, entry in self.forwarding_table.items(): 
            prefixnet = IPv4Network(f"{item.network_address}/{entry['network_mask']}")
            if destination_address in prefixnet:
                if prefixnet.prefixlen > longest_prefixlen:
                    longest_prefixlen = prefixnet.prefixlen
                    longest_match = entry

        if longest_match:
            self.forward_packet(packet, longest_match, ifaceName)
        else:
            # Handle the case when there's no match in the forwarding table
            # For now, just drop the packet
            log_info(f"No matching entry for destination address {destination_address}, dropping packet.")

    def handle_arp(self, arp: Arp, ifaceName: str):
        # 检查是否为ARP请求(request)
        if arp.operation == ArpOperation.Request:
            # 查找目标IP地址是否在路由器接口中
            for iface_name, iface in self.interfaces.items(): # pylint: disable=unused-variable
                if iface.ipaddr == arp.targetprotoaddr:
                    # 更新缓存的ARP表项(ip->mac)
                    self.arp_cache[arp.senderprotoaddr] = arp.senderhwaddr
                    # 如果目标IP地址在接口列表中，创建并发送ARP响应
                    log_warn(f"Send ARP reply via {ifaceName} to {arp.senderprotoaddr}")
                    arp_reply = create_ip_arp_reply(iface.ethaddr, arp.senderhwaddr, iface.ipaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, arp_reply)
        
        # 检查是否为ARP回复(reply)
        elif arp.operation == ArpOperation.Reply:
            if arp.senderhwaddr != EthAddr("ff:ff:ff:ff:ff:ff"):
                # 更新缓存的ARP表项(ip->mac)
                for iface_name, iface in self.interfaces.items(): # pylint: disable=unused-variable
                    if iface.ipaddr == arp.targetprotoaddr:
                        self.arp_cache[arp.senderprotoaddr] = arp.senderhwaddr
                # 从列表中找到要转发的数据包并且移除它
                if arp.senderprotoaddr.exploded in self.arp_request_list:
                    self.arp_request_list.remove(arp.senderprotoaddr.exploded)
                # 从队列中找到要转发的数据包并且移除它
                for pkt_info in list(self.arp_queue.queue):
                    if IPv4Address(pkt_info['dst_eth_ip']) == arp.senderprotoaddr:
                        pkt_info['packet'][Ethernet].src = self.interfaces[pkt_info['ifaceName']].ethaddr
                        pkt_info['packet'][Ethernet].dst = arp.senderhwaddr

                        self.net.send_packet(pkt_info['ifaceName'], pkt_info['packet'])
                        self.arp_queue.queue.remove(pkt_info)

    def forward_packet(self, packet: Packet, entry: dict, ifaceName: str): #这里的ifaceame是接收端口
        # Decrement the TTL field
        packet.get_header(IPv4).ttl -= 1
        # 获取转发的目标ip地址
        dst_eth_ip = None
        if entry['next_hop_ip'] == '0.0.0.0':
            dst_eth_ip = packet.get_header(IPv4).dst.exploded
        else:
            dst_eth_ip = entry['next_hop_ip']
        # 根据ip地址来查找arp缓存表里面有没有条目
        dst_eth_addr = self.arp_cache.get(IPv4Address(dst_eth_ip))
        # 如果没有，看是否发过arp请求
        if dst_eth_addr is None:
            # 如果没有发过，那就要发送arp请求更新arp缓存表
            if dst_eth_ip not in self.arp_request_list:
                log_warn(f"Send ARP request via {entry['interface']} to {dst_eth_ip}")
                self.send_arp_request(dst_eth_ip, entry['interface'])
                self.arp_request_list.append(dst_eth_ip)
            # 如果没有条目，将收到的数据包放入队列
            pkt_info = {
                'packet': packet,
                'dst_eth_ip': dst_eth_ip,
                'ifaceName': entry['interface'],
                'last_sent': time.time(),
                'retries': 1
            }
            self.arp_queue.put(pkt_info)
        else:
            # 如果有，直接转发数据包
            packet[Ethernet].src = self.interfaces[entry['interface']].ethaddr
            packet[Ethernet].dst = dst_eth_addr

            self.net.send_packet(entry['interface'], packet)


    def send_arp_request(self, ip_addr: IPv4Address, ifaceName: str):
        arp_request = create_ip_arp_request(self.interfaces[ifaceName].ethaddr, self.interfaces[ifaceName].ipaddr, ip_addr)
        self.net.send_packet(ifaceName, arp_request)


    def check_arp_queue(self):
        items_to_remove = []

        for dst_eth_ip in self.arp_request_list:
            for pkt_info in self.arp_queue.queue:
                if dst_eth_ip == pkt_info['dst_eth_ip']:
                    if time.time() - pkt_info['last_sent'] > 1:
                        # Check if we have already sent 5 requests for this IP address
                        if pkt_info['retries'] < 5:
                            # Increment the retry count and update the last sent time
                            pkt_info['retries'] += 1
                            pkt_info['last_sent'] = time.time()
                            
                            # Send another ARP request
                            arp_request = create_ip_arp_request(self.interfaces[pkt_info['ifaceName']].ethaddr, self.interfaces[pkt_info['ifaceName']].ipaddr, pkt_info['dst_eth_ip'])
                            self.net.send_packet(pkt_info['ifaceName'], arp_request)
                            log_warn(f"Send ARP request via {pkt_info['ifaceName']} to {pkt_info['dst_eth_ip']} again")
                        else:
                            # If we have sent 5 requests without receiving a reply, drop the packet
                            log_info(f"No ARP reply after 5 retries for {pkt_info['dst_eth_ip']}, dropping packet.")
                            items_to_remove.append(dst_eth_ip)
                            for pkt in list(self.arp_queue.queue):
                                if pkt['dst_eth_ip'] == pkt_info['dst_eth_ip']:
                                    self.arp_queue.queue.remove(pkt)
                    break #只要找到相同ip地址的数据包（发送arp request的那个包），无论后续操作如何，最后肯定要退出循环
        
        for item in items_to_remove:  
            self.arp_request_list.remove(item)


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.check_arp_queue()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()

    def build_forwarding_table(self):
        '''
        构建转发表
        '''
        forwarding_table = {}
        # 获取接口信息
        for iface_name, iface in self.interfaces.items(): # pylint: disable=unused-variable
            network_address = ipaddress.ip_network(f"{iface.ipaddr}/{iface.netmask}", strict=False)
            forwarding_table[network_address] = {
                'network_mask': iface.netmask.exploded,
                'next_hop_ip': '0.0.0.0',
                'interface': iface.name
            }
        # 从文件读取转发表项
        with open("forwarding_table.txt", "r") as file:
            for line in file:
                parts = line.split()
                network_address = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
                forwarding_table[network_address] = {
                    'network_mask': parts[1],
                    'next_hop_ip': parts[2],
                    'interface': parts[3]
                }

        for network_address, entry in forwarding_table.items():
            log_warn(f"Network Address: {network_address}, Mask: {entry['network_mask']}, Next Hop IP: {entry['next_hop_ip']}, Interface: {entry['interface']}")
        return forwarding_table

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()