#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from collections import *
from ipaddress import *

#命名元组
ForwardItem = namedtuple('ForwardItem', ['ip', 'next_hop', 'intf'])     #转发表项
ARPSendInfo = namedtuple('ARPSendInfo', ['send_time', 'remain_times', 'wait_packs', 'intf'])  #存储ARP发送信息

class Node:
    def __init__(self, key, value):
        self.key, self.value = key, value
        self.prev = self.next = self

    def add_next(self, node):
        node.next = self.next
        node.prev = self
        self.next.prev = node
        self.next = node

    def remove(self):
        self.next.prev = self.prev
        self.prev.next = self.next

class DictQueue:
    def __init__(self):
        self.node = Node(None, None)
        self.map = {}
        self.size = 0

    def push(self, key, value):
        self.node.add_next(Node(key, value))
        self.map[key] = self.node.next
        self.size += 1

    def peek(self):
        if self.size == 0:
            return None
        return self.node.prev

    def pop(self):
        if self.size == 0:
            return None
        p = self.node.prev
        p.remove()
        self.map.pop(p.key)
        self.size -= 1
        return p

    def remove(self, key):
        if self.size == 0 or key not in self.map:
            return None
        p = self.map[key]
        p.remove()
        self.map.pop(p.key)
        self.size -= 1
        return p.value

    def get(self, key):
        if self.size == 0 or key not in self.map:
            return None
        return self.map[key].value
        
#转发表
class ForwardTable:
    def __init__(self):
        self.table = []
    
    def add(self, ip, next_hop, intf):
        self.table.append(ForwardItem(ip, next_hop, intf))
    
    def search(self, ip):
        try:
            return max(filter(lambda item: ip in item.ip, self.table), key=lambda item: item.ip.prefixlen)
            #filter函数过滤出包含目标IP地址的转发项，然后max函数找到前缀长度最长的转发项
        except ValueError:
            return None

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {}    #ARP表
        self.forward_table = ForwardTable()  #转发表
        self.arp_send = DictQueue()    #ARP发送队列
        self.build_forward_table()
        
    #构建转发表
    def build_forward_table(self):
        for intf in self.net.interfaces():
            ipintf = intf.ipinterface.network
            self.forward_table.add(ipintf, IPv4Address('0.0.0.0'), intf)
        table_file = open('forwarding_table.txt', 'r')
        for line in table_file:
            ip, mask, next_hop, intf = line.split()
            self.forward_table.add(IPv4Network(f'{ip}/{mask}'), IPv4Address(next_hop), self.net.port_by_name(intf))
        table_file.close()
        log_info(f"forward table: {self.forward_table.table}")

    #检查给定的IP地址是否属于路由器的任何一个接口
    def is_ip_in_router(self, ip):
        return ip in [intf.ipaddr for intf in self.net.interfaces()]

    def handle_arp(self, arp, iface):
        if self.arp_table.get(arp.senderprotoaddr) != arp.senderhwaddr:
            #收到的ARP消息中的发送者IP地址已经在ARP表中，但是对应的MAC地址与发送者MAC地址不同
            self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr  #更新ARP表中对应的条目
            log_info(f'Update ARP Table: {self.arp_table}')
        if self.is_ip_in_router(arp.targetprotoaddr):
            #检查目标IP地址是否属于路由器的任何一个接口，是：根据ARP操作类型执行相应的操作
            if arp.operation == ArpOperation.Request:
                #ARP请求
                intf = self.net.interface_by_ipaddr(arp.targetprotoaddr)   #根据目标 IP 地址找到对应的接口
                pkt = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr) #创建 ARP 响应报文
                log_info(f"get request, reply arp {pkt} to {iface}")
                self.net.send_packet(iface, pkt)     #将其发送到接收到 ARP 消息的接口
            else:
                #ARP响应
                wait_packs = self.arp_send.remove(arp.senderprotoaddr) #从 ARP 发送队列中取出等待发送的数据包
                if wait_packs is not None:
                    for wait_pack in wait_packs.wait_packs:
                        wait_pack[Ethernet].dst = arp.senderhwaddr    #并将目标 MAC 地址替换为收到的 ARP 消息中的发送者 MAC 地址
                        log_info(f"get reply, send pend ip {wait_pack} to {wait_packs.intf}")
                        self.net.send_packet(wait_packs.intf, wait_pack)    #然后将数据包发送到相应的接口

    def handle_ip(self, ip, packet):
        packet[IPv4].ttl -= 1    #将 IP 报头中的 TTL 字段递减 1
        forward =  None if self.is_ip_in_router(ip.dst) else self.forward_table.search(ip.dst)
        #数据包是针对路由器本身的（即目标地址在路由器的接口中），则只需丢弃/忽略该数据包
        #否则，从转发表中查找下一跳MAC地址
        if forward is not None:
            log_info(f"forward table hit {forward}")
            next_hop_ip = ip.dst if forward.next_hop == IPv4Address('0.0.0.0') else forward.next_hop
            next_hop = self.arp_table.get(next_hop_ip)
            packet[Ethernet].src = forward.intf.ethaddr    #根据转发表中的信息更新数据包的源 MAC 地址，
            if next_hop is not None:
                #找到了下一跳MAC地址
                packet[Ethernet].dst = next_hop    #更新数据包的目的 MAC 地址为下一跳地址的 MAC 地址
                log_info(f"arp cache hit: {next_hop}, send ip {packet} to {forward.intf}")
                self.net.send_packet(forward.intf, packet)    #并将数据包发送到转发表中指定的接口
            else:
                #没有找到下一跳地址对应的 MAC 地址
                log_info(f"arp cache miss, pend ip {packet}")
                wait_packs = self.arp_send.get(next_hop_ip)    #将数据包添加到 ARP 发送队列中，并等待 ARP 响应。
                
                if wait_packs is None:
                    self.arp_send.push(next_hop_ip, ARPSendInfo(0, 5, [packet], forward.intf))
                else:
                    wait_packs.wait_packs.append(packet)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        #检查数据包是否是 ARP 数据包
        if arp is not None:
            log_info(f"receive a arp packet {ifaceName} {arp}")
            self.handle_arp(arp, self.net.port_by_name(ifaceName))
        else:
            ip = packet.get_header(IPv4)    #是否是 IPv4 数据包
            if ip is not None:
                log_info(f"receive a ip packet {ifaceName} {ip}")
                self.handle_ip(ip, packet)
                
    #定时重新发送 ARP 请求
    def resend_arp(self):
        while self.arp_send.peek() and time.time() - self.arp_send.peek().value.send_time >= 1:
            #循环检查 ARP 发送队列中是否有需要重新发送的 ARP 请求，并检查上次发送时间距离当前时间是否超过了1秒
            node = self.arp_send.pop()
            key, value = node.key, node.value
            if value.remain_times > 0:
                #满足条件，取出待发送的 ARP 请求
                arp = create_ip_arp_request(value.intf.ethaddr, value.intf.ipaddr, key)
                log_info(f"resend {key}, {value} {arp}")
                self.net.send_packet(value.intf, arp)
                self.arp_send.push(key, ARPSendInfo(time.time(), value.remain_times - 1, value.wait_packs, value.intf))
                #更新发送时间及剩余发送次数，然后重新发送 ARP 请求。

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            self.resend_arp()

            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    type(net.interfaces()[0]).__repr__ = lambda self: self.name
    router = Router(net)
    router.start()
