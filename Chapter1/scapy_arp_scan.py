#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import ipaddress
import time
from scapy_arp_request import scapy_arp_request
from multiprocessing import Process,Queue
def scapy_arp_scan(network):
	qyt_queue = Queue()
	net = ipaddress.ip_network(network)
	for ip in net:
		ip_addr = str(ip)#读取网络中的每一个IP地址，注意需要str转换为字符串！
		arp_one = Process(target=scapy_arp_request, args=(ip_addr,qyt_queue))
		arp_one.start()
	time.sleep(2)
	########队列常见方法#######
	#Queue.qsize() 返回队列的大小  
	#Queue.empty() 如果队列为空，返回True,反之False  
	#Queue.full() 如果队列满了，返回True,反之False 
	##########################
	#print(qyt_queue.qsize())
	ip_mac_list = []
	while True:
		if qyt_queue.empty():#如果队列为空，就退出循环！
			break
		else:
			ip,mac = qyt_queue.get()#如果不为空，就不断提取队列中的IP，MAC映射
			ip_mac_list.append((ip,mac))
	return ip_mac_list			

if __name__ == '__main__':
	import sys
	active_ip_mac = scapy_arp_scan(sys.argv[1])
	print('活动IP与MAC地址如下:')
	for ip,mac in active_ip_mac:
		print(ip,mac)
