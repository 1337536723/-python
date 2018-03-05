#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import ipaddress
import time
import multiprocessing
from scapy_ping_one import scapy_ping_one
from scapy.all import *
def scapy_ping_scan(network):
	net = ipaddress.ip_network(network)
	ip_processes = {}
	for ip in net:
		ip_addr = str(ip)#读取网络中的每一个IP地址，注意需要str转换为字符串！
		ping_one = multiprocessing.Process(target=scapy_ping_one, args=(ip_addr,))
		ping_one.start()
		ip_processes[ip_addr] = ping_one#产生IP与进程对应的字典
	ip_list = []
	for ip, process in ip_processes.items():
		if process.exitcode == 3:#退出码为3表示Ping成功！
			ip_list.append(ip)#把活动IP地址放入ip_list
		else:
			process.terminate()
	return sorted(ip_list)
if __name__ == '__main__':
	import time
	t1 = time.time()
	active_ip = scapy_ping_scan(sys.argv[1])
	print('活动IP地址如下:')
	for ip in active_ip:
		print(ip)
	t2= time.time()
	print(t2-t1)
