#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import ipaddress
import time
import multiprocessing
from scapy_ping_one_new import scapy_ping_one
from scapy.all import *
def scapy_ping_scan(network):
	net = ipaddress.ip_network(network)
	ip_list = []
	for ip in net:
		ip_list.append(str(ip))
	pool = multiprocessing.Pool(processes=300)
	result = pool.map(scapy_ping_one, ip_list)
	scan_list = []
	for ip,ok in result:
		if ok == 1:
			scan_list.append(ip)
	return(sorted(scan_list))

if __name__ == '__main__':
	import time
	t1 = time.time()
	print('活动IP地址如下:')
	for ip in scapy_ping_scan(sys.argv[1]):
		print(str(ip))
	t2= time.time()
	print(t2-t1)
