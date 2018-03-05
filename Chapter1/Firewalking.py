#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

conf.route.add(net='10.1.1.0/24',gw='202.100.1.10')#可以为Scapy单独添加路由

#print(conf.route)

def Firewalking(dstaddr, ttlno, lport, hport):
	result_raw = sr(IP(dst=dstaddr, ttl=ttlno)/TCP(dport=(lport,hport)), inter=1, timeout=5, verbose=False)
	#注意必须目的地址真实存在，流量确实被ACL放过，TTL抵达防火墙时为0，测试才能成功！！！
	result_list = result_raw[0].res

	for i in range(len(result_list)):
		icmp_fields = result_list[i][1]['ICMP'].fields
		ip_fields = result_list[i][1]['IP'].fields
		scan_fields = result_list[i][0]['TCP'].fields
		if icmp_fields['type'] == 11:
			print('Firewall is at ' + ip_fields['src'] + ' Port: ' + str(scan_fields['dport']) + ' is Open!!!')

if __name__ == '__main__':
	Firewalking('10.1.1.1', 0, 20, 40)
