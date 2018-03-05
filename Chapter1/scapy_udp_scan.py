#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy_ping_one_new import scapy_ping_one

def udp_scan_final(hostname,lport,hport):
	ping_result = scapy_ping_one(hostname)
	if ping_result[1] == 2:
		print('设备' + hostname + '不可达！！！')
	else:
		result_raw = sr(IP(dst=hostname)/
						UDP(dport=(int(lport),int(hport))),
						timeout = 1, 
						verbose = False)
		scan_port = []
		for x in range(int(lport),int(hport)):
			scan_port.append(x)
		port_not_open = []
		result_list = result_raw[0].res #类型为清单
		for i in range(len(result_list)):
			if result_list[i][1].haslayer(ICMP):
				port_not_open.append(result_list[i][1][3].fields['dport'])
				#提取UDP in IP中的原始数据包的目的端口信息

		return list(set(scan_port).difference(set(port_not_open)))#获得两个清单的差集

if __name__ == '__main__':
	host = input('请你输入扫描主机的IP地址: ')
	port_low = input('请你输入扫描端口的最低端口号: ')
	port_high = input('请你输入扫描端口的最高端口号: ')
	print('开放的UDP端口号如下:')
	for port in udp_scan_final(host,port_low,port_high):
		print(port)