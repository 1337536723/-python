#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *

def scapy_arp_request(ip_address, queue = None, ifname = 'eno33554944'):
	result_raw = srp(Ether(dst='FF:FF:FF:FF:FF:FF')
					/ARP(op=1, hwdst='00:00:00:00:00:00', pdst=ip_address), 
					timeout = 1,
					iface = ifname,
					verbose = False)	
	try:
		result_list = result_raw[0].res#把响应的数据包对，产生为清单
		#[0]第一组响应数据包
		#[1]接受到的包，[0]为发送的数据包
		#[1]ARP头部字段中的['hwsrc']字段，作为返回值返回
		if queue == None:
			#return result_list[0][1][1].fields['hwsrc']
			return result_list[0][1].getlayer(ARP).fields['hwsrc']
		else:
			queue.put((ip_address, result_list[0][1].getlayer(ARP).fields['hwsrc']))
	except:
		return

if __name__ == "__main__":
	import sys
	print(scapy_arp_request(sys.argv[1]))

