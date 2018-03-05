#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from random import randint
def scapy_ping_one(host):
	id_ip = randint(1,65535)#随机产生IP ID位
	id_ping = randint(1,65535)#随机产生Ping ID位
	seq_ping = randint(1,65535)#随机产生Ping序列号位
	#构造Ping数据包
	packet = IP(dst=host, ttl=1, id=id_ip)/ICMP(id=id_ping,seq=seq_ping)/b'Welcome to qytang'
	ping = sr1(packet, timeout=2, verbose = False)#获取响应信息，超时为2秒，关闭详细信息
	if ping:#如果有响应信息
		os._exit(3)#退出码为3
if __name__ == '__main__':
	scapy_ping_one(sys.argv[1])
