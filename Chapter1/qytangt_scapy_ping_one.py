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
	packet = IP(dst=host, ttl=64, id=id_ip)/ICMP(id=id_ping,seq=seq_ping)/b'Welcome to qytang'
	result = sr1(packet)

	result.show()

if __name__ == '__main__':
	scapy_ping_one('202.100.1.1')
