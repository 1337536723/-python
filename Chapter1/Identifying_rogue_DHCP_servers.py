#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

conf.checkIPaddr = False

hw = get_if_raw_hwaddr('eno33554944')

dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])

result_raw = srp(dhcp_discover, multi=True, timeout=5, verbose=False, iface='eno33554944')
result_list = result_raw[0].res

for i in range(len(result_list)):
		ether_fields = result_list[i][1][0].fields
		ip_fields = result_list[i][1][1].fields
		dhcp_fields = result_list[i][1][3].fields
		serverno = str(i + 1)
		print('='*20 + 'Server' + serverno + '='*20)
		print('Server' + serverno + '  MAC地址为:  ' + ether_fields['src'])
		print('Server' + serverno + '  IP地址为:   ' + ip_fields['src'])
		print('Server' + serverno + '  操作码为:       ' + str(dhcp_fields['op']))
		print('Server' + serverno + '  ciaddr为:   ' + dhcp_fields['ciaddr'])
		print('Server' + serverno + '  giaddr为:   ' + dhcp_fields['giaddr'])
		print('Server' + serverno + '  yiaddr为:   ' + dhcp_fields['yiaddr'])
		print('Server' + serverno + '  siaddr为:   ' + dhcp_fields['siaddr'])