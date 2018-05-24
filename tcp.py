#_*_ coding utf-8
import socket
import time
import random
import sys
from  struct import *
def checksum(msg):
    s = 0

    for i in range(0,len(msg),2):
         w = (ord(msg[i]) << 8) + (ord(msg[i+1]))
         s = s+w
    s = (s>>16) + (s & 0xffff)
    s+=(s>>16)
    s = ~s & 0xffff
    return s
def CreateIPHeader(source_ip,dest_ip):
    version=4
    headerlen=5
    tos=0
    total_len=40
    id=random.randrange(18000,65535,1)
    flag=0
    ttl=255
    check=10
    protocol=socket.IPPROTO_TCP
    saddr=socket.inet_aton(source_ip)
    daddr=socket.inet_aton(dest_ip)
    hl_version=(version<<4)+headerlen
    ip_header=pack('!BBHHHBBH4s4s',hl_version,tos,total_len,id,flag,ttl,protocol,check,saddr,daddr)
    return ip_header
def create_tcp_syn_header(source_ip,dest_ip,dest_port):
    source=4444
    seq=0
    ack_seq=0
    syn=1
    fin=0
    ack=0
    doff=5
    rst=0
    psh=0
    urg=0
    window=socket.htons(8192)
    check=0
    urg_ptr=0
    offset_res=(doff<<4)+0
    tcp_flags=fin+(syn<<1)+(rst<<2)+(psh<<3)+(ack<<4)+(urg<<5)
    tcp_header=pack('!HHLLBBHHH',source,dest_port,seq,ack_seq,offset_res,tcp_flags,window,check,urg_ptr)
    source_address=socket.inet_aton(source_ip)
    dest_address=socket.inet_aton(dest_ip)
    placeholder=0
    protocol=socket.IPPROTO_TCP
    tcp_length=len(tcp_header)
    psh=pack('!4s4sBBH',source_address,dest_address,placeholder,protocol,tcp_length)
    psh=psh+tcp_header
    tcp_checksum=checksum(psh)
    tcp_header=pack('!HHLLBBHHH',source,dest_port,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_ptr)
    return tcp_header
def create_tcp_ack_header(source_ip,dest_ip,dest_port,seq,ack_seq):
    source=4444
    doff=5
    syn=0
    ack=1
    fin=0
    rst=0
    psh=0
    urg=0
    window=socket.htons(8192) 
    check=0 
    urg_ptr=0 
    offset_res=(doff<<4)+0 
    tcp_flags=fin+(syn<<1)+(rst<<2)+(psh<<3)+(ack<<4)+(urg<<5) 
    tcp_header=pack('!HHLLBBHHH',source,dest_port,seq,ack_seq,offset_res,tcp_flags,window,check,urg_ptr)
    source_address=socket.inet_aton(source_ip) 
    dest_address=socket.inet_aton(dest_ip) 
    placeholder=0 
    protocol=socket.IPPROTO_TCP
    tcp_length=len(tcp_header)                                              
    psh=pack('!4s4sBBH',source_address,dest_address,placeholder,protocol,tcp_length) 
    psh=psh+tcp_header 
    tcp_checksum=checksum(psh) 
    tcp_header=pack('!HHLLBBHHH',source,dest_port,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_ptr) 
    return tcp_header 
def CreateSocket():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
    except socket.error,msg:
        print 'Socket create error:'+str(msg[0])+'message:'+msg[1]
        sys.exit()
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    return s
source_ip='192.168.198.136'#你的源ip地址
dest_ip='192.168.0.19'#你的目的ip地址
port=80
s=CreateSocket()
ip_header=CreateIPHeader(source_ip,dest_ip)
tcp_header=create_tcp_syn_header(source_ip,dest_ip,port)
packet=ip_header+tcp_header
s.sendto(packet,(dest_ip,0))
data = s.recvfrom(1024) [0][0:]    
ip_header_len = (ord(data[0]) & 0x0f) * 4 
ip_header_ret = data[0: ip_header_len - 1]  
tcp_header_len = (ord(data[32]) & 0xf0)>>2 
tcp_header_ret = data[ip_header_len:ip_header_len+tcp_header_len - 1]  
ret=''
for t in range(0,len(tcp_header_ret)-1):
    ret=ret+hex(ord(tcp_header_ret[t]))+","
print ret
seq=tcp_header_ret[4:8]
ack_seq=tcp_header_ret[8:12]
seq=((ord(seq[0])<<24)&0xffffffff)+((ord(seq[1])<<16)&0xffffff)+((ord(seq[2])<<8)&0xffff)+(ord(seq[3])&0xff)
ack_seq=((ord(ack_seq[0])<<24)&0xffffffff)+((ord(ack_seq[1])<<16)&0xffffff)+((ord(ack_seq[2])<<8)&0xffff)+(ord(ack_seq[3])&0xff)
seq_ACK=ack_seq
ack_seq_ACK=seq+1
print "flags ->ack:"+hex(ord(tcp_header_ret[13]))
if ord(tcp_header_ret[13]) == 0x12: # SYN/ACK flags
    print "[+]send ACK"
    ack_header= create_tcp_ack_header(source_ip,dest_ip,port,seq_ACK,ack_seq_ACK)
    packet=ip_header+ack_header
    s.sendto(packet,(dest_ip,0))
