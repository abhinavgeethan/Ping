import struct
import os
import socket
import time

self_id=os.getpid() & 0xFFFF
dest_ip="2a00:1450:4019:0802::200e"
seq_num=0
packet_size=32
timeout=1000*(10**-3)
duration=[]
packets_sent=0
packets_rcvd=0
isIPV6=False
def calc_checksum(data_string):
    limit=(int(len(data_string)/2)*2)
    sum=0
    ctr=0
    low=0
    high=0
    while ctr<limit:
        # Works only on Windows Machines
        low=chr(data_string[ctr])
        high=chr(data_string[ctr+1])
        sum+=(ord(high)*256+ord(low))
        ctr+=2
    if limit<len(data_string):
        low=data_string[len(data_string)-1]
        sum+=ord(low)
    sum&=0xffffffff
    sum= (sum>>16)+(sum&0xffff)
    sum+=sum>>16
    ret=~sum&0xffff
    ret=socket.htons(ret)
    return ret

def get_TTL(icmp_packet):
    icmp_header=struct.unpack("!BBHHH",icmp_packet[20:28])
    if icmp_header[3]==self_id:
        ip_header=struct.unpack("!BBHHHBBHII",icmp_packet[:20])
        return ip_header[5]

def make_packet():
    # Psuedo Header
    if isIPV6:
        header=struct.pack("!BBHHH",128,0,0,self_id,seq_num)
    else:
        header=struct.pack("!BBHHH",8,0,0,self_id,seq_num)
    
    # Data Gen
    padding=[]
    startVal=0x42
    for i in range(startVal,startVal+packet_size):
        padding+=[(i&0xff)]
    data=bytes(padding)
    
    # Calculating Checksum
    checksum=calc_checksum(header+data)
    # Actual Header with Checksum
    if isIPV6:
        header=struct.pack("!BBHHH",128,0,checksum,self_id,seq_num)
    else:
        header=struct.pack("!BBHHH",8,0,checksum,self_id,seq_num)
    packet=header+data
    return packet

def ping_once():
    global packets_sent
    global packets_rcvd
    if isIPV6:
        sock=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.getprotobyname("ipv6-icmp"))
    else:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
    packet=make_packet()
    startTime=time.time()
    try:
        if isIPV6:
            sock.sendto(packet,(dest_ip,58,0,0))
        else:
            sock.sendto(packet,(dest_ip,1))
        packets_sent+=1
    except socket.gaierror as err:
        print(f"Could not find host {dest_ip}.")
        print(err)
        return
    resp_packet=None
    endtime=None
    while (time.time()-startTime)<timeout and not resp_packet:
        resp_packet,addr=sock.recvfrom(2048)
        if not isIPV6:
            ttl=get_TTL(resp_packet)
    endtime=time.time()
    time_taken=int((endtime-startTime)*1000)
    duration.append(time_taken)
    packets_rcvd+=1
    if isIPV6:
        print(f"Reply from {addr[0]}: time={time_taken}ms")
    else:
        print(f"Reply from {addr[0]}: bytes={len(resp_packet)-28} time={time_taken}ms TTL={ttl}")
def print_stats():
    print(f"\nPing statistics for {dest_ip}:")
    print(f"\tPackets: Sent = {packets_sent}, Received = {packets_rcvd}, Lost = {packets_sent-packets_rcvd} ({int(((packets_sent-packets_rcvd)/packets_sent)*100)}% loss)")
    print(f"Approximate round trip times in milli-seconds:")
    print(f"\tMinimum = {min(duration)}ms, Maximum = {max(duration)}ms, Average = {int(sum(duration)/len(duration))}ms")
    return
if ':' in dest_ip:
    isIPV6=True
print(f"Pinging {dest_ip} with {packet_size} bytes of data:")
ping_once()
ping_once()
ping_once()
ping_once()
print_stats()