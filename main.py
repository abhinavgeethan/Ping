import struct
import os
import socket
import time
import re
import select
import argparse

self_id=os.getpid() & 0xFFFF
duration=[]
packets_sent=0
packets_rcvd=0
# seq_num=0
# packet_size=32
# dest_ip="google.ga"
# dest_name=None
# timeout=1000*(10**-3)
# isIPV6=False
# forceV6=False
# forceV4=True
# setTTL=None
# tries=None

def calc_checksum(data_string:bytes)->int:
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

def get_TTL(icmp_packet)->int:
    icmp_header=struct.unpack("!BBHHH",icmp_packet[20:28])
    if icmp_header[3]==self_id:
        ip_header=struct.unpack("!BBHHHBBHII",icmp_packet[:20])
        return ip_header[5]

def get_ID(icmp_packet)->int:
    icmp_header=struct.unpack("!BBHHH",icmp_packet[20:28])
    return icmp_header[3]

def make_packet(isIPV6:bool,packet_size:int=32)->bytes:
    seq_num=0
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

def ping_once(dest_ip:str,isIPV6:bool,*args,**kwargs):
    global packets_sent
    global packets_rcvd
    local_timeout=(kwargs.get('timeout') or 1)*1000*(10**-3)
    if isIPV6:
        sock=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.getprotobyname("ipv6-icmp"))
    else:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
    setTTL=kwargs.get('ttl') or None
    if setTTL!=None:
        print("Set TTL to: ",setTTL)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,setTTL)
    packet=make_packet(isIPV6)
    startTime=time.time()
    try:
        if isIPV6:
            sock.sendto(packet,(dest_ip,58,0,0))
        else:
            sock.sendto(packet,(dest_ip,1))
        packets_sent+=1
    except socket.gaierror:
        print(f"Could not find host {dest_ip}.[HOST_UNREACHABLE]")
        exit()
    # Receive Packet
    resp_packet=None
    endtime=None
    addr=None
    while True:
        select_start_time=time.time()
        selected=select.select([sock,],[],[],local_timeout)
        select_time=time.time()-select_start_time
        if selected[0]==[]:
            print("Request timed out.")
            return
        resp_packet,addr=sock.recvfrom(2048)
        if not isIPV6:
            ttl=get_TTL(resp_packet)
            break
        elif get_ID(resp_packet)==self_id:continue
        local_timeout=local_timeout-select_time
        if local_timeout<=0:break
    if not resp_packet and not addr:
        print("Request timed out.")
        return
    endtime=time.time()
    time_taken=int((endtime-startTime)*1000)
    duration.append(time_taken)
    packets_rcvd+=1
    if isIPV6:
        print(f"Reply from {addr[0]}: time={time_taken}ms")
    else:
        print(f"Reply from {addr[0]}: bytes={len(resp_packet)-28} time={time_taken}ms TTL={ttl}")

def print_stats(dest_ip:str)->None:
    print(f"\nPing statistics for {dest_ip}:")
    print(f"\tPackets: Sent = {packets_sent}, Received = {packets_rcvd}, Lost = {packets_sent-packets_rcvd} ({int(((packets_sent-packets_rcvd)/packets_sent)*100)}% loss)")
    if duration==[]:return
    print(f"Approximate round trip times in milli-seconds:")
    print(f"\tMinimum = {min(duration)}ms, Maximum = {max(duration)}ms, Average = {int(sum(duration)/len(duration))}ms")
    return

def ping(dest_ip:str,forceV4:bool=False,forceV6:bool=False,*args,**kwargs):
    isIPV6=True if ':' in dest_ip else False
    tries=kwargs.get('tries') or 4
    dest_name=None
    packet_size=kwargs.get("packet_size") or 32
    if forceV4 or forceV6:
        if forceV4 and forceV6:
            print("Cannot force IPv4 and IPv6 together.")
            exit()
        try:
            addr_info=socket.getaddrinfo(dest_ip,None)
        except socket.gaierror as err:
            print(f"Could not find host {dest_ip}.[ADDR_INFO ERROR]")
            exit()
        # print(addr_info)
        v4_IP=None
        v6_IP=None
        for options in addr_info:
            try:
                curr_IP=options[4][0]
            except:
                print("Address could not be resolved.")
                raise
                exit()
            if ':' in curr_IP:
                v6_IP=curr_IP
            else:
                v4_IP=curr_IP
        if v4_IP==None and v6_IP==None:
                print("Address could not be resolved.")
                exit()
        elif forceV6:
            if v6_IP==None:
                print("Host does not support IPv6.")
                exit()
            else:
                dest_name=dest_ip
                dest_ip=v6_IP
                isIPV6=True
        elif forceV4:
            if v4_IP==None:
                print("Address could not be resolved.")
                exit()
            else:
                dest_name=dest_ip
                dest_ip=v4_IP
                isIPV6=False
        # if len(addr_info)==1 and forceV6:
        #     print("Host does not support IPv6.")
        # elif len(addr_info)==1 and forceV4:
        #     try:
        #         v4_IP=addr_info[0][4][0]
        #     except:
        #         print("Address could not be resolved.")
        #         raise
        #         exit()
        #     dest_name=dest_ip
        #     dest_ip=v4_IP
        #     isIPV6=False
        # else:
        #     try:
        #         v4_IP=addr_info[1][4][0]
        #         v6_IP=addr_info[0][4][0]
        #     except:
        #         print("Address could not be resolved.")
        #         raise
        #         exit()
        #     if forceV4 and v4_IP:
        #         dest_name=dest_ip
        #         dest_ip=v4_IP
        #         isIPV6=False
        #     if forceV6 and v6_IP:
        #         dest_name=dest_ip
        #         dest_ip=v6_IP
        #         isIPV6=True
    has_letters=re.search("[a-z]",dest_ip)
    if has_letters and len(has_letters[0])>0 and not isIPV6:
        dest_name=dest_ip
        try:
            dest_ip=socket.gethostbyname(dest_name)
            print(f"Pinging {dest_name} [{dest_ip}] with {packet_size} bytes of data:")
        except socket.gaierror:
            print(f"Could not find host {dest_ip}. [NAME_RESOLUTION_ERROR]")
            exit()
    elif dest_name!=None and (forceV4 or forceV6):
        print(f"Pinging {dest_name} [{dest_ip}] with {packet_size} bytes of data:")
    else:
        print(f"Pinging {dest_ip} with {packet_size} bytes of data:")
    if tries!=None:
        for i in range(tries):
            time.sleep(1)
            ping_once(dest_ip=dest_ip,isIPV6=isIPV6,**kwargs)
    else: 
        while True:
            try:
                time.sleep(1)
                ping_once(dest_ip=dest_ip,isIPV6=isIPV6,**kwargs)
            except KeyboardInterrupt:
                break
    print_stats(dest_ip=dest_ip)
ping("google.ga")