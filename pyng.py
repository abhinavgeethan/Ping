# Importing required libraries
import struct   # For parsing and constructing bytearrays
import os       # For getting ProcessID to use as unique ID while sending packets.
import socket   # For socket communication
import time     # For measuring timeouts and delay
import re       # For triggering DNS lookup of hostnames
import select   # For awaiting socket
import argparse # For parsing input arguments
import sys      # For showing Usage by default

SELF_ID=os.getpid() & 0xFFFF
duration=[]    # Time taken by each packet
packets_sent=0 # Total packets sent
packets_rcvd=0 # Total packets received

# Helper Type function for numeric input argument parsing
def int_range(minval:int,maxval:int):
    """
    Returns function to be used as type in argparser.
    Checks if the given argument is an integer and if it is in the
    range specified by the minval and maxval.
    """
    def checker(arg):
        try:
            i=int(arg)
        except ValueError:
            raise argparse.ArgumentTypeError("must be an integer.")
        if i<minval or i>maxval:
            raise argparse.ArgumentTypeError(f"must be in range [{minval}-{maxval}].")
        return i
    return checker

# Generates ArgumentParser for input parsing
def make_arg_parser()->argparse.ArgumentParser:
    parser=argparse.ArgumentParser(prog="pyng",description="Ping command implemented in Python for CN Assignment. - Abhinav Geethan",epilog="Only works on Windows machines.\nRun as administrator if permission errors are encountered.")
    parser.add_argument(dest="dest_ip",type=str,metavar="Destination_Host",help="IP or name address of host to be pinged.")
    count_group=parser.add_mutually_exclusive_group()
    count_group.add_argument("-t",dest="tries",action="store_const",const=-1,help="Ping host until stopped.\nTo stop enter: CTRL+C")
    count_group.add_argument("-n",dest="tries",metavar="count",default=4,type=int_range(1,1000),help="Number of echo requests to send. Default is 4.")
    parser.add_argument("-i","--ttl",dest="ttl",metavar="TTL",default=None,type=int_range(1,255),help="Specify (TTL) Time To Live of packets sent. IPv4 only.")
    parser.add_argument("-w",dest="timeout",metavar="timeout",default=2000,type=int_range(1,60000),help="Timeout in milliseconds to wait for each reply. Default is 1000.")
    parser.add_argument("-l",dest="packet_size",metavar="size",default=32,type=int_range(1,255),help="Send buffer size. Default is 32.")
    force_proto_group=parser.add_mutually_exclusive_group()
    force_proto_group.add_argument("-4",dest="forceV4",action="store_true",help="Force ping to use IPv4 protocol. [Default]")
    force_proto_group.add_argument("-6",dest="forceV6",action="store_true",help="Force ping to use IPv6 protocol.")
    return parser

# Helper function for calculating checksum of packet
def calc_checksum(data_string:bytes)->int:
    # Uses Deferred Carries Method
    """
    As per RFC1071 [Section 2: (1)]:
        "Deferred Carries:
            ...
            One approach is to sum 16-bit words in a 32-bit accumulator, so
            the overflows build up in the high-order 16 bits.
            ..."

    """
    sum=0 # Used as 32-bit Accumulator
    low=0
    high=0
    ctr=0
    limit=(int(len(data_string)/2)*2)
    # Adding 16bits at a time
    while ctr<limit:
        """
        Suitable for little-endian machines but as per RFC1071 [Section 2: (A)],
        checksum calculation should be byte-order independent.
        """
        low=chr(data_string[ctr])
        high=chr(data_string[ctr+1])
        sum+=(ord(high)*256+ord(low))
        ctr+=2
    # Adding last byte if odd length
    if limit<len(data_string):
        low=data_string[len(data_string)-1]
        sum+=ord(low)
    sum&=0xffffffff # To avoid overflow (rare)
    # Folding 32-bit to 16-bits
    sum= (sum>>16)+(sum&0xffff)
    sum+=sum>>16
    # One's complement
    ret=~sum&0xffff # Inverting and truncating to 16bits
    # Retuen as bytes
    ret=socket.htons(ret)
    return ret

# Parses response IP header to get TTL of reply 
def get_TTL(icmp_packet:bytes)->int:
    # Unpacking response header
    icmp_header=struct.unpack("!BBHHH",icmp_packet[20:28])
    # Checking if packet is in response to our ICMP Echo Request
    if icmp_header[3]==SELF_ID:
        # Unpacking IP header from packet
        ip_header=struct.unpack("!BBHHHBBHII",icmp_packet[:20])
        # Returning TTL value of packet
        return ip_header[5]

# Parses response header to get ID. Only used for IPv6 since header is checked in get_TTL for IPv4.
def get_ID(icmp_packet:bytes)->int:
    # Unpacking response header
    icmp_header=struct.unpack("!BBHHH",icmp_packet[20:28])
    # Returning ID of packet 
    return icmp_header[3]

# Constructs packet with dummy payload
def make_packet(isIPV6:bool,packet_size:int=32)->bytes:
    """
    Leaving sequence number as 0 for each packet since
    they are being sent in 1 second intervals.
    """
    seq_num=0

    # Psuedo Header
    """
    Checksum needs to be a part of the header eventually,
    so a psuedo header with checksum=0 but accurate values
    for other fields is used to calculate it.
    """
    if isIPV6:
        header=struct.pack("!BBHHH",128,0,0,SELF_ID,seq_num)
    else:
        header=struct.pack("!BBHHH",8,0,0,SELF_ID,seq_num)
    
    # Generating dummy data of specified packet size to be sent
    dummy=[]
    startVal=0x42
    for i in range(startVal,startVal+packet_size):
        dummy+=[(i&0xff)]
    data=bytes(dummy)
    
    # Calculating Checksum
    checksum=calc_checksum(header+data)
    
    # Actual Header with Checksum
    if isIPV6:
        header=struct.pack("!BBHHH",128,0,checksum,SELF_ID,seq_num)
    else:
        header=struct.pack("!BBHHH",8,0,checksum,SELF_ID,seq_num)
    
    # Returning packet
    packet=header+data
    return packet

# Sends and receives one ICMP packet
def ping_once(dest_ip:str,isIPV6:bool,*args,**kwargs)->None:
    global packets_sent
    global packets_rcvd
    local_timeout=(kwargs.get('timeout') or 1000)*(10**-3)
    packet_size=kwargs.get('packet_size') or 32
    
    # Creating ICMP socket
    if isIPV6:
        sock=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.getprotobyname("ipv6-icmp"))
    else:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
    
    # Setting TTL to specified amount or defaults to OS default
    setTTL=kwargs.get('ttl') or None
    if setTTL!=None:
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,setTTL)
    
    # Construct echo request packet with dummy data of specified size
    packet=make_packet(isIPV6,packet_size)
    
    # Sending request
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
    """
    Loop times out according to specified timeout amount or
    defaults to 1 second.
    """
    while not resp_packet:
        select_start_time=time.time()
        selected=select.select([sock,],[],[],local_timeout)
        select_time=(time.time()-select_start_time)
        local_timeout-=select_time
        
        if not selected[0]:
            print("Request timed out. [select]")
            print(selected)
            return
        
        # Reading received response
        resp_packet,addr=sock.recvfrom(2048)
        
        # Reading TTL from IP for IPv4 response
        if resp_packet:
            if not isIPV6:
                ttl=get_TTL(resp_packet)
                break
            elif not get_ID(resp_packet)==SELF_ID:continue
        if local_timeout<=0:break
    
    if not resp_packet and not addr:
        print("Request timed out.")
        return
    
    # Measuring time taken (RTT)
    endtime=time.time()
    time_taken=int((endtime-startTime)*1000)
    duration.append(time_taken)
    packets_rcvd+=1
    
    if isIPV6:
        print(f"Reply from {addr[0]}: time={time_taken}ms")
    else:
        print(f"Reply from {addr[0]}: bytes={len(resp_packet)-28} time={time_taken}ms TTL={ttl}")

# Prints overall statistics
def print_stats(dest_ip:str)->None:
    print(f"\nPing statistics for {dest_ip}:")
    print(f"\tPackets: Sent = {packets_sent}, Received = {packets_rcvd}, Lost = {packets_sent-packets_rcvd} ({int(((packets_sent-packets_rcvd)/packets_sent)*100)}% loss)")
    if duration==[]:return
    print(f"Approximate round trip times in milli-seconds:")
    print(f"\tMinimum = {min(duration)}ms, Maximum = {max(duration)}ms, Average = {int(sum(duration)/len(duration))}ms")
    return

# Handles input options and triggers ping_once
def ping(dest_ip:str,forceV4:bool=False,forceV6:bool=False,*args,**kwargs)->None:
    isIPV6=True if ':' in dest_ip else False
    tries=kwargs.get('tries') or 4
    dest_name=None
    packet_size=kwargs.get("packet_size") or 32
    
    # Force IPv4 or IPv6 - if specified
    # Defaults to IPv4
    if forceV4 or forceV6:
        if forceV4 and forceV6:
            print("Cannot force IPv4 and IPv6 together.")
            exit()
        
        # DNS lookup to find available IPs
        try:
            addr_info=socket.getaddrinfo(dest_ip,None)
        except socket.gaierror as err:
            print(f"Could not find host {dest_ip}.[ADDR_INFO ERROR]")
            exit()
        
        # Reading IPv4 and IPv6 (if any) addresses from lookup
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
    
    # DNS Lookup for hostnames [purely cosmetic]
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
    
    # Attempt ping
    """
    No. of attempts specified by input, defaults to 4.
    -1 for continous ping until interrupted.
    """
    if tries!=-1:
        for i in range(tries):
            time.sleep(1)
            ping_once(dest_ip=dest_ip,isIPV6=isIPV6,**kwargs)
    else: 
        # Ping until interrupted
        while True:
            try:
                time.sleep(1)
                ping_once(dest_ip=dest_ip,isIPV6=isIPV6,**kwargs)
            except KeyboardInterrupt:
                break
    
    # Printing statistics report
    print_stats(dest_ip=dest_ip)

if __name__=="__main__":
    parser=make_arg_parser()
    if len(sys.argv)==1:
        parser.print_help()
        exit()
    args=parser.parse_args()
    ping(args.dest_ip,forceV4=args.forceV4,forceV6=args.forceV6,ttl=args.ttl,tries=args.tries,timeout=args.timeout,packet_size=args.packet_size)