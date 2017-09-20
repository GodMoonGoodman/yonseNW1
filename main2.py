'''
Packet sniffer in python using the pcapy python library
 
Project website
http://oss.coresecurity.com/projects/pcapy.html
'''

#https://www.slideshare.net/vilss/sniff-presentation
 
import socket
from struct import *
import datetime
import pcapy
import sys
 
f = open('output','wb')
c = 0

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def main(argv):
    global c
    #list all devices
    devices = pcapy.findalldevs()
    # print devices
     
    # #ask user to enter device name to sniff
    # print "Available devices are :"
    # for d in devices :
    #     print d
     
    dev = 'en0'
     
    # print "Sniffing device " + dev
     
    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live(dev , 65536 , 1 , 0)
    count=0
    #start sniffing packets
    while(1) :
        (header, packet) = cap.next()

        #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        parse_packet(packet)
 
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
 
#function to parse a packet
def parse_packet(packet) :

    global c 
    #https://netmanias.com/ko/?m=view&id=blog&no=5372
    #parse ethernet header : DA_MAC 6B, SA_MAC 6B, ETpye 2B
    eth_length = 14
     
    eth_header = packet[:eth_length]
    # print eth_header


    #https://docs.python.org/2/library/struct.html
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        # print iph
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);


        #TCP protocol
        if protocol == 6 :
            # print 'Version : ' + str(version) + ' \nIP Header Length : ' + str(ihl) + ' \nTTL : ' + str(ttl) + ' \nProtocol : ' + str(protocol) + ' \nSource Address : ' + str(s_addr) + ' \nDestination Address : ' + str(d_addr)

            # print 'TCP protocol'
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
 
            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)
            # print tcph
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
             
            # print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
            # return
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            # print(count)
            if data[0:3] == b'GET' or data[0:4] == b'HTTP' or data[0:4] == b'POST':

                if(b'\r\n\r\n' in data):
                    end = data.find(b'\r\n\r\n')
                    data = data[0:end]+b'\r\n\r\n'
                else:
                    data = data+b'\r\n'
            # print 'Data : ' + data
            # print len(data)
                no = str(c)+' '

                # f.write(no.encode())
                print(no+'',end='')
                if str(d_addr) == get_ip_address():
                    RRTpye = "Response"
                else:
                    RRTpye = "Request"
                print ('%s:%s %s:%s HTTP %s\r\n'%(str(s_addr),str(source_port),str(d_addr),str(dest_port),str(RRTpye)), end='')

                # f.write(data)
                print(data.decode('utf-8'),end='')
                # print(len(data))
                c=c+1
                print()
        else:
            print("not TCP")

if __name__ == "__main__":
  main(sys.argv)
  f.close()
