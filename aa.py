import socket
from struct import *



#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b



dev='en0'
cap = pcapy.open_live(dev , 65536 , 1 , 0)



while True:
	packet = s.recvform(66565)

	packet = packet[0]

	eth_length = 14

	eth_header = packet[:eth_length]
	# print eth_header

	#https://docs.python.org/2/library/struct.html
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])
	print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
