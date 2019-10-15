import socket
import time
import datetime
import hashlib
import struct
import random
import logging
import pyshark
import multiprocessing as mp
import os
from pathlib import Path
import geoip2.database
import errno
from geoip2.errors import AddressNotFoundError

#logging configuration
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO, filename='peerlog.txt', datefmt='%Y-%m-%d %H:%M:%S')

#yo mathi ko chai protocol wala message 
def create_version_message(host):
	version = struct.pack("i",70015)
	services = struct.pack("Q",0)
	timestamp = struct.pack("q",int(time.time()))
	addr_recv_services = struct.pack("Q",0)
	addr_recv_ip = struct.pack(">16s",bytes(host, 'utf-8'))
	addr_recv_port = struct.pack(">H",8333)
	addr_trans_services = struct.pack("Q",0)
	addr_trans_ip = struct.pack(">16s",bytes("127.0.0.1",'utf-8'))
	addr_trans_port = struct.pack(">H",8333)
	nonce = struct.pack("Q", random.getrandbits(64))
	user_agent_byes = struct.pack("B",0)
	start_height = struct.pack("i",596306)
	relay = struct.pack("?",False)

	payload = version + services + timestamp + addr_recv_services + addr_recv_ip + addr_recv_port +\
	          addr_trans_services + addr_trans_ip + addr_trans_port + nonce + user_agent_byes + start_height + relay

	magic = bytes.fromhex("F9BEB4D9")
	command = b"version" + 5 * b"\00"
	length = struct.pack("I", len(payload))
	checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
	return magic + command + length + checksum + payload

def create_verack_message():
	magic = bytes.fromhex("F9BEB4D9")
	command = b"verack" + 6 * b"\00"
	payload = b""
	length = struct.pack("I", len(payload))
	checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
	return magic + command + length + checksum + payload

def create_getaddr_message():
	magic = bytes.fromhex("F9BEB4D9")
	command = b"getaddr" + 5 * b"\00"
	payload = b""
	length = struct.pack("I", len(payload))
	checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
	return magic + command + length + checksum + payload

# check if ipv4 or ip6 addresses. disallow ipv6 addresses
def check_host_family(host, port):
	global nodelist
	global nodelistread

	assert (port is not None), "Port value not set"
	if(':' in host):
		print("Given host is a IPv6 address, passing over")
		nodelistread.append(host)
		print("Nodes found: " + str(len(nodelist)))
		print("Nodes read: " + str(len(nodelistread)))
		pass
	else:
		sniff_addr_packets(host, port)


# create a capture pyshark object
def sniff_addr_packets(host, port):

	# early sleep before resuming connection
	print("Sleeping now for 5 seconds")
	time.sleep(5)

	pkt_cnt = 0;
	conn_established = False
	try:
		print("-------------------------------------------------------")
		print("Attempting connection to " + host + " at port " + str(port))
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((host,port))
		conn_established = True
		print("Socket Connection Established Successfully")
	except (socket.error, ConnectionResetError) as err:
		print("Caught exception: %s" % err)
	
	# refer to the global nodelist dictionary & global nodelistread list
	global nodelist
	global nodelistread
	global CURRENT_TIME

	# proceed only if socket connection was established
	if(conn_established):
		# send version message
		sock.send(create_version_message(host))
		print("Version Message Sent Successfully")

		try:
			sock.recv(1024)
		except socket.error as err:
			if (err.errno == errno.ECONNRESET) or (err.errno == errno.ECONNABORTED):
				print("Caught exception: %s" % err)
				print("Connection Reset")
				pass
			pass
		# send verack message to seed node
		sock.send(create_verack_message())
		print("Verack Message Sent Successfully")
		try:
			sock.recv(1024)
		except socket.error as err:
			if (err.errno == errno.ECONNRESET) or (err.errno == errno.ECONNABORTED):
				print("Caught exception: %s" % err)
				pass
			pass
		# this line invokes tshark to capture packets asynchronously
		capture = pyshark.LiveCapture(interface='\\Device\\NPF_{9342EE7E-9981-4554-87AE-06666A717864}',display_filter='bitcoin')

		sock.send(create_getaddr_message())
		print("GetAddr Message Sent Successfully")
		print("Waiting for packets!")
		capture.sniff(timeout=30)
		pkts = [pkt for pkt in capture._packets]
		print("No. of packets captured: " + str(len(pkts)))
		
		print("Closing Capture")
		capture.close()
		
		for pkt in pkts:
			if(pkt.bitcoin.command == 'addr'):
				#increment the packet_count
				pkt_cnt += int(pkt.bitcoin.addr_count)
				addresses = list(pkt.bitcoin.address_address.all_fields)
				ports = list(pkt.bitcoin.address_port.all_fields)
				services = list(pkt.bitcoin.address_services.all_fields)
				ts = list(pkt.bitcoin.addr_timestamp.all_fields)
				
				with open('dummy.txt', 'a') as f:
					for i,j,x,y in zip(addresses, ports, services, ts):
						unformattedIP = str(i)
						#remove unnecessary information provided by the 
						formattedIP = unformattedIP.strip('<').strip('>').split(' ')[-1]
						#if the IP address is IPv4 address strip the ipv6 padding at the front
						if(formattedIP.startswith('::ffff:')):
							formattedIP = formattedIP.strip('::ffff:')
						
						unformattedPort = str(j)
						formattedPort = unformattedPort.strip('<').strip('>').split(' ')[-1]
						
						#formatting the address timestamp of each peer
						unformattedTS = str(y)
						formattedTSString = unformattedTS.split('p:')[-1].split('.0')[0].strip(' ')
						
						#we define a variable age to look for only recent peers
						uts = time.mktime(datetime.datetime.strptime(formattedTSString, "%b %d, %Y %H:%M:%S").timetuple())
						age = int(CURRENT_TIME - uts)
						
						#add the IP address to the nodelist dictionary if it has not been added yet and if it's age in less than 24 hours
						if (formattedIP not in nodelist) and (age <= 86400):
							nodelist[formattedIP] = int(formattedPort)
							f.write(formattedIP + "\t" + formattedPort + "\n")
						print(f"IP: {formattedIP} \t\t Port: {formattedPort} \t\t Timestamp: {formattedTSString}\n")

		print("Either packet count has reached its limit or has reached timeout")
		print("End Time: " + str(time.time()))
	
		#close the socket connection
		sock.shutdown(socket.SHUT_RDWR)
		sock.close()
	else:
		print("Connection couldn't be established")
		time.sleep(5)

	nodelistread.append(host)
	print("Nodes found: " + str(len(nodelist)))
	print("Nodes read: " + str(len(nodelistread)))

#main boilerplate syntax
if __name__ == '__main__':
	#maintain a dictionary to store found IPs mapping to their port number
	global nodelist
	nodelist = {}

	#set seed.bitcoin.sipa.be as the seed node
	seed_nodelist = {'193.111.156.2':8333,'199.16.8.253':8333, '79.77.33.128':8333, '79.235.174.12':8333, '84.217.160.164':8333, '195.154.187.6':8333}

	global nodelistread
	nodelistread = []

	global CURRENT_TIME
	CURRENT_TIME = time.time()

	#check if there is already a file containing IP addresses
	file_path = Path('dummy.txt')
	if(not file_path.exists()):
		print("Node list doesn't exist. Creating one")
		with open('dummy.txt','w') as fp:
			for k,v in seed_nodelist.items():
				fp.write(k + "\t" + str(v) + "\n")
				nodelist[k] = v
				# nodelistread.append(k)
		fp.close()
	else:
		print("Output file exists already. Reading peer nodes list")
		with open('dummy.txt','r') as fp2:
			for line in fp2.readlines():
				ip = line.split('\t')[0] #strip the ip from each line
				port = int(line.split('\t')[-1]) #strip the port from each line
				nodelist[ip] = port
				# nodelistread.append(ip)
		fp2.close()

	while(True):
		for k,v in nodelist.copy().items():
			if k not in nodelistread:
				check_host_family(k,v)
			else:
				continue

		if(len(nodelist) == len(nodelistread)):
			break

		#explicitly break the loop when the list of nodes found active in the last 24 hours is greater than 9500
		if(len(nodelist) >= 9500):
			break