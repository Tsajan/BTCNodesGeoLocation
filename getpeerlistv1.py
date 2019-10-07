import socket
import time
import hashlib
import struct
import random
import logging
import pyshark
import multiprocessing as mp
import threading
import os

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

#create a capture pyshark object
def sniff_addr_packets(host, port):
	print("Attempting connection to " + host + " at port " + str(port))
	pkt_cnt = 0;
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host,port))
	print("Socket Connection Established Successfully")
	
	#send version message
	sock.send(create_version_message(host))
	time.sleep(4)
	print("Version Message Sent Successfully")
	sock.recv(1024)

	#send verack message to seed node
	sock.send(create_verack_message())
	time.sleep(4)
	print("Verack Message Sent Successfully")
	sock.recv(1024)

	#this line invokes tshark to capture packets asynchronously
	capture = pyshark.LiveCapture(interface='\\Device\\NPF_{9342EE7E-9981-4554-87AE-06666A717864}',display_filter='bitcoin')
	
	#send getaddr message
	sock.send(create_getaddr_message())
	print("GetAddr Message Sent Successfully")
	
	#refer to the global nodelist dictionary
	global nodelist
	start_time = time.time()
	print("Start Time: " + str(start_time))
	end_time = time.time() + 125 # we want to look up a node upto 125 seconds to see if it contains a list of nodes
	print("Capture will end prolly before: " + str(end_time))
	capture.sniff(timeout=20)
	for pkt in capture:
		if(pkt.bitcoin.command == 'addr'):
			#increment the packet_count
			pkt_cnt += int(pkt.bitcoin.addr_count)
			addresses = list(pkt.bitcoin.address_address.all_fields)
			ports = list(pkt.bitcoin.address_port.all_fields)
			print("-------------------------------------------------------")
			with open('output.txt', 'a') as f:
				for i,j in zip(addresses, ports):
					unformattedIP = str(i)
					
					#remove unnecessary information provided by the 
					formattedIP = unformattedIP.strip('<').strip('>').split(' ')[-1]
					#if the IP address is IPv4 address strip the ipv6 padding at the front
					if(formattedIP.startswith('::ffff:')):
						formattedIP = formattedIP.strip('::ffff:')
					unformattedPort = str(j)
					formattedPort = unformattedPort.strip('<').strip('>').split(' ')[-1]

					#add the IP address to the nodelist dictionary if it has not been added yet
					if formattedIP not in nodelist:
						nodelist[formattedIP] = int(formattedPort)
					print(f"IP: {formattedIP} \t\t Port: {formattedPort} \n")
					f.write(formattedIP + "\t" + formattedPort + "\n")

				#because the capture was proceeding async, and we want only 1000 IPs from a single node, so we explicitly stop when that condition meets
				if ((pkt_cnt >= 1000)):
					print("Closing Capture")
					capture.close()
					# break
				if time.time() > end_time:
					print("Closing Capture")
					capture.close()
		else:
			continue
	capture.close()
	print("No further address packets received in the time limit")
	print("End Time: " + str(time.time()))
	
	#close the socket connection
	sock.close()

	print("Sleeping now for 80 seconds")
	time.sleep(80)

#main boilerplate syntax
if __name__ == '__main__':
	#maintain a dictionary to store found IPs mapping to their port number
	global nodelist
	nodelist = {'seed.bitnodes.io':8333}
	nodelistread = []
	
	#define ending time
	PROG_END_TIME = time.time() + 600 # we wish to run the script for 10 mins (600s)

	print(nodelist)
	# while(time.time() < PROG_END_TIME):
	while(True):
		print("I am here!")
		time.sleep(2)
		for k,v in nodelist.copy().items():
			if k not in nodelistread:
				childThread = threading.Thread(target=sniff_addr_packets, args=(k,v,))
				childThread.daemon = True
				childThread.start()
				print("Active threads: " + str(threading.active_count()))
				childThread.join()
				nodelistread.append(k)
			else:
				continue

		if(len(nodelist) == len(nodelistread)):
			break
	print("Data collected over 10 mins successfully")
	print("Length of nodelist: " + str(len(nodelist)))