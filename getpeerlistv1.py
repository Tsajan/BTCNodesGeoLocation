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
##upto here

#create a capture pyshark object
#yo chai host sanga ko connection
def sniff_addr_packets(host, port):
	childThreadID = os.getpid()
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host,port))
	print("Socket Connection Established Successfully")
	
	#send version message
	sock.send(create_version_message(host))
	time.sleep(2)
	print("Version Message Sent Successfully")
	sock.recv(1024)

	#send verack message to seed node
	sock.send(create_verack_message())
	time.sleep(2)
	print("Verack Message Sent Successfully")
	sock.recv(1024)

	#yo line le chai indirectly tshark invoke garchha
	capture = pyshark.LiveCapture(interface='\\Device\\NPF_{9342EE7E-9981-4554-87AE-06666A717864}',display_filter='bitcoin')
	
	#send getaddr message
	sock.send(create_getaddr_message())
	print("GetAddr Message Sent Successfully")

	
	capture.sniff(timeout=20)
	#start_time = time.time()
	for pkt in capture:
		print("Capturing Pakets!")
		# if(time.time() > start_time + 4):
		# 	break;
		if(pkt.bitcoin.command == 'addr'):

			addresses = list(pkt.bitcoin.address_address.all_fields)
			ports = list(pkt.bitcoin.address_port.all_fields)
			print("-------------------------------------------------------")
			with open('output.txt', 'a') as f:
				for i,j in zip(addresses, ports):
					print("IP: " + str(i) + "\t\t" + "Port: " + str(j) + "\n")
					f.write(str(i) + "\t" + str(j) + "\n")
				capture.close()
		else:
			continue
	capture.close()


def set_timer():
	#define starting time and ending time
	START_TIME = time.time()
	END_TIME = time.time() + 300 # we wish to run the script for 5 mins (300s)


#main boilerplate syntax
if __name__ == '__main__':
	#maintain an array to store found IPs
	nodelist = []
	global childThreadID
	childThreadID = 0 #assign it as zero initially
	#define starting time and ending time
	START_TIME = time.time()
	END_TIME = time.time() + 100 # we wish to run the script for 5 mins (300s)

	
	childThread = threading.Thread(target=sniff_addr_packets,args=("seed.bitnodes.io",8333,))
	childThread.daemon = True
	childThread.start()
	#sniff_addr_packets("seed.bitnodes.io",8333)
	print(threading.active_count())
	print(threading.enumerate())
	while(time.time() < END_TIME):
		pass
	
	childThread.join()
	# os.kill(childThreadID, signal.SIGTERM)
	print("Exited the loop!")