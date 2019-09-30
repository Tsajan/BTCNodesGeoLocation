import socket
import time
import hashlib
import struct
import random
import logging
import pyshark

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
def sniff_addr_packets():
	capture = pyshark.LiveCapture(interface='\\Device\\NPF_{9342EE7E-9981-4554-87AE-06666A717864}',display_filter='bitcoin')
	capture.sniff(timeout=20)
	for pkt in capture:
		if(pkt.bitcoin.command == 'addr'):
			print(pkt.bitcoin.command)
			ip_addr = pkt.bitcoin.address_address
			port = pkt.bitcoin.address_port
			print("IP: {ip_addr} \t Port : {port}")
		else:
			continue
	capture.close()

#perform handshake between client and server
def perform_handshake(host, port):
	sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	sock.connect((host,port))
	print("Socket Connection Established Successfully")

	#send version message
	sock.send(create_version_message(host))
	time.sleep(2)
	print("Version Message Sent Successfully")

	#send verack message to seed node
	sock.send(create_verack_message())
	time.sleep(2)
	print("Verack Message Sent Successfully")

	#send getaddr message
	sock.send(create_getaddr_message())
	time.sleep(20)
	print("GetAddr Message Sent Successfully")

#logging configuration
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO, filename='peerlog.txt', datefmt='%Y-%m-%d %H:%M:%S')

#main boilerplate syntax
if __name__ == '__main__':
	
	#maintain an array to store found IPs
	nodelist = []

	#define starting time and ending time
	START_TIME = time.time()
	END_TIME = time.time() + 300 # we wish to run the script for 5 mins (300s)

	while(time.time() < END_TIME):
		perform_handshake("seed.bitnodes.io",8333)
		sniff_addr_packets()
		time.sleep(10)
