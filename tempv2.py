import socket
import time
import hashlib
import struct
import random
import logging
import pyshark 

#create a streaming socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
HOST = "seed.bitnodes.io"
PORT = 8333

#define starting time and ending time
START_TIME = time.time()
END_TIME = time.time() + 100 # we wish to run the script for 100s

#constant that we want for addr response
ADDR_RESP_HEX = 'f9beb4d9616464720000000000000000' # hex code concatenated from magic code for mainnet + addr command + zero paddings

#logging configuration
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO, filename='peerlog.txt', datefmt='%Y-%m-%d %H:%M:%S')

#maintain an array to store found IPs
nodelist = []

def create_version_message():
	version = struct.pack("i",70015)
	services = struct.pack("Q",0)
	timestamp = struct.pack("q",int(time.time()))
	addr_recv_services = struct.pack("Q",0)
	addr_recv_ip = struct.pack(">16s",bytes(HOST, 'utf-8'))
	addr_recv_port = struct.pack(">H",8333)
	addr_trans_services = struct.pack("Q",0)
	addr_trans_ip = struct.pack(">16s",bytes("127.0.0.1",'utf-8'))
	addr_trans_port = struct.pack(">H",8333)
	nonce = struct.pack("Q", random.getrandbits(64))
	user_agent_byes = struct.pack("B",0)
	#user_agent = struct.pack("p",0)
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

sock.connect((HOST,PORT))

#create a capture pyshark object
capture = pyshark.LiveCapture(interface='\\Device\\NPF_{9342EE7E-9981-4554-87AE-06666A717864}',display_filter='bitcoin')

#send version message
sock.send(create_version_message())
print(sock.recv(1024))
time.sleep(2)

#send verack message to seed node
sock.send(create_verack_message())
print(sock.recv(1024))
time.sleep(2)

#send getaddr message
while(time.time() < END_TIME):
	sock.send(create_getaddr_message())
	capture.sniff(timeout=10)
	for pkt in capture:
		if(pkt.bitcoin.command == 'addr'):
			print(pkt.bitcoin.pretty_print())
			print("--------------------------------------------------")
			addrport = str(pkt.bitcoin.address_address) + '\t' + str(pkt.bitcoin.address_port)
			print(addrport)
			with open('output.txt', 'a') as f:
				f.write(addrport)

	time.sleep(10)
