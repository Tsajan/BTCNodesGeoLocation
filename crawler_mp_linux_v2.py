import socket
import time
import datetime
import hashlib
import struct
import random
import logging
import pyshark
import multiprocessing
from multiprocessing import Pool, Manager
import os
import errno
from pathlib import Path
import geoip2.database
from geoip2.errors import AddressNotFoundError
import json
from decimal import Decimal

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
def check_host_family(host, port, nodelist, nodelistread):
	# global nodelist
	# global nodelistread

	assert (port is not None), "Port value not set"
	if(':' in host):
		print("Given host is a IPv6 address, passing over")
		nodelistread.append(host)
		print("Nodes found: " + str(len(nodelist)))
		print("Nodes read: " + str(len(nodelistread)))
		pass
	else:
		sniff_addr_packets(host, port, nodelist, nodelistread)


# create a capture pyshark object
def sniff_addr_packets(host, port, nodelist, nodelistread):

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
	# global nodelist
	# global nodelistread
	# global CURRENT_TIME

	# proceed only if socket connection was established
	if(conn_established):
		# send version message
		try:
			sock.send(create_version_message(host))
			print("Version Message Sent Successfully")
		except socket.error as err:
			print("Caught exception: %s" % err)
			pass
		

		try:
			sock.recv(1024)
		except socket.error as err:
			if (err.errno == errno.ECONNRESET) or (err.errno == errno.ECONNABORTED):
				print("Caught exception: %s" % err)
				print("Connection Reset")
				pass
			pass
		# send verack message to seed node
		try:
			sock.send(create_verack_message())
			print("Verack Message Sent Successfully")
		except socket.error as err:
			print("Caught exception: %s" % err)
			pass
		
		try:
			sock.recv(1024)
		except socket.error as err:
			if (err.errno == errno.ECONNRESET) or (err.errno == errno.ECONNABORTED):
				print("Caught exception: %s" % err)
				pass
			pass
		# this line invokes tshark to capture packets asynchronously
		capture = pyshark.LiveCapture(interface='eno1',display_filter='bitcoin')

		try:
			sock.send(create_getaddr_message())
			print("GetAddr Message Sent Successfully")
		except socket.error as err:
			print("Caught exception: %s" % err)
			pass
		print("Waiting for packets!")
		capture.sniff(timeout=30)
		pkts = [pkt for pkt in capture._packets]
		# print("No. of packets captured: " + str(len(pkts)))
		
		print("Closing Capture")
		capture.close()
		
		for pkt in pkts:
			try:
				if(pkt.bitcoin.command == 'addr'):
					#increment the packet_count
					pkt_cnt += int(pkt.bitcoin.addr_count)
					addresses = list(pkt.bitcoin.address_address.all_fields)
					ports = list(pkt.bitcoin.address_port.all_fields)
					services = list(pkt.bitcoin.address_services.all_fields)
					ts = list(pkt.bitcoin.addr_timestamp.all_fields)
					
					
					for i,j,x,y in zip(addresses, ports, services, ts):
						unformattedIP = str(i)
						#remove unnecessary information provided by the 
						formattedIP = unformattedIP.strip('<').strip('>').split(' ')[-1]
						#if the IP address is IPv4 address strip the ipv6 padding at the front
						if(formattedIP.startswith('::ffff:')):
							formattedIP = formattedIP.strip('::ffff:')
						
						unformattedPort = str(j)
						formattedPort = unformattedPort.strip('<').strip('>').split(' ')[-1]

						#formatting the service field
						unformattedService = str(x)
						formattedService = unformattedService.strip('<').strip('>').split(' ')[-1]
						serv = formattedService.strip('0x')
						
						#formatting the address timestamp of each peer
						unformattedTS = str(y)
						formattedTSString = unformattedTS.split('p:')[-1].split('.0')[0].strip(' ')
						
						#we define a variable age to look for only recent peers
						uts = time.mktime(datetime.datetime.strptime(formattedTSString, "%b %d, %Y %H:%M:%S").timetuple())
						age = int(time.time() - uts)
						
						#add the IP address to the nodelist dictionary if it has not been added yet and if it's age in less than 8 hours
						if (formattedIP not in nodelist) and (age <= 28800) and (serv == '40d'):
							nodelist[formattedIP] = int(formattedPort)
							# f.write(formattedIP + "\t" + formattedPort + "\n")
						# print(f"IP: {formattedIP} \t\t Port: {formattedPort} \t\t Timestamp: {formattedTSString}\n")
			except AttributeError as err:
				print("Caught exception: %s" % err)
				continue

		print("Packet Count Limit or Timeout Reached")
	
		#close the socket connection
		# sock.shutdown(socket.SHUT_RDWR)
		sock.close()
	else:
		print("Connection couldn't be established")
		time.sleep(5)

	# nodelistread.append(host)
	print("Nodes found: " + str(len(nodelist)))
	print("Nodes read: " + str(len(nodelistread)))

def raw_geoip(address):
	"""Resolves GeoIP data for the specified address using MaxMind databases."""
	country = None
	iso_code = None
	city = None
	lat = 0.0
	lng = 0.0
	timezone = None
	asn = None
	org = None

	#refer to the global GEOIP variables
	global GEOIP_COUNTRY
	global GEOIP_CITY
	global GEOIP_ASN

	prec = Decimal('.000001')

	if not address.endswith(".onion"):
		try:
			gcountry = GEOIP_COUNTRY.country(address)
		except AddressNotFoundError:
			pass
		else:
			iso_code = str(gcountry.country.iso_code)
			country = str(gcountry.country.name)

		try:
			gcity = GEOIP_CITY.city(address)
		except AddressNotFoundError:
			pass
		else:
			city = str(gcity.city.name).encode('utf-8')
			if gcity.location.latitude is not None and gcity.location.longitude is not None:
				lat = float(Decimal(gcity.location.latitude).quantize(prec))
				lng = float(Decimal(gcity.location.longitude).quantize(prec))
			timezone = gcity.location.time_zone

	if address.endswith(".onion"):
		asn = "TOR"
		org = "Tor network"
	else:
		try:
			asn_record = GEOIP_ASN.asn(address)
		except AddressNotFoundError:
			pass
		else:
			asn = 'AS{}'.format(asn_record.autonomous_system_number)
			org = str(asn_record.autonomous_system_organization).encode('utf-8')
	
	return (iso_code, country, city, lat, lng, timezone, asn, org)

def geolocateip_db():
	addresses = []
	geomap = {}
	new_item = {}
	initial_json_array = []
	final_json_array = []
	global finalnodelist
	for i in finalnodelist.keys():
		addresses.append(i)
    
	print("Addresses found: "+ str(len(addresses)))

	for address in addresses:
		(iso_code, country, city, lat, lng, timezone, asn, org) = raw_geoip(address)
		geomap['ip'] = address
		geomap['iso'] = iso_code
		geomap['country'] = country
		geomap['lat'] = lat
		geomap['lng'] = lng
		s_json = json.dumps(geomap, indent=4, sort_keys=True)
		ds_json = json.loads(s_json)
		initial_json_array.append(ds_json)

	with open('initialdata.json','w') as fp2:
		json.dump(initial_json_array, fp2)
	fp2.close()

	while(len(initial_json_array) >= 1):
		item = initial_json_array.pop()
		#if final_json_array doesn't have any element yet, put the popped item into it
		if(len(final_json_array) == 0):
			new_item = {}
			new_item['id'] = item['iso']
			new_item['name'] = item['country']
			new_item['z'] = 1
			new_item['percent'] = float("{0:.2f}".format(new_item['z'] * 100 / len(addresses)))
			new_item['ips'] = list()
			new_item['ips'].append(item['ip'])
			final_json_array.append(new_item)

		else: #that is, if there are already elements in the final_json_array
			updated = False
			# loop through existing elements in the final_json_array
			for i in final_json_array:
				# if there exists values for the country iso code, update the counts
				if(bool(i.get('id') == item['iso'])):
					i['z'] = i['z'] + 1
					i['percent'] = float("{0:.2f}".format(i['z'] * 100 / len(addresses)))
					i['ips'].append(item['ip'])
					updated = True
					break
			if not updated:
				new_item = {}
				new_item['id'] = item['iso']
				new_item['name'] = item['country']
				new_item['z'] = 1
				new_item['percent'] = float("{0:.2f}".format(new_item['z'] * 100 / len(addresses)))
				new_item['ips'] = list()
				new_item['ips'].append(item['ip'])
				final_json_array.append(new_item)

	# remove null or None keys from the array of JSON
	final_json_array = [item for item in final_json_array if item['id'] != "None"]
	final_json_array = [item for item in final_json_array if item['id'] != "null"]
    
	print("Number of countries: " + str(len(final_json_array)))

	with open('data.json','w') as fp3:
		json.dump(final_json_array, fp3)
	fp3.close()

#main boilerplate syntax
if __name__ == '__main__':
	#maintain a dictionary to store found IPs mapping to their port number
	global finalnodelist

	global GEOIP_COUNTRY
	global GEOIP_CITY
	global GEOIP_ASN

	#offline geoip databases provided by MaxMind
	GEOIP_COUNTRY = geoip2.database.Reader("GeoLite2-Country.mmdb")
	GEOIP_CITY = geoip2.database.Reader("GeoLite2-City.mmdb")
	GEOIP_ASN = geoip2.database.Reader("GeoLite2-ASN.mmdb")


	# global nodelistread
	# nodelistread = []
	CURRENT_TIME = time.time()
	print("------------------------------------------------------------------------------")
	print("Starting phase one: IP Collection")

	#read data from seed node list
	# for k,v in seed_nodelist.items():
	# 	nodelist[k] = v

	threadList=[]
	pool = Pool(processes=multiprocessing.cpu_count())
	pool2 = Pool(processes=100)
	pool3 = Pool(processes=400)
	maxPool=10;
	maxPool2=100;
	maxPool3=400;
	manager =  Manager()
	nodelist = manager.dict()
	nodelistread = manager.list()

	#set seed.bitcoin.sipa.be as the seed node
	seed_nodelist = {'193.111.156.2':8333,'199.16.8.253':8333, '79.77.33.128':8333, '79.235.174.12':8333, '84.217.160.164':8333, '195.154.187.6':8333, '71.19.155.244':8333, '173.254.232.51':8333, '45.79.97.30':8333, '198.252.112.64':8333, '35.128.8.141':8333}

	for k,v in seed_nodelist.items():
		nodelist[k] = v

	while(True):
		for k,v in nodelist.copy().items():
			if k not in nodelistread:
				nodelistread.append(k)
				#the case when there are less than 100 node addresses in our list, we decide to do multiprocessing with only 4 processes
				if(len(nodelist) < 100):
					if len(threadList) >= maxPool:
						print("********************************************************")
						print("************THREAD LIST CLEARED*************************")
						print("*               "+str(len(threadList))+"               *")
						print("********************************************************")
						for x in threadList:
							x.get()
						threadList=[]
					else:
						threadList.append(pool.apply_async(check_host_family, (k, v, nodelist, nodelistread)))
				# else when there are more than 100 nodes addresses, we do multiprocessing with 100 processes
				elif((len(nodelist) - len(nodelistread)) >= 100 and (len(nodelist) - len(nodelistread)) <= 400):
					if len(threadList) >= maxPool2:
						print("********************************************************")
						print("************THREAD LIST CLEARED*************************")
						print("*               "+str(len(threadList))+"               *")
						print("********************************************************")
						for x in threadList:
							x.get()
						threadList=[]
					else:
						threadList.append(pool2.apply_async(check_host_family, (k, v, nodelist, nodelistread)))
				else:
					if len(threadList) >= maxPool3:
						print("********************************************************")
						print("************THREAD LIST CLEARED*************************")
						print("*               "+str(len(threadList))+"               *")
						print("********************************************************")
						for x in threadList:
							x.get()
						threadList=[]
					else:
						threadList.append(pool3.apply_async(check_host_family, (k, v, nodelist, nodelistread)))
			else:
				continue

			#explicitly break the loop when the list of nodes found active in the last 8 hours is greater than 9500
		# 	if(len(nodelist) >= MAX_NODELIST_LENGTH): #break the inner for loop once nodelist exceeds MAX_NODELIST_LENGTH i.e. 9600
		# 		break 
		
		# if(len(nodelist) >= MAX_NODELIST_LENGTH): #break the outer while loop once nodelist exceeds MAX_NODELIST_LENGTH i.e. 9600
		# 	break 

		if(len(nodelist) == len(nodelistread)):
			break

	finalnodelist = nodelist.copy()

	print("Collected sufficient nodes!!!")
	print("------------------------------------------------------------------------------")
	print("Starting phase two: GeoMapping")
	geolocateip_db()

	END_TIME = time.time()
	DIFF_TIME = END_TIME - CURRENT_TIME
	print("Time taken: " + str(float(DIFF_TIME/60)) + "mins.")

		
		