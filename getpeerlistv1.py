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
from pathlib import Path
import geoip2.database
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
	except socket.error as err:
		print("Caught exception socket.error: %s" % err)
	
	# refer to the global nodelist dictionary & global nodelistread list
	global nodelist
	global nodelistread

	# proceed only if socket connection was established
	if(conn_established):
		# send version message
		sock.send(create_version_message(host))
		print("Version Message Sent Successfully")
		sock.recv(1024)

		# send verack message to seed node
		sock.send(create_verack_message())
		print("Verack Message Sent Successfully")
		sock.recv(1024)

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
				
				with open('output.txt', 'a') as f:
					for i,j,x,y in zip(addresses, ports, services, ts):
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
							f.write(formattedIP + "\t" + formattedPort + "\n")
						print(f"IP: {formattedIP} \t\t Port: {formattedPort} \n")

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

def raw_geoip(address):
    """
    Resolves GeoIP data for the specified address using MaxMind databases.
    """
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
            if gcity.location.latitude is not None and \
                    gcity.location.longitude is not None:
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


def geolocateip_db(file_path):
    addresses = []
    geomap = {}
    new_item = {}
    initial_json_array = []
    final_json_array = []
    with open(file_path, 'r') as fp:
        for line in fp.readlines():
            address = line.split('\t')[0]
            addresses.append(address)
    fp.close()
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

    while(len(initial_json_array) >= 1):
        item = initial_json_array.pop()
        #if final_json_array doesn't have any element yet, put the popped item into it
        if(len(final_json_array) == 0):
            new_item = {}
            new_item['id'] = item['iso']
            new_item['name'] = item['country']
            new_item['nodes'] = 1
            new_item['percent'] = float("{0:.2f}".format(new_item['nodes'] * 100 / len(addresses)))
            new_item['ips'] = list()
            new_item['ips'].append(item['ip'])
            final_json_array.append(new_item)
        else: #that is, if there are already elements in the final_json_array
            updated = False
            # loop through existing elements in the final_json_array
            for i in final_json_array:
                # if there exists values for the country iso code, update the counts
                if(bool(i.get('id') == item['iso'])):
                    i['nodes'] = i['nodes'] + 1
                    i['percent'] = float("{0:.2f}".format(i['nodes'] * 100 / len(addresses)))
                    i['ips'].append(item['ip'])
                    updated = True
                    break
            if not updated:
                new_item = {}
                new_item['id'] = item['iso']
                new_item['name'] = item['country']
                new_item['nodes'] = 1
                new_item['percent'] = float("{0:.2f}".format(new_item['nodes'] * 100 / len(addresses)))
                new_item['ips'] = list()
                new_item['ips'].append(item['ip'])
                final_json_array.append(new_item)
    
    print("Number of countries: " + str(len(final_json_array)))

    with open('data.json','w') as fp3:
        json.dump(final_json_array, fp3)


#main boilerplate syntax
if __name__ == '__main__':
	#maintain a dictionary to store found IPs mapping to their port number
	global nodelist
	nodelist = {}

	global GEOIP_COUNTRY
	global GEOIP_CITY
	global GEOIP_ASN

	GEOIP_COUNTRY = geoip2.database.Reader("GeoLite2-Country.mmdb")
	GEOIP_CITY = geoip2.database.Reader("GeoLite2-City.mmdb")
	GEOIP_ASN = geoip2.database.Reader("GeoLite2-ASN.mmdb")

	#set seed.bitcoin.sipa.be as the seed node
	seed_nodelist = {'193.111.156.2':8333,'199.16.8.253':8333, '79.77.33.128':8333, '79.235.174.12':8333, '84.217.160.164':8333, '195.154.187.6':8333}

	global nodelistread
	nodelistread = []

	#check if there is already a file containing IP addresses
	file_path = Path('output.txt')
	if(not file_path.exists()):
		print("Node list doesn't exist. Creating one")
		with open('output.txt','w') as fp:
			for k,v in seed_nodelist.items():
				fp.write(k + "\t" + str(v) + "\n")
				nodelist[k] = v
				# nodelistread.append(k)
		fp.close()
	else:
		print("Output file exists already. Reading peer nodes list")
		with open('output.txt','r') as fp2:
			for line in fp2.readlines():
				ip = line.split('\t')[0] #strip the ip from each line
				port = int(line.split('\t')[-1]) #strip the port from each line
				nodelist[ip] = port
				# nodelistread.append(ip)
		fp2.close()

	while(True):
		for k,v in nodelist.copy().items():
			if k not in nodelistread:
				childThread = threading.Thread(target=check_host_family, args=(k,v,))
				childThread.daemon = True
				childThread.start()
				childThread.join()
			else:
				continue

		if(len(nodelist) == len(nodelistread)):
			break