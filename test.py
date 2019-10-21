import geoip2.webservice
import geoip2.database
import urllib
import json
import requests
from geoip2.errors import AddressNotFoundError
from decimal import Decimal
import time

IPSTACK_API_KEY = '4afa84dfb47b7fbbce59b1fd3d2096a2'
GEOIP_USER_ID = 143765
GEOIP_API_KEY = 'ZjpLeZUFw5NKOoOM'

GEOIP_COUNTRY = geoip2.database.Reader("GeoLite2-Country.mmdb")
GEOIP_CITY = geoip2.database.Reader("GeoLite2-City.mmdb")
GEOIP_ASN = geoip2.database.Reader("GeoLite2-ASN.mmdb")

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


def geolocateip_using_geoip2(file_path):
    iplist = []
    geomap = {}
    client = geoip2.webservice.Client(143765, 'ZjpLeZUFw5NKOoOM')
    with open(file_path,'r') as fp: 
        for line in fp.readlines():
            ip = line.split('\t')[0]
            iplist.append(ip)
    fp.close()

    for ip in iplist:
        response = client.insights(ip)
        country = response.country.name
        city = response.city.name
        state = response.subdivisions.most_specific.name
        latitude = response.location.latitude
        longitude = response.location.longitude
        geomap[ip] = (country, state, city, longitude, latitude)
        print(ip + "\t-->" + str(geomap[ip]))
    return geomap

# Limitations of 10,000 requests per month
def geolocateip_using_ipstack(file_path):
    iplist = ['2a02:120b:c3f3:f7e0:597:89c6:2fef:8c44','2a03:1b20:1:f410::a01e','2a02:560:42cc:a600:ade5:1fbe:9be6:41e','2001:4dd3:449c:0:b141:f0c:5e8f:86c2']
    with open(file_path,'r') as fp:
        for line in fp.readlines():
            ip = line.split('\t')[0]
            iplist.append(ip)
    fp.close()

    base_url = 'http://api.ipstack.com/'

    for i in range(10):
        ip = iplist[i]
        url = base_url + ip + '?access_key=' + IPSTACK_API_KEY
        resp = requests.get(url=url)
        data = resp.json()
        print("Printing IP details:")
        print(f"\n\tIP --> {data['ip']}  \n\t Country --> {data['country_name']} \n\t Region --> {data['region_name']} \n\t City --> {data['city']} \n\t Zip Code --> {data['zip']}")

if __name__ == '__main__':
    geomap = {}
    # geomap = geolocateip_using_geoip2('output.txt')
    # for k,v in geomap.item():
    #     print("IP: " + k + "\tGeoinformation: " + v)
    # geolocateip_using_ipstack('output.txt')
    geolocateip_db('archive.txt')

