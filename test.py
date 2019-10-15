import geoip2.webservice
import geoip2.database
import urllib
import json
import requests
from geoip2.errors import AddressNotFoundError
from decimal import Decimal

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
            iso_code = str(gcountry.country.iso_code).encode('utf-8')
            country = str(gcountry.country.name).encode('utf-8')

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
            asn = 'AS{}'.format(asn_record.autonomous_system_number).encode('utf-8')
            org = str(asn_record.autonomous_system_organization).encode('utf-8')

    return (city, country, lat, lng, timezone, asn, org)

def geolocateip_db(file_path):
    addresses = []
    geomap = {}
    with open(file_path, 'r') as fp:
        for line in fp.readlines():
            address = line.split('\t')[0]
            addresses.append(address)
    fp.close()
    print("Addresses found: "+ str(len(addresses)))
    with open('details.txt','w') as fp:
        for address in addresses:
            # try:
            #     gcountry = GEOIP_COUNTRY.country(address)
            # except AddressNotFoundError:
            #     pass
            # else:
            #     country = gcountry.country.name

            # try:
            #     gcity = GEOIP_CITY.city(address)
            # except AddressNotFoundError:
            #     pass
            # else:
            #     city = gcity.city.name
            #     latitude = gcity.location.latitude
            #     longitude = gcity.location.longitude
            #     zip_code = gcity.location.postal_code

            # try:
            #     asn_record = ASN.

            geomap[address] = raw_geoip(address)
            print(address + "\t" + str(geomap[address]) + "\n")
            fp.write(address + "\t" + str(geomap[address]) + "\n")

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
    geolocateip_db('output.txt')

