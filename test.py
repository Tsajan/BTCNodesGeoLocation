import geoip2.webservice
import urllib
import json
import requests

IPSTACK_API_KEY = '4afa84dfb47b7fbbce59b1fd3d2096a2'
GEOIP_USER_ID = 143765
GEOIP_API_KEY = 'ZjpLeZUFw5NKOoOM'

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
    geolocateip_using_ipstack('output.txt')

