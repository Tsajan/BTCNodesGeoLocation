import geoip2.webservice
import geoip2.database
import urllib
import json
import requests
from geoip2.errors import AddressNotFoundError
from decimal import Decimal
import time

def whatever():
	with open('initialdata.json','w') as fp2:
		json.dump(initial_json_array, fp2)

	while(len(initial_json_array) >= 1):
		item = initial_json_array.pop()
		print("------------------------------------")
		print("JSON array length: " + str(len(initial_json_array)))
		print("Popping new JSON element")
		print(item)
		time.sleep(1)
		#if final_json_array doesn't have any element yet, put the popped item into it
		if(len(final_json_array) == 0):
			new_item['id'] = item['iso']
			new_item['name'] = item['country']
			new_item['nodes'] = 1
			new_item['percent'] = float("{0:.2f}".format(new_item['nodes'] * 100 / len(addresses)))
			new_item['ips'] = list()
			new_item['ips'].append(item['ip'])
			print("Initially list is empty")
			print(new_item)
			time.sleep(5)
			final_json_array.append(new_item)
		else: #that is, if there are already elements in the final_json_array
			updated = False
			# loop through existing elements in the final_json_array
			print(final_json_array)
			for i in final_json_array:
				# if there exists values for the country iso code, update the counts
				if(bool(i.get('id') == item['iso'])):
					i['nodes'] = i['nodes'] + 1
					i['percent'] = float("{0:.2f}".format(i['nodes'] * 100 / len(addresses)))
					i['ips'].append(item['ip'])
					updated = True
					print("Country already exists")
					break
			if not updated:
				new_item['id'] = item['iso']
				new_item['name'] = item['country']
				new_item['nodes'] = 1
				new_item['percent'] = float("{0:.2f}".format(new_item['nodes'] * 100 / len(addresses)))
				new_item['ips'] = list()
				new_item['ips'].append(item['ip'])
				print(new_item)
				print("New country added")
				time.sleep(5)
				final_json_array.append(new_item)
		print("Final list:")
		print(final_json_array)
	print(len(final_json_array))

whatever()