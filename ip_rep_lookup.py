#!/usr/bin/python3

import splunk.Intersplunk as si
import requests

class IPLookup():

	def __init__(self, ip):
		self.ip = ip
		self.asn = ''
		self.country = ''
		self.city = ''
		self.passive_domains = []
		self.reputation = ''

		self.find_basic_geo()
		self.find_passive_domains()
		self.find_reputation()

	#Get basic geo info
	def find_basic_geo(self):
		r = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + self.ip + '/geo')
		r_dict = r.json()
		self.asn = r_dict['asn']
		self.country =  r_dict['country_name']
		self.city = r_dict['city']


	#Get passive domain from IP - Limited to one request every 10sec
	def find_passive_domains(self):
		r = requests.get('https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=' + self.ip)
		r_dict = r.json()
		passive_domains = []
		for domain in r_dict['resolutions']:
			passive_domains.append(domain['domain'])
		self.passive_domains = passive_domains


	#Get IP reputation - Under testing
	def find_reputation(self):
		r = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + self.ip + '/reputation')
		r_dict = r.json()
		self.reputation = r_dict['reputation']

results_out = []
results_in = si.readResults()
for result_in in results_in:
	ip = result_in['ip']
	ip_lookup = IPLookup(ip)
	result_in['asn'] = ip_lookup.asn
	result_in['country'] = ip_lookup.country
	result_in['city'] = ip_lookup.city
	result_in['passive_domains'] = ip_lookup.passive_domains
	result_in['reputation'] = ip_lookup.reputation

	results_out.append(result_in)

si.outputResults(results_out)
