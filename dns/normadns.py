#
# Mariano `emdel` Graziano 
# pcap normalizer - summer 2011
#


import dpkt, socket, sys, os
from optparse import OptionParser


ddns = {}
NEW_FOLDER = "pcap_normalized_banload/"


def main():
	print "*** normalizer ***"
	
	parser = OptionParser()
	parser.add_option("-m", "--model", action="store", type="string", dest="model", help="Th pcap that will be used as model.");
	parser.add_option("-d", "--directory", action="store", type="string", dest="dir", help="The directory in which there are all the pcap files.");

	(options, args) = parser.parse_args()

	if options.model is None or options.dir is None:
		print "[-] Usage: %s --model <pcap> --directory <dir>" % sys.argv[0]
		sys.exit(-1)

	model = options.model
	folder = options.dir

	f = open(model)
	data = dpkt.pcap.Reader(f)

	print "\n[+] Building the dictionary for the model %s: " % model
	for ts, d in data:
		try: 
			eth = dpkt.ethernet.Ethernet(d)
		except: 
			continue
		try: 
			ip = eth.data
 		except: 
			continue

		if eth.type != 2048: 
			continue

 		if ip.p != 17: 
			continue

		try: 
			udp = ip.data
 		except: 
			continue

 		if udp.dport == 53: 
			dns = dpkt.dns.DNS(udp.data)
			if dns.qr == dpkt.dns.DNS_Q and dns.opcode == dpkt.dns.DNS_QUERY:
					qname = dns.qd[0].name
					if qname not in ddns:
						ddns[qname] = "foo"
						print "\t+ Found key: %s " % (qname) 		
		elif udp.sport == 53:
			dns = dpkt.dns.DNS(udp.data)
			if len(dns.an) < 1: 
				continue
				
			ip = []
			for answer in dns.an:
				if answer.type == 1:
					print "\t> Adding value %s" % (socket.inet_ntoa(answer.rdata))			
					ip.append(socket.inet_ntoa(answer.rdata))
					for k, v in ddns.items():
						if k == dns.qd[0].name:
							ddns[k] = ip

	pcaps = os.listdir(folder)
	good = []
	http_ret = dns_ret = False
	added = total = 0

	print "\n[+] Normalizing..."
	for pcap in pcaps:
		local = {}
		print "> pcap: %s" % pcap
		if folder+pcap == model:
			continue

		f = open(folder+pcap)
		data = dpkt.pcap.Reader(f)
		
		for ts, d in data:
			try: 
				eth = dpkt.ethernet.Ethernet(d)
			except: 
				continue
			try: 
				ip = eth.data
	 		except: 
				continue

			if eth.type != 2048: 
				continue

	 		if ip.p != 17: 
				continue

			try: 
				udp = ip.data
	 		except: 
				continue

	 		if udp.dport == 53: 
				dns = dpkt.dns.DNS(udp.data)
				if dns.qr == dpkt.dns.DNS_Q and dns.opcode == dpkt.dns.DNS_QUERY:
						qname = dns.qd[0].name
						if qname not in local:
							local[qname] = "foo"

			elif udp.sport == 53:
				dns = dpkt.dns.DNS(udp.data)
				if len(dns.an) < 1: 
					continue
				
				ip = []
				for answer in dns.an:
					if answer.type == 1:
						ip.append(socket.inet_ntoa(answer.rdata))
						for k, v in local.items():
							if k == dns.qd[0].name:
								local[k] = ip

		cnt = 0
		for mk, mv in ddns.items(): # The model
			for lk, lv in local.items(): # The other pcaps
				if mk == lk:
					cnt = 0
					for mip in mv:
						for lip in lv:
							if mip == lip:
								cnt += 1 
					if cnt != len(mv) and mv != 'foo':
						print "\t>> Fast Flux detected: There are %d IP but only %d counted (%s %s %s %s)" % (len(mv), cnt, mk, mv, lk, lv)
						print "\t>> Normalizing by using the IP: %s" % mv[0]
						fastfluxdomain = mk
						norm_ip = mv[0]
						old_ip = lv[0]
						f = open(folder+pcap)
						data = dpkt.pcap.Reader(f)
						num = 0
						data_w = dpkt.pcap.Writer(open(NEW_FOLDER+pcap,'wb'))
						for ts, d in data:
							num += 1
							try: 
								eth = dpkt.ethernet.Ethernet(d)
							except: 
								continue
							try: 
								ip = eth.data
					 		except: 
								continue

							if eth.type != 2048: 
								continue

							# TCP
							if ip.p is 0x06:
								tcp = ip.data
								if socket.inet_ntoa(ip.src) == old_ip:
									print "\t\t\t>> Changing the IP from %s to %s for the TCP pkt number %d" % (socket.inet_ntoa(ip.src), norm_ip, num)
									ip.src = socket.inet_aton(norm_ip)
									tcp.ulen = len(tcp)
									ip.len = len(ip)
									ip.sum = 0
									tcp.sum = 0
								elif socket.inet_ntoa(ip.dst) == old_ip:
									print "\t\t\t>> Changing the IP from %s to %s for the TCP pkt number %d" % (socket.inet_ntoa(ip.dst), norm_ip, num)
									ip.dst = socket.inet_aton(norm_ip)
									tcp.ulen = len(tcp)
									ip.len = len(ip)
									ip.sum = 0
									tcp.sum = 0
								data_w.writepkt(str(eth), ts)
					 		
							# UDP
							elif ip.p is 0x11: 
								udp = ip.data			
								if udp.sport == 53: # DNS reply 
									dns = dpkt.dns.DNS(udp.data)													
									if fastfluxdomain == dns.qd[0].name and len(dns.an) > 0:
										print "\t\t>> Changing the A type of DNS reply (%s) pkt number %d" % (fastfluxdomain, num)
										for ans in dns.an:
											if ans.type == 1:
												print "\t\t> Changing from %s to %s" % (socket.inet_ntoa(ans.rdata), norm_ip)
												ans.rdata = socket.inet_aton(norm_ip)	
												udp.data = dns
												udp.ulen = len(udp)
												ip.len = len(ip)
												ip.sum = 0
												udp.sum = 0
								data_w.writepkt(str(eth), ts)
							else:
								continue
						# write the pcap http://www.ainoniwa.net/doku/programming/python/dpkt/start
						data_w.close()



main()
