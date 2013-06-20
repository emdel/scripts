#
# Mariano `emdel` Graziano
# DNS ID Randomizer.
# Summer 2011
#


import dpkt, os, sys
from random import randrange

def main():
	print "*** dnsidrandomizer ***"

	if len(sys.argv) != 3:
		print "Usage %s: <pcap dir> <output dir>" % sys.argv[0]
		sys.exit(-1)


	pcaps = os.listdir(sys.argv[1])
	
	num = 0 # counter for the total packets
	for pcap in pcaps:
		print "\n[+] Opening %s" % pcap
		f = open(sys.argv[1]+pcap)
		data = dpkt.pcap.Reader(f)
		# you have to create the folder given as parameter sys.argv[2]
		data_w = dpkt.pcap.Writer(open(sys.argv[2]+pcap,'wb'))
		n = 0 # for the single pcap
		for ts, d in data:
			n += 1
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
		
			if ip.p is 0x11: 
				udp = ip.data			
				if udp.dport == 53: # DNS request 
					rnd = randrange(0,30000)
					dns = dpkt.dns.DNS(udp.data)							
					print "> DNS request for %s: Changing id from %d to %d (# %d)" % (dns.qd[0].name, dns.id, rnd, n)
					req = dns.qd[0].name
					code = dns.id		
					dns.id = rnd				
					udp.data = dns
					udp.ulen = len(udp)
					ip.len = len(ip)
					ip.sum = 0
					udp.sum = 0
					#print "> Dumping the request"
					#print repr(eth)
					data_w.writepkt(str(eth), ts)
					print "> Searching for the reply..."
					found = False
					h = open(sys.argv[1]+pcap)
					buff = dpkt.pcap.Reader(h)
					counter = 0
					for a, b in buff:
						counter += 1
						try: 
							e = dpkt.ethernet.Ethernet(b)
						except: 
							continue
						try: 
							i = e.data
						except: 
							continue

						if e.type != 2048: 
							continue
		
						if i.p is 0x11: 	
							u = i.data			
							if u.sport == 53: # DNS reply
								d = dpkt.dns.DNS(u.data)
								if d.qd[0].name == req and counter > n and code == d.id:
									found = True
									print "> DNS reply found (# %d)" % counter
									print "> Putting the same DNS ID %d (from %d to %d)" % (rnd, d.id, rnd)
									d.id = rnd					
									u.data = d
									u.ulen = len(u)
									i.len = len(i)
									i.sum = 0
									u.sum = 0
									#print "> Dumping the reply"
									#print repr(e)
									data_w.writepkt(str(e), ts)
									break
							else:
								continue
					if found == False: print "> Reply not found"
			# dump tcp
			else:
				data_w.writepkt(str(eth), ts)
									

	#			else:
	#				continue
		# write the pcap http://www.ainoniwa.net/doku/programming/python/dpkt/start
		data_w.close()


main()
