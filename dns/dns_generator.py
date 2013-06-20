#
# Mariano `emdel` Graziano
# DNS generator and sniffer
# summer 2011
#


from scapy.all import * 
import time, os, sys
from random import randrange

SITES = [ "www.slashdot.org",
	  "www.google.com",
	  "www.facebook.com",
	  "www.twitter.com"
	]
TCPDUMP = "/usr/sbin/tcpdump"
proc = 0

def die():
	print "[!] I'm exiting"
	stop_sniffer()
	sys.exit(-1)


def start_sniffer(pcap):
	# Check if tcpdump is installed
	if not os.path.exists(TCPDUMP):
       		print "[+] Cannot find tcpdump path at \"%s\". Please check your installation." % TCPDUMP
            	die()

	# Check if the suid bit is set
	mode = os.stat(TCPDUMP)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
        	print "[-] Tcpdump doesn't have SUID bit set."
		die()
		
	# tcpdump arguments/flags
	pargs = [TCPDUMP, '-q', '-i', 'eth0', '-n', '-s', '1515']
        pargs.extend(['-w', pcap])
	pargs.extend(['udp port 53')

	try:
        	proc = subprocess.Popen(pargs)
       	except Exception, why:
            	print "[-] Error starting tcpdump: %s" % why
            	die()

	print "[+] Tcpdump started monitoring UDP."
	

def stop_sniffer():
	if self.proc != None and self.proc.poll() == None:
		try:
			proc.terminate()
		except Exception, why:
		        print "[-] Error stopping tcpdump: %s" % why
		        die()

		    	print "[-] Stopping tcpdump."

def main():
	print "*** dns checker ***"

	if len(argc) != 3:
		print "\n> Usage: %s <output pcap file> <max # request>" % sys.argv[0]
		die()

	print "[+] Invoking the sniffer..."
	start_sniffer(sys.argv[1])	

	for i in range(0, sys.argv[2]):
		for site in SITES:
			print "* DNS query number %d to %s" % (i, site)
			send(IP(dst="10.0.0.1")/UDP(sport=randrange(1000,50000))/DNS(id=randrange(0,30000),rd=1,qd=DNSQR(qname=site)))
			time.sleep(1)



