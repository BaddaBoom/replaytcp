#!/usr/bin/env python
import sys
import time
import datetime
import os.path
import re
import warnings

try:
	from scapy.all import *
except ImportError:
	print("\n\n[!] ERROR: could not import scapy! Please install the scapy python package.\n\n")
	sys.exit(1)
		
version = 3.0

##########
#
# color class (and color support check function)
#
# basically just colors to pretty print the terminal
#
##########
supported_platform = sys.platform != 'Pocket PC' and (sys.platform != 'win32' or 'ANSICON' in os.environ)
is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
if not supported_platform or not is_a_tty:
	CAN_COLOR = False
else:
	CAN_COLOR = True
class color:
	if CAN_COLOR:
		BLUE = '\x1b[34m'
		RED = '\x1b[31m'
		YELLOW = '\x1b[33m'
		GREEN = '\x1b[32m'
		PURPLE = '\x1b[35m'
		CYAN = '\x1b[36m'
		GRAY = '\x1b[37m'
		BOLD = '\x1b[1m'
		UL = '\x1b[4m'
		RESET = '\x1b[0m'
		# the following *may* be supported
		BLUEBOLD = '\x1b[94m'
		REDBOLD = '\x1b[91m'
		YELLOWBOLD = '\x1b[93m'
		GREENBOLD = '\x1b[92m'
		PURPLEBOLD = '\x1b[95m'
		CYANBOLD = '\x1b[96m'
	else:
		BLUE = RED = YELLOW = GREEN = PURPLE = CYAN = GRAY = BOLD = UL = RESET = BLUEBOLD = REDBOLD = YELLOWBOLD = GREENBOLD = PURPLEBOLD = CYANBOLD = ''

##########
#
# PacketGen class
#
# Handles the stream and pcap object methods
# and sends the data out
#
##########
class PacketGen:
	stream = None
	ip_obj = None
	tcp_obj = None
	pcap = None
	odport = None

	# constructor
	def __init__(self, dest_ip, dest_port, src_ip):
		s = socket.socket()
		try:
			s.connect((dest_ip,dest_port))
		except socket.error as e:
			msg = "Could not connect to " + str(dest_ip) + ":" + str(dest_port)
			raise_error(msg)
		else:
			self.stream = StreamSocket(s)
			self.ip_obj = IP(src=src_ip, dst=dest_ip)
			self.tcp_obj = TCP(dport=dest_port)

	# loads the PCAP into memory
	def read_in_pcap(self, in_pcap):
		self.pcap = rdpcap(in_pcap)
		return

	# returns the payload or None if no payload found
	def get_datafield(self, packet):
		if (Raw in packet):
			return packet[Raw].load
		else:
			return None

	# send the payload in a new packet
	def send_packet(self,  payload):
		code = self.stream.send(self.ip_obj/self.tcp_obj/payload)
		return code

	# returns the packet object
	def packets(self):
		return self.pcap
	
	# set the original dport to match
	def set_orig_dport(self, dport):
		self.odport = dport
		return

	# determine if its a matched packet via dport
	def dport_match(self, packet):
		# skip this check if no dport match was requested
		if self.odport is None:
			return True
		# check if dport match
		if (TCP in packet):
			curr_dport = packet[TCP].dport
			if not args_is_port(curr_dport):
				curr_dport = TCP_SERVICES[curr_dport]
			if self.odport == curr_dport:
				return True

		return False		
	
# such hacks.
def getIPaddr():
	from fcntl import ioctl
	from struct import pack
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(ioctl(s.fileno(), 0x8915, pack('256s', 'eth0'[:15]))[20:24])

# basic timestamp function
def timestamp():
	return "[ " + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + " ]"

### Arg Functions
# Test if it is an IP address (only IPv4 support!)
def args_is_addr(inarg):
	expr = re.compile('^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$')
	if expr.match(inarg):
		return True
	return False

# Test if it is a port number
def args_is_port(inarg):
	try:
		isint = int(inarg)
	except ValueError:
		return False
	# this is to verify not a float value
	if (isint % 1 != 0):
		return False
	# this is to verify valid port number
	if isint < 1 or isint > 65535:
		return False
	return True

# Test for file
def args_is_file(inarg):
	if os.path.isfile(inarg):
		return True
	else:
		return False

### End arg funcs
def raise_error(msg):
	print(color.REDBOLD + "[!] ERROR: " + msg + "\n" + color.RESET)
	sys.exit(1) 

# tell them how to use the script
def usage(program):
	print(color.PURPLEBOLD + "USAGE: " + str(program) + " <Destination IP Address> <Destination Port> [<Source IP Address>] [<Original Destination Port>] <PCAP File>\n" + color.RESET)
	print("   <Destination IP Address>\tWhere to send the new packets to.")
	print("   <Destination Port>\t\tThe port you want the send the packets to.")
	print("   <Source IP Address>\t\tThe (apparent) source of traffic. If not provided, your current eth0 will be used.")
	print("   <Original Destination Port>\tTo not send every packet with a payload, you can use this to match specific streams in the PCAP.")
	print("   <PCAP File>\t\t\tThe PCAP you wish to replay.\n")
	sys.exit(1)

# script entry point
if __name__ == '__main__':
	print("\n")
	
	print("\n ____                    ___                      ______  ____     ____  ")
	print("/\\  _`\\                 /\\_ \\                    /\\__  _\\/\\  _`\\  /\\  _`\\ ")
	print("\\ \\ \\L\\ \\     __   _____\\//\\ \\      __     __  __\\/_/\\ \\/\\ \\ \\/\\_\\\\ \\ \\L\\ \\ ")
	print(" \\ \\ ,  /   /'__`\\/\\ '__`\\\\ \\ \\   /'__`\\  /\\ \\/\\ \\  \\ \\ \\ \\ \\ \\/_/_\\ \\ ,__/ ")
	print("  \\ \\ \\\\ \\ /\\  __/\\ \\ \\L\\ \\\\_\\ \\_/\\ \\L\\.\\_\\ \\ \\_\\ \\  \\ \\ \\ \\ \\ \\L\\ \\\\ \\ \\/ ")
	print("   \\ \\_\\ \\_\\ \\____\\\\ \\ ,__//\\____\\ \\__/.\\_\\\\/`____ \\  \\ \\_\\ \\ \\____/ \\ \\_\\ ")
	print("    \\/_/\\/ /\\/____/ \\ \\ \\/ \\/____/\\/__/\\/_/ `/___/> \\  \\/_/  \\/___/   \\/_/ ")
	print("                     \\ \\_\\                     /\\___/ ")
	print("                      \\/_/                     \\/__/ \n\n")

	if len(sys.argv) < 4 or len(sys.argv) > 6:
		usage(sys.argv[0])
	
	# start the output
	print(color.PURPLEBOLD + "==========\n" + color.RESET)

	# manipulate args
	destination_addr = sys.argv[1]
	destination_port = sys.argv[2]
	odp = None
	if len(sys.argv) == 4: # No SRC IP or ORIG PORT
		input_pcap = sys.argv[3]
		eth0 = getIPaddr()
		print(color.YELLOWBOLD + "[!] No source address was provided." + color.RESET)
		print("[+] Using " + str(eth0) + " as the source.\n")
	elif len(sys.argv) == 5: # Either SRC IP or ORIG PORT
		input_pcap = sys.argv[4]
		# tricky. Is it IP or Port?
		if args_is_addr(sys.argv[3]):
			eth0 = sys.argv[3]
		elif args_is_port(sys.argv[3]):
			odp = sys.argv[3]
			# this is only up here for message syntax. 
			eth0 = getIPaddr()
			print(color.YELLOWBOLD + "[!] No source address was provided." + color.RESET)
			print("[+] Using " + str(eth0) + " as the source.\n")
		else:
			msg = str(sys.argv[3]) + " is neither a IP address or a port number"
			raise_error(msg)
	else: # Both SRC IP and ORIG PORT
		input_pcap = sys.argv[5]
		odp = sys.argv[4]
		eth0 = sys.argv[3]

	### Test all variables
	# test for valid file
	if not args_is_file(input_pcap):
		msg = input_pcap + " could not be found"
		raise_error(msg)

	# test if orig port and valid
	if odp is not None:
		if not args_is_port(odp):
			print(color.YELLOWBOLD + "[!] The provided port of " + str(odp) + " is not valid. Ignoring." + color.RESET)
			odp = None
		else:
			print("\n[+] Only sending packets with " + str(odp) + " as the destination port.\n")

	# test for valid source address
	if not args_is_addr(eth0):
		eth0 = getIPaddr()
		print(color.YELLOWBOLD + "[!] The source address provided was not valid." + color.RESET)
		print("[+] Using " + str(eth0) + " as the source.\n")

	# test for valid destination port
	if not args_is_port(destination_port):
		msg = str(destination_port) + " is not a valid port number (1 - 65535)"
		raise_error(msg)

	# test for valid destination address
	if not args_is_addr(destination_addr):
		msg = str(destination_addr) + " is not a valid destination address"
		raise_error(msg)

	# init
	packets = PacketGen(destination_addr, int(destination_port), eth0)
	
	# add the orig dest port to the object
	if odp is not None:
		packets.set_orig_dport(int(odp))
	
	# lets roll!
	print(color.GREENBOLD + "[+] All variables look good. Lets Begin!" + color.RESET)
	print(color.CYAN + "[+] Starting at " + timestamp() + "\n" + color.RESET)

	# load pcap
	sys.stdout.write("\r[+] Loading PCAP into memory. This may take a few minutes. Please wait ... ")
	sys.stdout.flush()
	packets.read_in_pcap(input_pcap)
	print("\r[+] Loading PCAP into memory. This may take a few minutes. Please wait ... Done!\n")

	print(color.CYAN + "[+] Starting transmission at " + timestamp() + color.RESET)
	# check, build, send packets
	sys.stdout.write("\r[+] Sending Packets. This may take a few minutes. Please wait ... ")
	sys.stdout.flush()
	allpackets = packets.packets()
	c = 0
	for i, v in enumerate(allpackets):
		pl = packets.get_datafield(v)
		if pl is not None and packets.dport_match(v):
			packets.send_packet(pl)
			c += 1
	
	# epilogue
	print("\r[+] Sending Packets. This may take a few minutes. Please wait ... Done!")
	print(color.CYAN + "\n[+] Finished at " + timestamp() + color.RESET)
	print(color.GREENBOLD + "[+] Sent " + str(c) + " packets.\n" + color.RESET)

	sys.exit(0)