# replaytcp
A Python script that utilizes Scapy to reconstruct TCP sessions.

Useful if you need to replay TCP-based logs to a SIEM log collector or if you happen upon a site that doesn't understand what a CSRF token is...

### **About**
Tcpreplay will pick apart the supplied PCAP file and strip the body of either *all* the packets or just the ones marked by a specific *destination port*.
Sequence and acknowledgement numbers are discarded in favor of new (read: correct) ones but the rest of the packet can stay the same.

### **Usage**
replaytcp.py <Destination IP Address> <Destination Port> [<Source IP Address>] [<Original Destination Port>] <PCAP File>

Obviously you will need both **<Destination IP address>** and **<Destination Port>** so the script knows who to connect to
Since we are replaying, you can spoof a custom **<Source IP Address>** for the packets. If you don't then your active interface IP will be used.
If **<Original Destination Port>** is added then only packets in the PCAP with a matching destination port will be reconstructed.
Lastly, you need the **<PCAP File>** to replay.

### Notes
This script uses Scapy and therfore will only work with Python 2.7 on Windows so it is highly recommended that you use Linux.
You can install scapy via *pip install scapy* for Python 2 or *pip install scapy-python3* for Python 3.

-@BaddaBoom