from scapy.all import *  # Import the scapy module

# Create empty variables for AtIP, DstIP, AtMac and DstMac
AtIP = ""
DstIP = ""
AtMac = ""
DstMac = ""

packets = rdpcap('capture2.pcap')  # Read the contents of the capture2 pcap file and store it under the variable packets

for packet in packets:  # Establish a for loop that reads the lines of packets and stores it under the variable packet
    if packet.haslayer(ARP):  # See if the packet uses the arp protocol
        if packet.dst != 'ff:ff:ff:ff:ff:ff':  # Check if the packets destination mac is ff:ff:ff:ff:ff:ff
            if AtIP == "":  # If the variable AtIP hasn't been defined proceed with the following code
                AtIP = packet.psrc   # Assign the packet source IP to the AtIP variable
            # If the variable DstIP hasn't been defined and the destination IP isn't the same as the attackers IP proceed with the following code
            elif DstIP == "" and packet.pdst != AtIP:
                DstIP = packet.pdst # Assign the packet destination IP to the DstIP variable
            elif AtMac == "":  # If the variable AtMac hasn't been defined proceed with the following code
                AtMac = packet.src   # Assign the packet source Mac to the AtMac variable
            # If the variable DstMac hasn't been defined and the destination Mac isn't the same as the attackers Mac proceed with the following code
            elif DstMac == "" and packet.dst != AtMac:
                DstMac = packet.dst  # Assign the packet destination Mac to the DstMac variable

# Display the output information to the user
print "Attackers IP = " + AtIP
print "Destination IP = " + DstIP
print "Attackers MAC = " + AtMac
print "Destination MAC = " + DstMac