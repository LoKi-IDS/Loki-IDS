from netfilterqueue import NetfilterQueue
import threading
import time
import datetime
from scapy.all import IP, TCP, UDP


def process_packet(packet, IsInput):
    if IsInput:
        # now we are working in the input chain packet..
        pkt = IP(packet.get_payload()) # get the IP layer (it may have none if it's ICMP)..
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        timestamp = packet.get_timestamp()
        packetID = packet.id
        payloadLen = packet.get_payload_len()
        dst_port = 0 # just in case that the packet has no TCP or UDP port.
        src_port = 0

        if pkt.haslayer(TCP) : 
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport

        elif pkt.haslayer(UDP) : 
            dst_port = pkt[UDP].dport
            src_port = pkt[UDP].sport

        # let's calculate the timestampppp::
        #finalTimeStamp = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        finalTimeStamp = datetime.datetime.fromtimestamp(timestamp, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')

        print(" *** Data Captured from INPUT chain ***")
        print()

        print(f" Source IP: {src_ip}\n Dest Ip {dst_ip}\n timestamp: {finalTimeStamp}\n PacketID: {packetID}\n Payload Len: {payloadLen}\n Dst port: {dst_port}\n src port: {src_port}\n")

        # then just accept it:
        packet.accept()

    else:
        # now working withing the forward chain
        # do the same as above, but I'm lazy to rewrite it, just print anything and move-on..
        print("*** Recieved Data from FORWARD chain ***")
        print()

        packet.accept()

def forward_agent():
    nfq = NetfilterQueue()
    nfq.bind(200, lambda packet: process_packet(packet, False))

    try:
        nfq.run()
    except Exception as e:
        print(f"[!] forward agent crashed: {e}")


def input_agent():
    nfq = NetfilterQueue()
    nfq.bind(100, lambda packet: process_packet(packet, True))
    
    try:
        nfq.run()
    
    except Exception as e:
        print(f"[!] Input agent crashed: {e}")


if __name__ == "__main__":
    print("========== Starting LOKI IDS ==========")
    print()
    
    # let's now create the 2 threads..
    input_thread= threading.Thread(target=input_agent, daemon=True)
    forward_thread= threading.Thread(target=forward_agent, daemon= True)


    # now let's start it:::
    input_thread.start()
    forward_thread.start()

    print(" ### The Threads have started ### ")

    # let's make sure the main thread exit peacefully::
    try:
        while True:
            time.sleep(1) # just sleep for one second, then intercept.
    except KeyboardInterrupt:
        print()
        print("[*] Recieved ^C, then Quitting...")
        print(" ========== Stopping LOKI IDS ==========")


