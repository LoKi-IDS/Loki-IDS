from netfilterqueue import NetfilterQueue
import threading
import time
from packet_parser import scan_packet
from detectore_engine import PortScanningDetector
from signature_engine import SignatureScanning
from scapy.all import IP, Raw, ICMP
from logger import logger  # my logger module


def process_packet(packet, IsInput, port_scanner, sig_scanner, ip_blacklist):
    
    chain_name = "INPUT" if IsInput else "FORWARD"

    try:
        # now we are working in the input chain packet..
        packetInfo = scan_packet(packet)
        src_ip = packetInfo.get("src_ip")
        dst_ip = packetInfo.get("dst_ip")
        src_port = packetInfo.get("src_port")
        dst_port = packetInfo.get("dst_port")
        raw_timestamp = packetInfo.get("rawts")
        tcp_flags = packetInfo.get("tcp_flags")
        port = packetInfo.get('port')

        # safe, nfqueue always returns the IP layer not the ethernet..
        ip_layer = IP(packet.get_payload())
        is_icmp = ip_layer.haslayer(ICMP)
        if is_icmp:
            port = "ICMP"


        if src_ip in ip_blacklist:
             logger.log_alert(
                alert_type= "BLACKLIST",
                src_ip= src_ip,
                dst_ip= dst_ip,
                src_port= src_port,
                dst_port= dst_port,
                message=f"Blocking packets coming from ip_blacklist on {chain_name} chain",
                details={
                    "dst_ip": dst_ip,
                    "dst_port": packetInfo.get("dst_port"),
                    "chain": chain_name
                })
             packet.drop()
             return

      #  print(" *** Data Captured from INPUT chain ***")
      # print()

      #  print(f" Source IP: {packetInfo.get("src_ip")}\n Dest Ip {packetInfo.get("dst_ip")}\n timestamp: {packetInfo.get("timestamp")}\n PacketID: {packetInfo.get("packetID")}\n Payload Len: {packetInfo.get("payloadLen")}\n Dst port: {packetInfo.get("dst_port")}\n src port: {packetInfo.get("src_port")}\n TCP or UDP: {packetInfo.get("port")}\n")
        
        #print("the data are: ")
        #print(packetInfo)
        
        logger.console_logger.info(f"[{chain_name}] Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({port})")
        
        # let's now try to analyze it with the port scanner:

        # ok now we need to organize our scanning according to the type of packet. 
        # if it's TCP, UDP, ICMP (for now),,
        # TCP:
        # - SYN port scanning
        # - SYN flood (DoS)
        # ----------------
        # UDP
        # - UDP flood (DoS)
        #----------------
        # ICMP
        # - ICMP flood (DoS)

        # TCP should be only matter if SYN and not ACK to be classified as an
        # attack (again just for the moment, maybe modified latter)..
        if port == "TCP" and (tcp_flags & 0x02) and not (tcp_flags & 0x10):

            analyze_result = port_scanner.analyze_tcp(src_ip, dst_ip, raw_timestamp, dst_port)

            if analyze_result != 0:
                if analyze_result == 1:
                    message = f"Port Scan Detected on {chain_name} chain"
                else:
                    message = f"TCP Flood (DoS/DDoS) Detected on {chain_name} chain"

                # ALERT
                logger.log_alert(
                    alert_type="BEHAVIOR",
                    src_ip= src_ip,
                    dst_ip= dst_ip,
                    src_port= src_port,
                    dst_port= dst_port,
                    message= message,
                    details={
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "chain": chain_name
                    }
                )

        elif port == "UDP":

            analyze_result = port_scanner.analyze_udp(dst_ip, raw_timestamp, dst_port)

            if analyze_result:
                # ALERT:
                logger.log_alert(
                    alert_type="BEHAVIOR",
                    src_ip=src_ip,
                    dst_ip= dst_ip,
                    src_port= src_port,
                    dst_port= dst_port,
                    message=f"UDP Flood (DoS/DDoS) Detected on {chain_name} chain",
                    details={
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "chain": chain_name
                    }
                )

        elif is_icmp and ip_layer[ICMP].type == 8 : # echo req
            analyze_result = port_scanner.analyze_icmp(dst_ip, raw_timestamp)
            if analyze_result:
                # ALERT: Port Scan Detected
                logger.log_alert(
                    alert_type="BEHAVIOR",
                    src_ip=src_ip,
                    dst_ip= dst_ip,
                    src_port= src_port,
                    dst_port= dst_port,
                    message=f"ICMP Flood (DoS/DDoS) Detected on {chain_name} chain",
                    details={
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "chain": chain_name
                    }
                )

        else : # some other packet, we may just log it to type of packets in normal conditions
            logger.console_logger.info(f"Wierd type of packet: [{chain_name}] Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({port})")


        #analyze_result = port_scanner.analyze_packet(src_ip, dst_ip, raw_timestamp, dst_port, tcp_flags)
        
        #print(f"the analyze result is : {analyze_result}")
        
        # if analyze_result:
        #     # ALERT: Port Scan Detected
        #     logger.log_alert(
        #         alert_type="BLACKLIST",
        #         src_ip=src_ip,
        #         dst_ip= dst_ip,
        #         src_port= src_port,
        #         dst_port= dst_port,
        #         message=f"Port Scan Detected on {chain_name} chain",
        #         details={
        #             "dst_ip": dst_ip,
        #             "dst_port": packetInfo.get("dst_port"),
        #             "chain": chain_name
        #         }
        #     )

        # let's now test the signature based scanning..
              
        if ip_layer.haslayer(Raw):
          # print("packet has a Raw layer..")
            RawData = ip_layer[Raw].load
            RuleName, RulePattern, Drop = sig_scanner.CheckPacketPayload(RawData)
           #print(f"Rule Name: {RuleName}, Rule Pattern: {RulePattern}, Drop: {Drop}")
            
            if RuleName: # Match Found
                # ALERT: Signature Match
                logger.log_alert(
                    alert_type="SIGNATURE",
                    src_ip=src_ip,
                    dst_ip= dst_ip,
                    src_port= src_port,
                    dst_port= dst_port,
                    message=f"Signature Match: {RuleName}",
                    details={
                        "pattern": str(RulePattern),
                        "action": "DROP" if Drop else "ALERT",
                        "chain": chain_name
                    }
                )
                
                # Check if we need to drop based on signature rule
                if Drop:
                    logger.console_logger.warning(f"[*] Dropping packet from {src_ip} due to signature match.")
                    ip_blacklist.append(src_ip)
                    packet.drop()
                    return 

       #else:
        #   print("the packet has no Raw Layer..***********")
        # then just accept it:

        packet.accept()

    except Exception as e:
        logger.console_logger.error(f"[!] Error processing packet: {e}")
        packet.accept()

def forward_agent(sig_object, ip_blacklist):
    nfq = NetfilterQueue()
    port_scanner_object_forward = PortScanningDetector(15, 10)
    nfq.bind(200, lambda packet: process_packet(packet, False, port_scanner_object_forward, sig_object, ip_blacklist))

    try:
        nfq.run()

    except Exception as e:
        logger.console_logger.critical(f"[!] Forward agent crashed: {e}")


def input_agent(sig_object, ip_blacklist):
    nfq = NetfilterQueue()
    port_scanner_object_input = PortScanningDetector(15, 10)
    #sig_scanner_object_input = SignatureScanning()
    nfq.bind(100, lambda packet: process_packet(packet, True, port_scanner_object_input, sig_object, ip_blacklist))
        
    try:
        nfq.run()
    
    except Exception as e:
        logger.console_logger.critical(f"[!] Input agent crashed: {e}")


if __name__ == "__main__":
    logger.console_logger.info("========== Starting LOKI IDS ==========")
   #print()
    
    # let's now create the 2 threads..
    try:
        sig_object = SignatureScanning() # Load rules
    except Exception as e:
        logger.console_logger.error(f"Failed to load signatures: {e}")
        sig_object = None # Handle gracefully or exit

    if sig_object:
        ip_blacklist = []
        input_thread = threading.Thread(target=input_agent, args=(sig_object, ip_blacklist,), daemon=True)
        forward_thread = threading.Thread(target=forward_agent, args=(sig_object, ip_blacklist,), daemon=True)

        # now let's start it:::
        input_thread.start()
        forward_thread.start()

        logger.console_logger.info(" ### The Threads have started ### ")

    # let's make sure the main thread exit peacefully::
    try:
        while True:
            time.sleep(1) # just sleep for one second, then intercept.
    except KeyboardInterrupt:
        print()
        logger.console_logger.info("[*] Received ^C, Quitting...")
        logger.console_logger.info(" ========== Stopping LOKI IDS ==========")
