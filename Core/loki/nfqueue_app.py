from netfilterqueue import NetfilterQueue
import threading
import time
from packet_parser import scan_packet
from detectore_engine import PortScanningDetector  # Now with EWMA!
from signature_engine import SignatureScanning
from scapy.all import IP, Raw, ICMP
from logger import logger, AlertType, AlertSubtype
from db_integration import db_integration

# NEW: Import XDP manager
try:
    from xdp_manager import xdp_manager
    XDP_AVAILABLE = True
except ImportError:
    print("[!] XDP module not available, continuing without it")
    XDP_AVAILABLE = False
    xdp_manager = None


def process_packet(packet, IsInput, port_scanner, sig_scanner):
    
    chain_name = "INPUT" if IsInput else "FORWARD"

    try:
        packetInfo = scan_packet(packet)
        src_ip = packetInfo.get("src_ip")
        dst_ip = packetInfo.get("dst_ip")
        src_port = packetInfo.get("src_port")
        dst_port = packetInfo.get("dst_port")
        raw_timestamp = packetInfo.get("rawts")
        tcp_flags = packetInfo.get("tcp_flags")
        port = packetInfo.get('port')

        # Filter localhost traffic (both endpoints are localhost)
        if src_ip.startswith('127.') and dst_ip.startswith('127.'):
            packet.accept()
            return

        # safe, nfqueue always returns the IP layer not the ethernet..
        ip_layer = IP(packet.get_payload())
        is_icmp = ip_layer.haslayer(ICMP)
        if is_icmp:
            port = "ICMP"

        logger.console_logger.info(f"[{chain_name}] Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({port})")
        
        # TCP Analysis (now with EWMA!)
        if port == "TCP" and (tcp_flags & 0x02) and not (tcp_flags & 0x10):

            analyze_result = port_scanner.analyze_tcp(src_ip, dst_ip, raw_timestamp, dst_port)

            if analyze_result != 0:
                if analyze_result == 1:
                    message = f"Port Scan Detected on {chain_name} chain"
                    subtype = AlertSubtype.PORT_SCAN
                else:
                    message = f"TCP Flood (DoS/DDoS) Detected on {chain_name} chain"
                    subtype = AlertSubtype.TCP_FLOOD

                # ALERT
                logger.log_alert(
                    alert_type=AlertType.BEHAVIOR,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    message=message,
                    details={
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "chain": chain_name
                    },
                    subtype=subtype
                )
                
                # NEW: Add attacker to XDP blacklist
                if XDP_AVAILABLE and xdp_manager.enabled:
                    xdp_manager.add_to_blacklist(src_ip)
                
                # Drop packet
                packet.drop()
                return

        # UDP Analysis (now with EWMA!)
        elif port == "UDP":

            analyze_result = port_scanner.analyze_udp(dst_ip, raw_timestamp, dst_port)

            if analyze_result:
                # ALERT:
                logger.log_alert(
                    alert_type=AlertType.BEHAVIOR,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    message=f"UDP Flood (DoS/DDoS) Detected on {chain_name} chain",
                    details={
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "chain": chain_name
                    },
                    subtype=AlertSubtype.UDP_FLOOD
                )
                
                # NEW: Add to XDP blacklist
                if XDP_AVAILABLE and xdp_manager.enabled:
                    xdp_manager.add_to_blacklist(src_ip)
                
                packet.drop()
                return

        # ICMP Analysis (now with EWMA!)
        elif is_icmp and ip_layer[ICMP].type == 8:  # echo req
            analyze_result = port_scanner.analyze_icmp(dst_ip, raw_timestamp)
            if analyze_result:
                # ALERT: ICMP Flood Detected
                logger.log_alert(
                    alert_type=AlertType.BEHAVIOR,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    message=f"ICMP Flood (DoS/DDoS) Detected on {chain_name} chain",
                    details={
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "chain": chain_name
                    },
                    subtype=AlertSubtype.ICMP_FLOOD
                )
                
                # NEW: Add to XDP blacklist
                if XDP_AVAILABLE and xdp_manager.enabled:
                    xdp_manager.add_to_blacklist(src_ip)
                
                packet.drop()
                return

        else:  # some other packet
            logger.console_logger.debug(f"Other: [{chain_name}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({port})")

        # Signature scanning
        if ip_layer.haslayer(Raw):
            RawData = ip_layer[Raw].load
            RuleName, RulePattern, Drop = sig_scanner.CheckPacketPayload(RawData)
            
            if RuleName:  # Match Found
                # ALERT: Signature Match
                logger.log_alert(
                    alert_type=AlertType.SIGNATURE,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    message=f"Signature Match: {RuleName}",
                    details={
                        "pattern": str(RulePattern),
                        "action": "ALERT",
                        "chain": chain_name
                    },
                    subtype=None,
                    pattern=str(RulePattern)
                )
                
                # NEW: Add to XDP blacklist
                if XDP_AVAILABLE and xdp_manager.enabled:
                    xdp_manager.add_to_blacklist(src_ip)

        packet.accept()

    except Exception as e:
        logger.console_logger.error(f"[!] Error processing packet: {e}")
        packet.accept()


def forward_agent(sig_object):
    nfq = NetfilterQueue()
    port_scanner_object_forward = PortScanningDetector(15, 10)
    nfq.bind(200, lambda packet: process_packet(packet, False, port_scanner_object_forward, sig_object))

    try:
        nfq.run()
    except Exception as e:
        logger.console_logger.critical(f"[!] Forward agent crashed: {e}")


def input_agent(sig_object):
    nfq = NetfilterQueue()
    port_scanner_object_input = PortScanningDetector(15, 10)
    nfq.bind(100, lambda packet: process_packet(packet, True, port_scanner_object_input, sig_object))
        
    try:
        nfq.run()
    except Exception as e:
        logger.console_logger.critical(f"[!] Input agent crashed: {e}")


if __name__ == "__main__":
    logger.log_system_event("========== Starting LOKI IDS ==========", "INFO")
    
    # Enable database integration (for signatures and logging)
    if db_integration.enable():
        logger.log_system_event("Database integration enabled", "INFO")
    else:
        logger.log_system_event("Database integration failed", "WARNING")
    
    # NEW: Try to load XDP (optional, won't fail if unavailable)
    if XDP_AVAILABLE:
        if xdp_manager.load_and_attach():
            logger.log_system_event("XDP fast filtering enabled at NIC level", "INFO")
        else:
            logger.log_system_event("XDP not available, using nfqueue only", "WARNING")
    
    # Load signatures
    try:
        sig_object = SignatureScanning()
        logger.log_system_event("Signature rules loaded successfully", "INFO")
    except Exception as e:
        logger.log_system_event(f"Failed to load signatures: {e}", "ERROR")
        sig_object = None

    if sig_object:
        input_thread = threading.Thread(target=input_agent, args=(sig_object,), daemon=True)
        forward_thread = threading.Thread(target=forward_agent, args=(sig_object,), daemon=True)

        input_thread.start()
        forward_thread.start()

        logger.log_system_event("Detection threads started successfully", "INFO")

    # Alert lifecycle management
    last_check_time = time.time()
    last_stats_time = time.time()
    check_interval = 2
    stats_interval = 60  # Show stats every minute
    
    try:
        while True:
            time.sleep(1)
            
            current_time = time.time()
            
            # Check for ended attacks
            if current_time - last_check_time >= check_interval:
                ended_count = logger.check_ended_alerts()
                if ended_count > 0:
                    stats = logger.get_stats()
                    logger.console_logger.debug(
                        f"Closed {ended_count} attack(s) | "
                        f"Active: {stats['active_alerts']} | "
                        f"Suppressed: {stats['suppressed_alerts']}"
                    )
                last_check_time = current_time
            
            # Show XDP stats periodically
            if XDP_AVAILABLE and xdp_manager.enabled:
                if current_time - last_stats_time >= stats_interval:
                    xdp_manager.print_stats()
                    last_stats_time = current_time
                
    except KeyboardInterrupt:
        print()
        logger.log_system_event("Received shutdown signal (Ctrl+C)", "WARNING")
        
        # Final cleanup
        logger.check_ended_alerts()
        stats = logger.get_stats()
        logger.log_system_event(
            f"Session stats - Active: {stats['active_alerts']}, "
            f"Suppressed: {stats['suppressed_alerts']}, "
            f"Efficiency: {stats['suppression_rate']}",
            "INFO"
        )
        
        # Cleanup XDP
        if XDP_AVAILABLE and xdp_manager.enabled:
            xdp_manager.print_stats()
            xdp_manager.cleanup()
        
        logger.log_system_event("========== Stopping LOKI IDS ==========", "INFO")
