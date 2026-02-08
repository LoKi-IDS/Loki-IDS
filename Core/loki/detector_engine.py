"""
Detection Engine with EWMA Burst Detection
Enhanced version with Exponentially Weighted Moving Average for adaptive thresholds
"""
from netfilterqueue import NetfilterQueue
import time
from collections import deque, defaultdict, Counter


class PortScanningDetector:
    """
    Enhanced detector with EWMA-based burst detection
    Detects: Port Scanning, TCP Flood, UDP Flood, ICMP Flood
    """
    
    def __init__(self, threshold=15, max_seconds=10):
        self.threshold = threshold
        self.m_sec = max_seconds
        
        # Original detection state
        self.port_scanning_log = defaultdict(deque)
        self.tcp_flood_log = defaultdict(deque)
        self.udp_flood_log = defaultdict(deque)
        self.icmp_flood_log = defaultdict(deque)
        
        # Original thresholds
        self.port_scanning_window = 5
        self.port_scanning_threshold = 20
        
        self.tcp_flood_window = 2
        self.tcp_flood_threshold = 200
        self.tcp_ack_ratio = 0.2
        
        self.udp_flood_window = 2
        self.udp_flood_threshold = 300
        
        self.icmp_flood_window = 2
        self.icmp_flood_threshold = 100
        
        # ===== NEW: EWMA Tracking =====
        self.ewma_tcp = {}     # Key: (dst_ip, dst_port) -> EWMA value
        self.ewma_udp = {}     # Key: (dst_ip, dst_port) -> EWMA value
        self.ewma_icmp = {}    # Key: dst_ip -> EWMA value
        
        # EWMA parameters
        self.alpha = 0.3              # Smoothing factor (30% new, 70% history)
        self.burst_multiplier = 3.0   # Alert when traffic > 3x baseline
        # =================================
    
    def update_ewma(self, ewma_dict, key, current_value):
        """
        Update EWMA and detect burst
        
        Args:
            ewma_dict: Dictionary storing EWMA values
            key: Grouping key (e.g., (dst_ip, dst_port))
            current_value: Current rate (packets per second)
        
        Returns:
            (old_ewma, new_ewma, is_burst)
        """
        # First time seeing this key
        if key not in ewma_dict:
            ewma_dict[key] = current_value
            return (current_value, current_value, False)
        
        old_ewma = ewma_dict[key]
        
        # Check for burst BEFORE updating EWMA
        is_burst = False
        if old_ewma > 0:
            ratio = current_value / old_ewma
            if ratio > self.burst_multiplier:
                is_burst = True
        
        # Calculate new EWMA
        new_ewma = self.alpha * current_value + (1 - self.alpha) * old_ewma
        
        # Update stored EWMA
        ewma_dict[key] = new_ewma
        
        return (old_ewma, new_ewma, is_burst)
    
    def analyze_tcp(self, src_ip_add, dst_ip_add, timestamp, port_number):
        """
        Analyze TCP packet for port scan and SYN flood
        Enhanced with EWMA burst detection
        
        Returns:
            0 => No attack
            1 => Port scanning
            2 => TCP flood
        """
        # === Port Scan Detection (Original Logic) ===
        scan_key = (src_ip_add, dst_ip_add)
        
        if scan_key not in self.port_scanning_log:
            self.port_scanning_log[scan_key].append((timestamp, port_number))
            # Continue to flood check
        else:
            history = self.port_scanning_log[scan_key]
            
            # Remove old entries
            while history and ((timestamp - history[0][0]) > self.port_scanning_window):
                history.popleft()
            
            history.append((timestamp, port_number))
            
            # Check unique ports
            active_ports = {item[1] for item in history}
            if len(active_ports) > self.port_scanning_threshold:
                return 1  # Port scan detected!
        
        # === TCP Flood Detection (Enhanced with EWMA) ===
        flood_key = (dst_ip_add, port_number)
        
        if flood_key not in self.tcp_flood_log:
            self.tcp_flood_log[flood_key].append(timestamp)
        else:
            history = self.tcp_flood_log[flood_key]
            
            # Remove old entries
            while history and ((timestamp - history[0]) > self.tcp_flood_window):
                history.popleft()
            
            history.append(timestamp)
            
            # Calculate current rate (packets per second)
            time_span = timestamp - history[0] if len(history) > 1 else 1
            current_rate = len(history) / time_span if time_span > 0 else 0
            
            # === NEW: EWMA Burst Detection ===
            old_baseline, new_baseline, is_burst = self.update_ewma(
                self.ewma_tcp,
                flood_key,
                current_rate
            )
            
            if is_burst:
                # Burst detected! Traffic is 3x+ normal baseline
                return 2  # TCP flood!
            # =================================
            
            # Fallback to original threshold check (if EWMA didn't catch it)
            if len(history) > self.tcp_flood_threshold:
                return 2
        
        return 0  # No attack
    
    def analyze_udp(self, dst_ip_add, timestamp, port_number):
        """
        Analyze UDP packet for flood
        Enhanced with EWMA burst detection
        
        Returns:
            True => UDP flood detected
            False => Normal traffic
        """
        flood_key = (dst_ip_add, port_number)
        
        if flood_key not in self.udp_flood_log:
            self.udp_flood_log[flood_key].append(timestamp)
            return False
        else:
            history = self.udp_flood_log[flood_key]
            
            # Remove old entries
            while history and ((timestamp - history[0]) > self.udp_flood_window):
                history.popleft()
            
            history.append(timestamp)
            
            # Calculate current rate
            time_span = timestamp - history[0] if len(history) > 1 else 1
            current_rate = len(history) / time_span if time_span > 0 else 0
            
            # === NEW: EWMA Burst Detection ===
            old_baseline, new_baseline, is_burst = self.update_ewma(
                self.ewma_udp,
                flood_key,
                current_rate
            )
            
            if is_burst:
                return True  # UDP flood detected!
            # =================================
            
            # Fallback to original threshold
            if len(history) > self.udp_flood_threshold:
                return True
            
            return False
    
    def analyze_icmp(self, dst_ip_add, timestamp):
        """
        Analyze ICMP packet for flood
        Enhanced with EWMA burst detection
        
        Returns:
            True => ICMP flood detected
            False => Normal traffic
        """
        flood_key = dst_ip_add  # ICMP grouped by destination IP only
        
        if flood_key not in self.icmp_flood_log:
            self.icmp_flood_log[flood_key].append(timestamp)
            return False
        else:
            history = self.icmp_flood_log[flood_key]
            
            # Remove old entries
            while history and ((timestamp - history[0]) > self.icmp_flood_window):
                history.popleft()
            
            history.append(timestamp)
            
            # Calculate current rate
            time_span = timestamp - history[0] if len(history) > 1 else 1
            current_rate = len(history) / time_span if time_span > 0 else 0
            
            # === NEW: EWMA Burst Detection ===
            old_baseline, new_baseline, is_burst = self.update_ewma(
                self.ewma_icmp,
                flood_key,
                current_rate
            )
            
            if is_burst:
                return True  # ICMP flood detected!
            # =================================
            
            # Fallback to original threshold
            if len(history) > self.icmp_flood_threshold:
                return True
            
            return False
    
    def get_ewma_stats(self):
        """
        Get current EWMA statistics (for debugging/monitoring)
        
        Returns:
            dict: Current baselines for all tracked flows
        """
        return {
            'tcp_flows': len(self.ewma_tcp),
            'udp_flows': len(self.ewma_udp),
            'icmp_targets': len(self.ewma_icmp),
            'tcp_baselines': {str(k): v for k, v in list(self.ewma_tcp.items())[:5]},  # Sample
            'udp_baselines': {str(k): v for k, v in list(self.ewma_udp.items())[:5]},
            'icmp_baselines': {str(k): v for k, v in list(self.ewma_icmp.items())[:5]}
        }
