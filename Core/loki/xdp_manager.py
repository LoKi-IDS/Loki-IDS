"""
XDP Manager for Loki IDS
Manages XDP program loading and blacklist updates from Python
"""
import os
import socket
import struct
from bcc import BPF


class XDPManager:
    """
    Manages eBPF/XDP fast filtering
    Updates blacklist when Python IDS detects attacks
    """
    
    def __init__(self, interface="eth0", xdp_file="xdp_filter.c"):
        """
        Initialize XDP manager
        
        Args:
            interface: Network interface to attach XDP to
            xdp_file: Path to XDP C source file
        """
        self.interface = interface
        self.xdp_file = xdp_file
        self.bpf = None
        self.blacklist_map = None
        self.rate_limit_map = None
        self.stats_map = None
        self.enabled = False
    
    def load_and_attach(self):
        """
        Load XDP program and attach to interface
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if XDP file exists
            if not os.path.exists(self.xdp_file):
                print(f"[!] XDP file not found: {self.xdp_file}")
                print(f"[*] XDP disabled, using nfqueue only")
                return False
            
            # Load XDP program
            print(f"[*] Loading XDP program from {self.xdp_file}...")
            self.bpf = BPF(src_file=self.xdp_file)
            
            # Get function
            fn = self.bpf.load_func("xdp_firewall", BPF.XDP)
            
            # Attach to interface (generic mode for Raspberry Pi)
            self.bpf.attach_xdp(self.interface, fn, 0)
            
            # Get map references
            self.blacklist_map = self.bpf["blacklist"]
            self.rate_limit_map = self.bpf["rate_limit"]
            self.stats_map = self.bpf["stats"]
            
            self.enabled = True
            print(f"[+] XDP attached to {self.interface}")
            print(f"[*] Fast filtering enabled at NIC level")
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to load XDP: {e}")
            print(f"[*] Continuing without XDP (nfqueue only)")
            self.enabled = False
            return False
    
    def add_to_blacklist(self, ip_address):
        """
        Add IP to XDP blacklist
        Future packets from this IP will be dropped at NIC level
        
        Args:
            ip_address: IP address string (e.g., "192.168.1.100")
        
        Returns:
            bool: True if added, False if XDP not enabled
        """
        if not self.enabled or not self.blacklist_map:
            return False
        
        try:
            # Convert IP string to network byte order integer
            ip_int = struct.unpack("!I", socket.inet_aton(ip_address))[0]
            
            # Add to blacklist map (value = current timestamp)
            import time
            timestamp = int(time.time())
            
            self.blacklist_map[self.blacklist_map.Key(ip_int)] = \
                self.blacklist_map.Leaf(timestamp)
            
            print(f"[XDP] Blacklisted {ip_address} (instant blocking enabled)")
            return True
            
        except Exception as e:
            print(f"[!] Failed to add {ip_address} to XDP blacklist: {e}")
            return False
    
    def remove_from_blacklist(self, ip_address):
        """
        Remove IP from blacklist
        
        Args:
            ip_address: IP address string
        
        Returns:
            bool: True if removed, False otherwise
        """
        if not self.enabled or not self.blacklist_map:
            return False
        
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip_address))[0]
            del self.blacklist_map[self.blacklist_map.Key(ip_int)]
            print(f"[XDP] Removed {ip_address} from blacklist")
            return True
        except Exception as e:
            print(f"[!] Failed to remove {ip_address}: {e}")
            return False
    
    def get_stats(self):
        """
        Get XDP statistics
        
        Returns:
            dict: Statistics counters
        """
        if not self.enabled or not self.stats_map:
            return None
        
        try:
            stats = {}
            stats['total_packets'] = self.stats_map[self.stats_map.Key(0)].value
            stats['dropped_packets'] = self.stats_map[self.stats_map.Key(1)].value
            stats['blacklist_hits'] = self.stats_map[self.stats_map.Key(2)].value
            stats['rate_limit_hits'] = self.stats_map[self.stats_map.Key(3)].value
            
            # Calculate drop rate
            if stats['total_packets'] > 0:
                stats['drop_rate'] = (stats['dropped_packets'] / stats['total_packets']) * 100
            else:
                stats['drop_rate'] = 0.0
            
            return stats
        except:
            return None
    
    def print_stats(self):
        """Print XDP statistics"""
        if not self.enabled:
            return
        
        stats = self.get_stats()
        if stats:
            print(f"\n[XDP Statistics]")
            print(f"  Total packets: {stats['total_packets']}")
            print(f"  Dropped: {stats['dropped_packets']} ({stats['drop_rate']:.2f}%)")
            print(f"  Blacklist hits: {stats['blacklist_hits']}")
            print(f"  Rate limit hits: {stats['rate_limit_hits']}")
    
    def cleanup(self):
        """Detach XDP and cleanup"""
        if self.enabled and self.bpf:
            try:
                self.bpf.remove_xdp(self.interface, 0)
                print(f"[*] XDP detached from {self.interface}")
            except Exception as e:
                print(f"[!] Error detaching XDP: {e}")
        
        self.enabled = False


# Singleton instance
xdp_manager = XDPManager()
