from netfilterqueue import NetfilterQueue
import time
from collections import deque, defaultdict, Counter

# global var
MAX_SECONDS = 100

class PortScanningDetector:
    def __init__(self, threshold, max_seconds):
        self.threshold = threshold
        self.log = defaultdict(deque)
        self.m_sec = MAX_SECONDS

        # the dictionary should have the time, and ip address, and port accessed.
        # the IP as a key, and list of (time, port access) as a value.

    def analyze_packet(self, ip_address, timestamp, port_number):
        if ip_address not in self.log:
            # now it's the simplest case, just add it to the dictionary:    
            self.log[ip_address].append((timestamp, port_number))
            # and that's it...
            return False

        else:
            # now it's the main thing, here we should compare and do the other logic.
            
            history = self.log.get(ip_address)

            # check if there's already an item there and the difference in time is not big..
            while history and ((timestamp - history[0][0]) > self.m_sec) :
                # just pop up that entry::
                history.popleft()
                
            # let's just append that item..
            history.append((timestamp, port_number))

            # now you have everything fresh, let's go to the next step::
            # 2. now the last and most important thing, let's check if the uniqueue port access is bigger than the threshold::
            active_ports = [item[1] for item in history]
            # I used a set to automatically add only unique items

            #now let's check if the list contains more than 10 items
            if len(active_ports) > self.threshold:
                return True

            return False




            


