from netfilterqueue import NetfilterQueue
import time
from collections import deque, defaultdict, Counter

# global var

class PortScanningDetector:
    def __init__(self, threshold, max_seconds):
        self.threshold = threshold
        self.port_scanning_log = defaultdict(deque)

        self.tcp_flood_log = defaultdict(deque)
        self.udp_flood_log = defaultdict(deque)
        self.icmp_flood_log = defaultdict(deque)
        
        self.m_sec = max_seconds

        # values for testing attacks..
        self.port_scanning_window = 5
        self.port_scanning_threshold = 20

        self.tcp_flood_window = 2
        self.tcp_flood_threshold = 200
        self.tcp_ack_ratio = 0.2

        self.udp_flood_window = 2
        self.udp_flood_threshold = 300

        self.icmp_flood_window = 2
        self.icmp_flood_threshold = 100

    def analyze_tcp(self, src_ip_add, dst_ip_add, timestamp, port_number):
        # return types: (just again for test, maybe optimized later..)
        # 0 => no attack detected
        # 1 => port scanning
        # 2 => tcp flood
        result = self.check_port_scanning(src_ip_add, dst_ip_add, timestamp, port_number)
        if result:
            return 1 # whatever you wanna say about port scanning..
        result = self.check_tcp_flood(dst_ip_add, timestamp, port_number)
        if result:
            return 2 # again whatever you feel about DoS/DDoS attack.
        return 0

    def check_port_scanning(self, src_ip_add, dst_ip_add, timestamp, port_number):
    
        # first let's check the port scanning log:
        if ((src_ip_add, dst_ip_add) not in self.port_scanning_log):
            # now it's the simplest case, just add it to the dictionary:    
            self.port_scanning_log[(src_ip_add, dst_ip_add)].append((timestamp, port_number))

            # and that's it..
            return False
        else:
          
            # now it's the main thing, here we should compare and do the other logic.
            
            history = self.port_scanning_log.get((src_ip_add, dst_ip_add))

            # check if there's already an item there and the difference in time is not big..
            while history and ((timestamp - history[0][0]) > self.port_scanning_window) :
                # just pop up that entry::
                history.popleft()
                
            # let's just append that item..
            history.append((timestamp, port_number))

            # now you have everything fresh, let's go to the next step::
            # 2. now the last and most important thing, let's check if the uniqueue port access is bigger than the threshold::
            active_ports = {item[1] for item in history}
            # I used a set to automatically add only unique items

            #now let's check if the list contains more than 10 items
            if len(active_ports) > self.port_scanning_threshold:
                return True

            return False

    def check_tcp_flood(self, dst_ip_add, timestamp, port_number):

        # first let's check the port scanning log:
        if ((dst_ip_add, port_number) not in self.tcp_flood_log):
            # now it's the simplest case, just add it to the dictionary:    
            self.tcp_flood_log[(dst_ip_add, port_number)].append(timestamp)

            # and that's it..
            return False

        else:
          
            # now it's the main thing, here we should compare and do the other logic.
            
            history = self.tcp_flood_log.get((dst_ip_add, port_number))

            # check if there's already an item there and the difference in time is not big..
            while history and ((timestamp - history[0]) > self.tcp_flood_window) :
                # just pop up that entry::
                history.popleft()
                
            # let's just append that item..
            history.append(timestamp)

            # now you have everything fresh, let's go to the next step::
            # 2. now the last and most important thing, let's check if the uniqueue port access is bigger than the threshold::
            #access_rate = len(history)
            # I used a set to automatically add only unique items

            #now let's check if the list contains more than 10 items
            if len(history) > self.tcp_flood_threshold:
                return True

            return False

    def analyze_udp(self, dst_ip_add, timestamp, port_number):

        # first let's check the port scanning log:
        if ((dst_ip_add, port_number) not in self.udp_flood_log):
            # now it's the simplest case, just add it to the dictionary:    
            self.udp_flood_log[(dst_ip_add, port_number)].append(timestamp)

            # and that's it..
            return False

        else:
          
            # now it's the main thing, here we should compare and do the other logic.
            
            history = self.udp_flood_log.get((dst_ip_add, port_number))

            # check if there's already an item there and the difference in time is not big..
            while history and ((timestamp - history[0]) > self.udp_flood_window) :
                # just pop up that entry::
                history.popleft()
                
            # let's just append that item..
            history.append(timestamp)

            # now you have everything fresh, let's go to the next step::
            # 2. now the last and most important thing, let's check if the uniqueue port access is bigger than the threshold::
            #access_rate = len(history)
            # I used a set to automatically add only unique items

            #now let's check if the list contains more than 10 items
            if len(history) > self.udp_flood_threshold:
                return True

            return False

    def analyze_icmp(self, dst_ip_add, timestamp):
        # first let's check the port scanning log:
        if dst_ip_add not in self.icmp_flood_log:
            # now it's the simplest case, just add it to the dictionary:    
            self.icmp_flood_log[dst_ip_add].append(timestamp)

            # and that's it..
            return False

        else:
          
            # now it's the main thing, here we should compare and do the other logic.
            
            history = self.icmp_flood_log.get(dst_ip_add)

            # check if there's already an item there and the difference in time is not big..
            while history and ((timestamp - history[0]) > self.icmp_flood_window) :
                # just pop up that entry::
                history.popleft()
                
            # let's just append that item..
            history.append(timestamp)

            # now you have everything fresh, let's go to the next step::
            # 2. now the last and most important thing, let's check if the uniqueue port access is bigger than the threshold::
            # access_rate = len(history)
            # I used a set to automatically add only unique items

            #now let's check if the list contains more than 10 items
            if len(history) > self.icmp_flood_threshold:
                return True

            return False


    # def analyze_packet(self, src_ip_add, dst_ip_add, timestamp, port_number):
    #     if (src_ip_add, dst_ip_add) not in self.log:
    #         # now it's the simplest case, just add it to the dictionary:    
    #         self.log[(src_ip_add, dst_ip_add)].append((timestamp, port_number))

    #         # and that's it...
    #         return False

    #     else:
    #         # now it's the main thing, here we should compare and do the other logic.
            
    #         history = self.log.get((src_ip_add, dst_ip_add))

    #         # check if there's already an item there and the difference in time is not big..
    #         while history and ((timestamp - history[0][0]) > self.m_sec) :
    #             # just pop up that entry::
    #             history.popleft()
                
    #         # let's just append that item..
    #         history.append((timestamp, port_number))

    #         # now you have everything fresh, let's go to the next step::
    #         # 2. now the last and most important thing, let's check if the uniqueue port access is bigger than the threshold::
    #         active_ports = {item[1] for item in history}
    #         # I used a set to automatically add only unique items

    #         #now let's check if the list contains more than 10 items
    #         if len(active_ports) > self.threshold:
    #             return True

    #         return False




            


