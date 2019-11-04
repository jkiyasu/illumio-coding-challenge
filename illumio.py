import pandas as pd
import heapq

class Firewall:
    ### "filepath" is filepath to csv
    
    def __init__(self, filepath):
        """creates firewall object based on csv of rules"""
        rules = pd.read_csv(filepath, names=["direction", "protocol", "port_r", "ip_address_r"])
        #pre-filter into 4 categories so don't have to repeatedly filter 
        self.in_tcp = rules[(rules["direction"]=='inbound') & (rules["protocol"]=="tcp")]
        self.out_tcp = rules[(rules["direction"]=='outbound') & (rules["protocol"]=="tcp")]
        self.in_udp = rules[(rules["direction"]=='inbound') & (rules["protocol"]=="udp")]
        self.out_udp = rules[(rules["direction"]=='outbound') & (rules["protocol"]=="udp")]
        self.dir_pro_map = {"inbound": {"tcp": self.in_tcp, "udp": self.in_udp}, "outbound": {"tcp": self.out_tcp, "udp": self.out_udp}}
        ### think of alternative, may try to merge overlapping rules later

    def accept_packet(self, direction, protocol, port, ip_address):
        """returns boolean based on 
        - direction (string): “inbound” or “outbound”
        - protocol (string): exactly one of “tcp” or “udp”, all lowercase
        - port (integer) – an integer in the range [1, 65535]
        - ip_address (string): a single well-formed IPv4 address."""

        rules = self.dir_pro_map[direction][protocol] 
        for row in rules.head().itertuples():
            rule_port, rule_ip = row.port_r, row.ip_address_r
            rule_port_r, rule_ip_r = to_range_port(rule_port), to_range_ip(rule_ip)
            if in_range_port(port, rule_port_r) and in_range_ip(ip_address, rule_ip_r):
                return True
        return False

class Rule:
    def __init__(self, direction, protocol, port_r, ip_address_r):
        """ Standardize port and ip_address to all be ranges"""
        self.direction = direction
        self.protocol = protocol
        self.port_r = port_r #list containing start and end (inclusive)
        self.ip_address_r = ip_address_r #list containing start and end (inclusive)

### helper functions ###

def in_range_port(value, r): 
    if value >= r[0] and value <= r[1]:
        return True
    else:
        return False

def in_range_ip(value, r):
    #convert ip to list in order to compare properly
    value_ip = list(map(int, value.split('.')))
    start_ip = list(map(int, r[0].split('.')))
    end_ip = list(map(int, r[1].split('.')))
    if value_ip >= start_ip and value_ip <= end_ip:
        return True
    else:
        return False

def to_range_port(port):
        """converts input to range if it isn't already, 
        returns list of start and end (inclusive)"""
        if "-" in port:
            port_r = port.split("-")
            port_r[0] = int(port_r[0])
            port_r[1] = int(port_r[1])
        else:
            port_r = [int(port), int(port)]
        return port_r

def to_range_ip(ip):
    if "-" in ip:
        ip_r = ip.split("-")
    else:
        ip_r = [ip, ip]
    return ip_r

#merge intervals code taken from my previous interview practice
def merge_intervals(arr):
    list_of_intervals = []
    heap = arr.deepcopy()
    heapq.heapify(heap)
    if len(heap) == 0:
        return []
    first_elem = heapq.heappop(heap)
    while len(heap) > 0:
        second_elem = heapq.heappop(heap)
        if first_elem[1] >= second_elem[0]:
            second_elem = [first_elem[0], second_elem[1]]
        else:
            list_of_intervals.append(first_elem)
        first_elem = second_elem
    list_of_intervals.append(first_elem)
    return list_of_intervals

fw = Firewall("fw.csv")
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) # matches first rule
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) # matches third rule
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")) # false
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92")) # false