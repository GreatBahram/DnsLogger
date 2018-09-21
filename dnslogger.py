#!/usr/bin/env python3
'''This code captures whole information about DNS packets.
'''
# Standard library imports
import json
import socket
import sys
import time
from datetime import datetime
from struct import unpack

# save each flow in this file.
FLOW_FILE = "myflow.log"
# Header Len
ETH_HDR_LEN = 14
ARP_HDR_LEN = 28
IPv4_HDR_LEN = 20
IPv6_HDR_LEN = 40
TCP_HDR_LEN = 20
UDP_HDR_LEN = 8

###
# Specific to Ethernet Packets
ETH_UNPACK_PATTERN = '!6s6sH'
ETH_TYPE_POS = 2

# Packet Type
IPv4_ID = 8            # IPv4 Packet
###
# Specific to IPv4 Packets
IPv4_UNPACK_PATTERN = '!BBHHHBBH4s4s'
IPv4_PROTOCOL_POS = 6  # Where the protocol info is stored
IPv4_SRC_ADDR_POS = 8  # Where the source address is stored
IPv4_DEST_ADDR_POS = 9  # Where the dest address is stored
IPv4_ICMP_PROTO = 1    # ICMP Protocol
IPv4_TCP_PROTO = 6     # TCP Protocol
IPv4_UDP_PROTO = 17    # UDP Protocol

# Specific to UDP Packets
UDP_UNPACK_PATTERN = '!HHHH'
UDP_SRC_PORT_POS = 0  # Where the source port is stored
UDP_DEST_PORT_POS = 1  # Where the destination port is stored
UDP_DATA_LEN = 2

# Ports of interest
DNS_PORT = "53"

# Values of interest in DNS packet
DNS_RESP = ("0x8180", "0x8190")   # Standard Query Response, No Error
DNS_RESP_NE = "0x8182"   # Resource Record doesn't exist
DNS_NXDOMAIN = "0x8183"   # Domain doesn't exist.
DNS_REQ = ("0x0100", "0x100", "0x0120", "0x120", "0x110", "0x0110")    # Standard Query Request, No Error

# Specific to DNS packet
DNS_UNPACK_PATTERN = '!HHHHHH'
DNS_HDR_LEN = 12
DNS_ANS_UNPACK_PATTERN = '!HHHIH'
DNS_ANS_HDR_LEN = 12
DNS_IPv4_UNPACK_PATTERN = '!4s'
DNS_IPv4_SIZE = 4  # 4 Bytes to store an IP
DNS_FLAGS_POS = 1
DNS_NUM_REQ_POS = 2
DNS_NUM_ANS_POS = 3  # Answer RRs
DNS_NUM_AUTH_POS = 4 # Authority RRs
DNS_NUM_ADD_POS = 5  # Additional RRs 
DNS_ANS_TYPE_POS = 1
DNS_ANS_CLASS_POS = 2
DNS_QUERY_TYPE_POS = 0
DNS_QUERY_CLASS_POS = 1

# Record Resource Common
DNS_A_TYPE = "1"      # IP Address
DNS_NS_TYPE = "2"     # Name Server
DNS_CNAME_TYPE = "5"  # Canonical name
DNS_SOA_TYPE = "6"    # Start of authority
DNS_MX_TYPE = "15"    # Mail Server
DNS_TXT_TYPE = "16"   # Description About this Record
DNS_AAAA_TYPE = "28"  # IPv6 Address
#
# Record Resource Uncommon
DNS_RRSIG_TYPE = "46"   # Signature
DNS_DNSKEY_TYPE = "48"  # DNS Key
DNS_ANY_TYPE = "255"    # Any information

# Human Readable Record Resource
dnstypes = { 0:"ANY", 255:"ALL", 1:"A", 2:"NS", 3:"MD", 4:"MF", 5:"CNAME",
             6:"SOA", 7: "MB", 8:"MG", 9:"MR",10:"NULL",11:"WKS",12:"PTR",
             13:"HINFO",14:"MINFO",15:"MX", 16:"TXT", 17:"RP",18:"AFSDB",
             28:"AAAA", 29:"LOC", 33:"SRV", 35:"NAPTR", 38:"A6",39:"DNAME",
             41:"OPT", 43:"DS", 46:"RRSIG", 47:"NSEC", 48:"DNSKEY", 50: "NSEC3",
             51: "NSEC3PARAM", 32769:"DLV", 44:"SSHFP", 52:"TLSA"}
Record_Resource = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "46": "RRSIG",
    "48": "DNSKEY",
    "255": "ANY"
}

DNS_CLASS = "1"        # Internet Address
DNS_NAME_END = 0       # Default end value for names
DNS_PTR_END = 192      # Default end value for PTR types used in names

# Do not Record anything about this IP Addresses
g_disallowed_ip = ("127.0.0.1", )


class Stack:
    '''This class define concept of Stack in python by using list datatype.
    '''
    def __init__(self):
        self.items = []

    def peek(self):
        return len(self.items)-1

    def remove(self, index):
        self.items.remove(self.items[index])
        return True

    def size(self):
        return len(self.items)

    def isempty(self):
        return self.items == []

    def push(self, ID, length, time, rr, url):
        self.items.append([ID, length, time, rr, url])
        return True

    def search(self, item):
        for row in self.items:
            if item in row[0]:
                shomare = self.items.index(row)
                return self.items.pop(shomare)

        return ''


def save_json(mydic):
    ''' takes a dictionary and save it as a json file.
    Key agruments:
        mydic -- dictionary data type that will be return as string
    '''
    return json.dumps(mydic)

# test fucn
def decode_name_from_dns_packet(start_pos, packet, isPtr=False):
    name = ""

    # As part of message compression, pointers are used to reference
    # to part of the previously filled domain name. These are used
    # only in the response section. So, if Query is sent for:
    # www.github.com and the CNAME is github.com the a pointer is
    # used inside the RR section to point the part of the packet
    # where 'github.com' already appears. Now in these scenarios
    # the end of name is, necesarily, 'zero' but '0xC0' (i.e. 192)
    prev_pos = start_pos
    (next_len,) = unpack('!B', packet[prev_pos:prev_pos + 1])
    prev_pos += 1
    while ((next_len != DNS_NAME_END) and (next_len != DNS_PTR_END)):
        if name:
            name += "."
        name += packet[prev_pos:prev_pos + next_len].decode('utf-8')
        prev_pos += next_len
        (next_len,) = unpack('!B', packet[prev_pos:prev_pos + 1])
        prev_pos += 1

    # if a PTR was used the increment by one because a pointer is
    # of 16-bit in length (i.e., 2 Bytes).
    if (next_len == DNS_PTR_END):
        prev_pos += 1
    return name, prev_pos


def dump_packet_info(packet):
    '''Extract all important information about IPv4 packet like source address
    destination address, source and destination port and finally size of data
    Keyword agruments:
        packet -- packet is packet that caputerd by socket module.
    Returns:
        It will return source and destination IP and port, size of payload.
    '''
    eth_header = packet[:ETH_HDR_LEN]
    eth = unpack(ETH_UNPACK_PATTERN, eth_header)
    eth_protocol = socket.ntohs(eth[2])
    if eth_protocol == IPv4_ID:
        flag = retrieve_ipv4_packet_info(packet)
        if flag:
            s_addr, src_port, d_addr, dst_port, data_size =\
                    retrieve_ipv4_packet_info(packet)
            return s_addr, src_port, d_addr, dst_port, data_size
    return False


def retrieve_ipv4_packet_info(packet):
    ''' Gather all information from different functions 
    '''
    ip_header = unpack(IPv4_UNPACK_PATTERN,
                       packet[ETH_HDR_LEN: IPv4_HDR_LEN + ETH_HDR_LEN])
    protocol = ip_header[IPv4_PROTOCOL_POS]
    s_addr = socket.inet_ntoa(ip_header[IPv4_SRC_ADDR_POS]);
    d_addr = socket.inet_ntoa(ip_header[IPv4_DEST_ADDR_POS]);
    if protocol == IPv4_UDP_PROTO:
        flag_udp = retrieve_udp_packet_info(packet)
        if flag_udp:
            src_port, dst_port, data_size = flag_udp
            return s_addr, src_port, d_addr, dst_port, data_size
    return False


def retrieve_udp_packet_info(packet):
    '''This function provides all information about DNS UDP packets

    Key arguments:
        packet -- get packet from socket.socket
    
    Returns:
        if packet is DNS packet -- it provilde src and dst port + data size
        if it's not -- just return False
    '''
    start_pos = ETH_HDR_LEN + IPv4_HDR_LEN
    udp_header = unpack(UDP_UNPACK_PATTERN,
                        packet[start_pos: start_pos + UDP_HDR_LEN])
    src_port = str(udp_header[UDP_SRC_PORT_POS])
    dst_port = str(udp_header[UDP_DEST_PORT_POS])
    length = udp_header[2]
    h_size = ETH_HDR_LEN + IPv4_HDR_LEN + UDP_HDR_LEN
    #data_size = len(packet) - h_size
    data_size = length - UDP_HDR_LEN
# DATA
    data = packet[h_size:]
    if src_port == '53' or dst_port == '53':
        return src_port, dst_port, data_size
    return False


def parse_dns(packet):
    start_pos = ETH_HDR_LEN + IPv4_HDR_LEN + UDP_HDR_LEN
    end_pos = start_pos + DNS_HDR_LEN
    dns_header = unpack(DNS_UNPACK_PATTERN, packet[start_pos:end_pos])
    flag = str(hex(dns_header[DNS_FLAGS_POS]))

    if flag in DNS_REQ:
        number_of_question = int(dns_header[DNS_NUM_REQ_POS])
        url, next_pos = decode_name_from_dns_packet(end_pos, packet)  # what is the request
        request_pos = next_pos + 4  # '4' bytes for "DNS Type" & "DNS Class"data
        rr_type, dns_class = unpack('!HH', packet[next_pos:request_pos])  # what type of record and determine DNS class
        return rr_type, "REQ"

    elif flag in DNS_RESP:
        number_of_answers = int(dns_header[DNS_NUM_ANS_POS])
        number_of_authority = int(dns_header[DNS_NUM_AUTH_POS])
        number_of_additional = int(dns_header[DNS_NUM_ADD_POS])
        url, next_pos = decode_name_from_dns_packet(end_pos, packet)  # what is the request
        answer_pos = next_pos + 4  # '4' bytes for "DNS Type" & "DNS Class" data
        rr_type, dns_class = unpack('!HH', packet[next_pos:answer_pos])  # what type of record and determine DNS class
        '''
        this condition is the main condition. it return 5 items. each of them is so important. 
        First one is the resource record typen and second is response function flag.
        Third one is the number of answer that server returns to our dns cache, next is number 
        of authority and the last one is number of additional resource record
        '''
        return rr_type, "RESP", number_of_answers, number_of_authority, number_of_additional

    elif flag == DNS_RESP_NE:
        number_of_answers = int(dns_header[DNS_NUM_ANS_POS])
        url, next_pos = decode_name_from_dns_packet(end_pos, packet)  # what is the request
        answer_pos = next_pos + 4  # '4' bytes for "DNS Type" & "DNS Class" data
        rr_type, dns_class = unpack('!HH', packet[next_pos:answer_pos])  # what type of record and determine DNS class
        return rr_type, "RESP_NE"

    elif flag == DNS_NXDOMAIN:
        number_of_answers = int(dns_header[DNS_NUM_ANS_POS])
        url, next_pos = decode_name_from_dns_packet(end_pos, packet)  # what is the request
        answer_pos = next_pos + 4  # '4' bytes for "DNS Type" & "DNS Class" data
        rr_type, dns_class = unpack('!HH', packet[next_pos:answer_pos])  # what type of record and determine DNS class
        return "%s" % (rr_type), "RESP_NX"

    else:
        number_of_answers = int(dns_header[DNS_NUM_ANS_POS])
        url, next_pos = decode_name_from_dns_packet(end_pos, packet)  # what is the request
        answer_pos = next_pos + 4  # '4' bytes for "DNS Type" & "DNS Class" data
        rr_type, dns_class = unpack('!HH', packet[next_pos:answer_pos])  # what type of record and determine DNS class
        return "%s" % (rr_type), "Unknown %s" % (flag)

def main():
    myip = ("192.168.56.101", "192.168.20.1", "172.17.2.11")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print('Please Run with Sudo.')
        sys.exit(2)
    stack = Stack()

    while True:
# We have to save our log into standard format that can be use for future purpose
        request_dic = {
                'timestamp': '',
                'type': 'request',
                'request-size': '',
                'resource-record':'',
                'src-ip': '',
                'src-port': '',
                'url': '',
                }

        response_dic = {
                'type': 'response',
                'timestamp': '',
                'dst-ip': '',
                'dst-port': '',
                'response-size': '',
                'response-flag': '',
                'Answer-RRs': '',
                'Authority-RRs': '',
                'Additional-RRs' : '', 
                }
        try:
            packet = s.recvfrom(65565)
# Parse IP header
            packet, address = packet
            timestamp = time.time()
            result = dump_packet_info(packet)
            now = datetime.now()
            #timestamp = str(now.strftime('%d-%b-%y %H:%M:%S.%f'))
            result = dump_packet_info(packet)
            if result:
                s_addr, src_port, d_addr, dst_port, data_size = result
                if s_addr in g_disallowed_ip or d_addr in g_disallowed_ip:
                    continue
                answers =  authorities = additionals = '0'
                try:
                    # for reuqest and reponse that encounter an error 
                    rr_type, poquest = parse_dns(packet)  # get RR and request or response
                except ValueError:
                    # for valid response return especial return 
                    rr_type, poquest , answers, authorities, additionals = parse_dns(packet)

                if d_addr in  myip and poquest == 'REQ':
                    start_pos = ETH_HDR_LEN + IPv4_HDR_LEN + UDP_HDR_LEN
                    end_pos = start_pos + DNS_HDR_LEN
                    url = decode_name_from_dns_packet(end_pos, packet)[0] # url address
                    stack.push('{0}#{1}'.format(s_addr, src_port), '{0}'.format\
                                (data_size), '{0}'.format(timestamp), "{0}".format(rr_type), "{0}".format(url))

                if d_addr != myip and poquest != 'REQ':
                    hasel = stack.search('{0}#{1}'.format(d_addr, dst_port))
                    # save to flow file
                    if hasel != '':
# make request dicionary format
                        request_dic['timestamp'] = hasel[2] 
                        request_dic['request-size'] = hasel[1] 
                        request_dic['resource-record'] =  hasel[3]
                        request_dic['src-ip'] = hasel[0].split('#')[0]
                        request_dic['src-port'] = hasel[0].split('#')[1]
                        request_dic['url'] =  hasel[4]
                        print(request_dic)
                        part1 = save_json(request_dic)
# make request dicionary format
                        response_dic['timestamp'] = timestamp
                        response_dic['dst-ip'] = d_addr
                        response_dic['dst-port'] = dst_port
                        response_dic['response-size'] = data_size
                        response_dic['response-flag'] = poquest
                        response_dic['Answer-RRs'] = answers 
                        response_dic['Authority-RRs'] = authorities 
                        response_dic['Additional-RRs'] = additionals
                        print(response_dic)
                        part2 = save_json(response_dic)

                        with open(FLOW_FILE, mode='a', encoding='utf-8') as fp:
                            fp.write(part1 + ' + ' + part2)
                            fp.write('\n')

        except KeyboardInterrupt:
            print('Break by user.')
            sys.exit(1)

if __name__ == '__main__':
    main()
