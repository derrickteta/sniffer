#!/usr/bin/python3.4
# -*-coding:Utf-8 -*
#import os # On importe le module os



import socket
import struct
import textwrap
import datetime
from time import strftime


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1= '\t '
DATA_TAB_2= '\t\t '
DATA_TAB_3= '\t\t\t '
DATA_TAB_4= '\t\t\t\t '
ip_address="192.168.43.150"
chemin="/home/derrick/Documents/rapport.txt"
def main():
    conn=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ligne=1
    tmp={}
    lignestr=str(ligne)
    savefile= open(chemin, "a")
    print('*************************Enregistrement dans le fichier***********************')
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data  =ethernet_frame(raw_data)
        tailleint= len(raw_data)
        taille = str(tailleint)
        now = datetime.datetime.now()
        tps=now.strftime("%H:%M:%S %d/%m/%Y")
        
        #8 for IPV4
        if eth_proto == 8:
            (version, header_lenght,ttl, proto, src, target, data) = ipv4_packet(data)
            
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
            #TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,flag_fin, data ) = tcp_segment(data)
            #UDP
            elif proto == 17:
                src_port , dest_port, length, data =udp_segment(data)
        if target != ip_address:
            lignestr=str(ligne)
            src_portstr=str(src_port)
            savefile.write("\n "+lignestr+"-) IP machine: "+src+":\n"
                           +DATA_TAB_2+ "  port:"+src_portstr+"  taille:"+taille+" Octect temps:"+tps+" \n")       
            tmp={target:"-) IP machine: "+src+":\n"
                           +DATA_TAB_2+ "  port:"+src_portstr}
            ligne=ligne+1
        else:
            for srctmp, srcinfo in tmp.items():
                if src==srctmp:
                    lignestr=str(ligne) 
                    savefile.write("\n "+lignestr+tmp[src]+"  taille:"+taille+" Octect temps:"+tps+" \n")
                    ligne=ligne+1
            
    savefile.close()
#unapack ethernet frame 
def ethernet_frame(data):
    dest_mac,src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac),socket.htons(proto), data[14:]


#return properly formatted mac address (ie AA:BB:CC:DD:EE:)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#unpack IPV4 packet
def ipv4_packet(data):
    version_header_length=data[0]
    version = version_header_length >> 4 
    header_length = (version_header_length & 15) * 4
    ttl , proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, header_length, ttl , proto, ipv4(src), ipv4(target),data[header_length:] 
    
#return properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str,addr))

#unpacks ICMP packet
def icmp_packet(data):
    icmp_type , code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpacks tcp
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
    offset= (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst= (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,flag_fin, data[offset:]
    

#unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data [8:]

#Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -=len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



main() 
#os.system("pause")