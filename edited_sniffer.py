import socket
from general import *
from datetime import date

from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

from excel.report import Report

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def resolveName(ip):
    data = socket.gethostbyaddr(ip)
    host = repr(data[0])
    return host


def main():
    report = Report()
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:

        #check if date passes
        if report.current_date != date.today().strftime("%d_%m_%Y"):
            #create new report
            report = Report()
            print ("New Date")

        raw_data, addr = conn.recvfrom(65535)
        eth = Ethernet(raw_data)
        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                if len(tcp.data) > 0:

                    # HTTP
                    if  (tcp.src_port == 80 or tcp.dest_port == 80 or tcp.dest_port == 443 or tcp.src_port == 443) :
                        print('HTTP Data:')
                        #print(TAB_2 + 'Flags:')
                        #print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                        #print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:

                                #print(DATA_TAB_3 + str(line))

                                #resolve ip addresses to hosts
                                #resolvedSrc = resolveName(ipv4.src)
                                #resolvedDest = esolveName(ipv4.target)

                                #print Log
                                print(DATA_TAB_1 + "Source IP:")
                                print(DATA_TAB_2 + ipv4.src)
                                #print(DATA_TAB_2 + resolvedSrc)

                                print(DATA_TAB_1 + "Destination IP:")
                                print(DATA_TAB_2 + ipv4.target)
                                #print(DATA_TAB_2 + resolvedDest)

                                # add line to report
                                report.add_row(ipv4.src,ipv4.target)

                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))


main()
