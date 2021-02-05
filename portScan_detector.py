import dpkt
import sys
import subprocess
import platform
import socket
import binascii
# Create an empty list
my_list = []  # List to Store TCP PACKETS
ip_list = list()  # List to store IPS
scans_list = []


def check_flags(flags):
    fin_flag = (flags & dpkt.tcp.TH_FIN ) != 0  # end of data
    syn_flag = (flags & dpkt.tcp.TH_SYN ) != 0  # SYN flag
    rst_flag = (flags & dpkt.tcp.TH_RST ) != 0  # Reset flag
    psh_flag = (flags & dpkt.tcp.TH_PUSH) != 0  # Push flag
    ack_flag = (flags & dpkt.tcp.TH_ACK ) != 0  # Acknowledgment number
    urg_flag = (flags & dpkt.tcp.TH_URG ) != 0  # Urgent pointer
    ece_flag = (flags & dpkt.tcp.TH_ECE ) != 0
    cwr_flag = (flags & dpkt.tcp.TH_CWR ) != 0  # Congestion windows reduced
    toReturn = ""
    if syn_flag and not (ack_flag or fin_flag or rst_flag or psh_flag or urg_flag or ece_flag or cwr_flag):
        # TCP SYN PING
        toReturn = "TCP SYN SCAN"
    elif not (syn_flag or fin_flag or rst_flag or psh_flag or urg_flag or ece_flag or cwr_flag) and ack_flag:
        # TCP ACK Ping
        toReturn = "TCP ACK SCAN"
    elif fin_flag and psh_flag and urg_flag:
        # XMAS scan
        toReturn = "TCP XMAS SCAN"
    elif fin_flag and not syn_flag and not ack_flag and not psh_flag and not urg_flag:
        # TCP FIN Scan
        toReturn = "TCP FIN SCAN"
    elif not(fin_flag or syn_flag or ack_flag or psh_flag or rst_flag or psh_flag or urg_flag or ece_flag or cwr_flag):
        # TCP NULL Scan
        toReturn = "TCP NULL SCAN"
    elif not (syn_flag or rst_flag or psh_flag or urg_flag or ece_flag or cwr_flag) and ack_flag and fin_flag:
        toReturn = "TCP MAIMON SCAN"
    return toReturn


def tcpFlags(tcp):
    """Returns a list of the set flags in this TCP packet."""
    ret = []

    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        ret.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN  != 0:
        ret.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST  != 0:
        ret.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        ret.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK  != 0:
        ret.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG  != 0:
        ret.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE  != 0:
        ret.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR  != 0:
        ret.append('CWR')

    return ret


def check_list(tcp):
    if len(my_list) == 0:
        my_list.append([tcp])
        return False

    # Check all values in list:
    for i in range(0, len(my_list)):
        # Check if it's the same attack, an answer or a diff attack
        if tcp.sport == my_list[i][0].sport and tcp.dport == my_list[i][0].dport:
            flags = list()
            for z in range (0, len(my_list[i])): # Obtain Flags of the TCP Packets in this position
                flags = flags + tcpFlags(my_list[i][z])
            # Obtain info about the incoming tcp packet

            # Case 1: it's the second packet in TCP SYN Scan
            if {'SYN'} == set(flags) and {'RST'} == set(tcpFlags(tcp)):  # Answer in tcp SYN scan
                my_list[i].append(tcp)
                return True

            if tcp.seq > my_list[i][len(my_list[i])-1].seq:  # Case 2: It's a real communication
                my_list[i].append(tcp)
                return True

            if flags == tcpFlags(tcp):  # Case 3: it's same scan from same source port and same target port
                my_list.append([tcp])
                return  False

    # Once we checked all values and it doesn't exist we add it
    my_list.append([tcp])
    return False


def add_colons_to_mac(mac_addr):
    s = list()
    for i in range(0, 6):
        s.append(mac_addr[i*2:i*2+2].decode())
    r = ":".join(s)
    return r


def arp_packet(info):
    # Obtain info inside arp packet
    print("\tsource protocol address", socket.inet_ntoa(info.spa))
    print("\tsource hardware address", add_colons_to_mac(binascii.hexlify(info.sha)))
    print("\tTarget protocol address", socket.inet_ntoa(info.tpa))
    print("\tTarget hardware address", add_colons_to_mac(binascii.hexlify(info.tha)))


def icmp_scan(ip):
    print("\tSource ip: ", socket.inet_ntoa(ip.src))
    print("\tTarget ip: ", socket.inet_ntoa(ip.dst))
    icmp = ip.data
    # Destination reachable
    if icmp.type == 0:
        print("\tICMP: REPLY")
    elif icmp.type == 8:
        print("\tICMP: REQUEST")
    elif icmp.type == 3:
        print("\tICMP: DESTINATION UNREACHABLE")


def tcp_scan(ip):
    """
   Discovery options:
    - TCP SYN ping: sends and empty TCP Packet with SYN flag set.
    - TCP ACK Ping: similar to SYN ping. TCP ACK flag is set not SYN flag.
    - TCP XMAS Scan: flags set -> FIN, PUSH, URGENT
    - TCP FIN Scan: flag set -> FIN
    - TCP NULL Scan: flag set -> no-one
   """
    tcp = ip.data
    if socket.inet_ntoa(ip.src) != ip_source:
        return
    if not check_list(tcp):  # Check if it is an answer to a previous TCP packet
        ip_list.append(ip)  # If its not add ip info to list


def udp_scan(ip):
    udp = ip.data
    if socket.inet_ntoa(ip.src) != ip_source:
        return
    my_list.append(udp)
    ip_list.append(ip)


def print_ip(pos):
    if pos > len(ip_list):
        print_ip("IMPOSSIBLE POSITION")
        return
    source_ip = socket.inet_ntoa(ip_list[pos].src)
    target_ip = socket.inet_ntoa(ip_list[pos].dst)
    tcp = ip_list[pos].data
    source_port = tcp.sport
    target_port = tcp.dport
    print(source_ip,"->",target_ip,": ", source_port, "->", target_port, end=" ")


def add_scan(type):
    added = False
    if len(scans_list) == 0:
        scans_list.append([type])
    else:
        for i in range (0, len(scans_list)):
            if type is scans_list[i][0]: # Same kind of scan
                scans_list[i].append(type)
                added = True
        if not added:
            scans_list.append([type])


def obtain_info():
    scans = 0

    for i in range(0, len(my_list)):
        if 0 < len(my_list[i]) <= 2:  # SEND MAX " TCP PACKETS IN TCP SCAN
            scanType = check_flags(my_list[i][0].flags)
            if scanType:
                if "-vv" in sys.argv:
                    print_ip(i)
                    print("\t",scanType)
                add_scan(scanType)
                scans += 1

        elif ip_list[i].p == 17:  # It's an UDP Packet
            if "-vv" in sys.argv:
                print_ip(i)
                print("\t\tUDP SCAN")
            add_scan("UDP SCAN")
            scans += 1
    if scans > 0:
        print("DETECTED", scans, "POSSIBLES SCANS!")
        for i in range(0, len(scans_list)):
            print("DETECTED", len(scans_list[i]), scans_list[i][0])
    else:
        print("NO SCANS DETECTED! YOU ARE SAFE!")


def main():
    # Opening file
    f = open(sys.argv[1], 'rb')
    print("_"*15, "PORT SCAN DETECTOR", "_"*15)
    pcap = dpkt.pcap.Reader(f)
    global ip_source
    ip_set = False
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # print("IP PROTOCOL")
            # Now we must get what kind of scan did
            ip = eth.data
            if not ip_set:
                ip_source = "192.168.5.15"
                ip_set = True
                # print("SOURCE IP =", ip_source)
            # First one ping scan:
            if ip.p == dpkt.ip.IP_PROTO_ICMP:
                continue
                print("\tICMP SCAN")
                # icmp_scan(ip)
            elif ip.p == dpkt.ip.IP_PROTO_TCP:
                # print("\tTCP SCAN")
                tcp_scan(ip)
            elif ip.p == 17:
                udp_scan(ip)

        elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            # NMAP begins a scan with arp ping!
            continue
            arp_packet(eth.arp)

    f.close()


if __name__ == '__main__':
    # Check params length
    if len(sys.argv) < 2:
        sys.exit("Check your parameters: 1: file.exe 2: file.pcap")

    # Begin cleaning the console
    if platform.system() == "Linux":
        subprocess.run("clear", shell=True)
    else:
        subprocess.run("cls", shell=True)
    main()
    # Check info in list
    obtain_info()


