from scapy.all import *

import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString
yaml = ruamel.yaml.YAML()

llc_sap = {
    "00": "Null SAP",
    "02": "LLC Sublayer Management / Individual",
    "03": "LLC Sublayer Management / Group",
    "06": "IP (DoD internet Protocol)",
    "de": "PROWAY",
    "42": "STP",
    "4e": "MMS",
    "5e": "ISI IP",
    "7e": "X.25 PLP",
    "8e": "PROWAY Active station list maintenance",
    "aa": "SNAP",
    "e0": "IPX",
    "f4": "LAN Management",
    "fe": "ISO Network Layer Protocols",
    "ff": "Global DSAP",
    "f0": "NETBIOS"
}

# TODO task 2 part 2 -> ethertype, protocol, number of ports for transporting protocols must be from external txt file!
EtherType = {
    # "0200": "XEROX PUP",
    # "0201": "PUP Addr Trans",
    # "2000": "CDP",
    # "0800": "Internet IP (IPv4)",
    # "0801": "X.75 Internet",
    # "0805": "X.25 Level 3",
    # "0806": "ARP",
    # "8035": "Reverse ARP",
    # "809b": "AppleTalk",
    # "80f3": "AppleTalk AARP (Kinetics)",
    # "8100": "IEEE 802.1Q VLAN-tagged frames",
    # "8137": "Novel IPX",
    # "86dd": "IPv6",
    # "880b": "PPP",
    # "8847": "MPLS",
    # "88cc": "LLDP",
    # "8848": "MPLS with-assigned label",
    # "8863": "PPPoE Discovery stage",
    # "8864": "PPoE Session Stage",
    # "9000": "Loopback"
}

ip_protocols = {
    # 1: "ICMP",
    # 2: "IGMP",
    # 6: "TCP",
    # 9: "IGRP",
    # 17: "UDP",
    # 47: "GRE",
    # 50: "ESP",
    # 51: "AH",
    # 57: "SKIP",
    # 88: "EIGRP",
    # 89: "OSPF",
    # 115: "L2TP"
}

#list of lists (ip and amount of repetitions)
sender_ip_addresses = []
sender_ip_pakets_amount = []

def display_info(order, paket, frame_type, all_data):
    hexa_frame_output = ''

    # formatted hex output
    hex_pairs = [paket[i:i + 2] for i in range(0, len(paket), 2)]
    formatted_hex = ' '.join(hex_pairs)

    # mac's
    receiver_mac = ':'.join(paket[i:i + 2] for i in range(0, 12, 2))
    sender_mac = ':'.join(paket[i:i + 2] for i in range(12, 24, 2))



    # print("frame_number: ", str(order + 1))
    # print("len_frame_pcap: ", str(int(len(paket) / 2)))
    # print("len_frame_medium: ", str(int((len(paket) / 2) + 4)))
    # print("frame_type: ", frame_type)
    # print("Mac address reciever: ", receiver_mac)
    # print("Mac address sender: ", sender_mac)

    # print("hexa_frame: |")
    for i in range(0, len(formatted_hex), 48):
        # print(formatted_hex[i:i + 48].upper().strip())
        # hexa_frame_output += '   ' + formatted_hex[i:i + 48] + '\n'
        hexa_frame_output += (formatted_hex[i:i + 48].upper().strip() + '\n')

    # TODO: llc snap nad llc to 1 condition!
    if frame_type == "IEEE 802.3 LLC & SNAP":
        pid_or_sap = 'pid'
        pid_or_sap_output = detect_ether_type(paket[40:44])
        data = {
            'frame_number': (order + 1),
            'len_frame_pcap': (int(len(paket) / 2)),
            'len_frame_medium': (int((len(paket) / 2) + 4)),
            'frame_type': frame_type,
            'src_mac': sender_mac.upper(),
            'dst_mac': receiver_mac.upper(),
            pid_or_sap: pid_or_sap_output,
            'hexa_frame': LiteralScalarString(hexa_frame_output)
        }
        # print("PID: ", detect_ether_type(paket[40:44]))
    elif frame_type == "IEEE 802.3 LLC":
        pid_or_sap = 'sap'
        pid_or_sap_output = detect_llc_sap(paket[30:32])
        data = {
            'frame_number': (order + 1),
            'len_frame_pcap': (int(len(paket) / 2)),
            'len_frame_medium': (int((len(paket) / 2) + 4)),
            'frame_type': frame_type,
            'src_mac': sender_mac.upper(),
            'dst_mac': receiver_mac.upper(),
            pid_or_sap: pid_or_sap_output,
            'hexa_frame': LiteralScalarString(hexa_frame_output)
        }
    elif frame_type == "ETHERNET II":
        ether_type = detect_ether_type(paket[24:28])
        # TODO add dist and src ip address
        if detect_ether_type(paket[24:28]) == "Internet IP (IPv4)":

            src_ip = '.'.join(str(int(paket[i:i + 2], 16)) for i in range(52, 60, 2))
            dst_ip = '.'.join(str(int(paket[i:i + 2], 16)) for i in range(60, 67, 2))

            if detect_ip_protocol(paket[46:48]) == "TCP" or detect_ip_protocol(paket[46:48]) == "UDP":
                # calculating offset
                if paket[29:30] == 1:
                    ihl = paket[29:31]
                else:
                    ihl = paket[29:30]
                offset = int(int(ihl) * 32 / 8 * 2)

                src_port = int(paket[28+offset:28+offset+4], 16)
                dst_port = int(paket[32+offset:32+offset+4], 16)

                # for IPV4 WITH TCP or UDP protocol
                data = {
                    'frame_number': (order + 1),
                    'len_frame_pcap': (int(len(paket) / 2)),
                    'len_frame_medium': (int((len(paket) / 2) + 4)),
                    'frame_type': frame_type,
                    'src_mac': sender_mac.upper(),
                    'dst_mac': receiver_mac.upper(),
                    'ether_type:': ether_type,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': detect_ip_protocol(paket[46:48]),
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'hexa_frame': LiteralScalarString(hexa_frame_output)
                }
            else:
                # for IPV4 WITHOUT TCP or UDP protocol
                data = {
                    'frame_number': (order + 1),
                    'len_frame_pcap': (int(len(paket) / 2)),
                    'len_frame_medium': (int((len(paket) / 2) + 4)),
                    'frame_type': frame_type,
                    'src_mac': sender_mac.upper(),
                    'dst_mac': receiver_mac.upper(),
                    'ether_type:': ether_type,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': detect_ip_protocol(paket[46:48]),
                    'hexa_frame': LiteralScalarString(hexa_frame_output)
                }
            if src_ip not in sender_ip_addresses:
                sender_ip_addresses.append(src_ip)
                sender_ip_pakets_amount.append(1)
            else:
                sender_ip_pakets_amount[sender_ip_addresses.index(src_ip)] += 1

        else:
            # NOT PRINTING PROTOCOL FOR NOT IPV4
            data = {
                'frame_number': (order + 1),
                'len_frame_pcap': (int(len(paket) / 2)),
                'len_frame_medium': (int((len(paket) / 2) + 4)),
                'frame_type': frame_type,
                'src_mac': sender_mac.upper(),
                'dst_mac': receiver_mac.upper(),
                'ether_type:': ether_type,
                'hexa_frame': LiteralScalarString(hexa_frame_output)
            }
        # print("sap: ", detect_llc_sap(paket[30:32]))
    else:
        data = {
            'frame_number': (order + 1),
            'len_frame_pcap': (int(len(paket) / 2)),
            'len_frame_medium': (int((len(paket) / 2) + 4)),
            'frame_type': frame_type,
            'src_mac': sender_mac.upper(),
            'dst_mac': receiver_mac.upper(),
            'hexa_frame': LiteralScalarString(hexa_frame_output)
        }

    all_data.append(data)


def detect_ip_protocol(n):
    return ip_protocols.get(int(n, 16))


def is_ethernet(n):
    if int(n, 16) > 1500:
        return True


def is_raw(n):
    if n == "ffff":
        return True


def is_llc_snap(n):
    if n == "aaaa03":
        return True


def detect_llc_sap(bytes):
    return llc_sap.get(bytes)


def detect_ether_type(bytes):
    return EtherType.get(bytes)


def detect_frame_type(order, paket, all_data):

    if is_ethernet(paket[24:28]):
        display_info(order, paket, "ETHERNET II", all_data)

    elif is_raw(paket[28:32]):
        display_info(order, paket, "IEEE 802.3 RAW", all_data)

    elif is_llc_snap(paket[28:34]):
        display_info(order, paket, "IEEE 802.3 LLC & SNAP", all_data)

    else:
        display_info(order, paket, "IEEE 802.3 LLC", all_data)


# --------------------------------------------------------------------------------------------

def main():

    print(EtherType)
    # creating ethertype dictionary:
    ethertype_file = "./ethertypes.txt"
    with open(ethertype_file, "r") as f:
        for line in f:
            splited_line = line.split()
            EtherType[splited_line[0]] = " ".join(splited_line[1::])
            # print(line.split())
    print(EtherType)

    print(ip_protocols)
    # creating ethertype dictionary:
    ip_protocol_file = "./ip_protocols.txt"
    with open(ip_protocol_file, "r") as f:
        for line in f:
            splited_line = line.split()
            ip_protocols[int(splited_line[0])] = " ".join(splited_line[1::])
            # print(line.split())
    print(ip_protocols)

    pcap_file = "./vzorky_pcap_na_analyzu/trace-26.pcap"
    packets = rdpcap(pcap_file)

    all_data = []

    yaml_file_path = './output.yaml'

    for order, frame_data in enumerate(packets):
        raw_packet = bytes(frame_data)
        hex_packet = raw_packet.hex()

        detect_frame_type(order, hex_packet, all_data)

    # Implemented task 3 !!!
    ipv4_senders = []
    max_send_packets_by = []

    for sender in sender_ip_addresses:
        current_sender_stat = {
            'node': sender,
            'number_of_sent_packets': sender_ip_pakets_amount[sender_ip_addresses.index(sender)]
        }
        ipv4_senders.append(current_sender_stat)

    largest_packets_amount = max(sender_ip_pakets_amount)
    for sender in sender_ip_addresses:
        if sender_ip_pakets_amount[sender_ip_addresses.index(sender)] == largest_packets_amount:
            max_send_packets_by.append(sender)

    data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_file,
        'packets': all_data,

        'ipv4_senders': ipv4_senders,
        'max_send_packets_by': max_send_packets_by
    }

    with open(yaml_file_path, 'w') as yaml_file:
        yaml.dump(data, yaml_file)


if __name__ == "__main__":
    main()
