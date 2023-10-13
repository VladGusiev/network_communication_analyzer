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
    "8e": "PROWAY Active station list maintance",
    "aa": "SNAP",
    "e0": "IPX",
    "f4": "LAN Management",
    "fe": "ISO Network Layer Protocols",
    "ff": "Global DSAP",
    "f0": "NETBIOS"
}

EtherType = {
    "0200": "XEROX PUP",
    "0201": "PUP Addr Trans",
    "2000": "CDP",
    "0800": "Internet IP (IPv4)",
    "0801": "X.75 Internet",
    "0805": "X.25 Level 3",
    "0806": "ARP",
    "8035": "Reverse ARP",
    "809b": "AppleTalk",
    "80f3": "AppleTalk AARP (Kinetics)",
    "8100": "IEEE 802.1Q VLAN-tagged frames",
    "8137": "Novel IPX",
    "86dd": "IPv6",
    "880b": "PPP",
    "8847": "MPLS",
    "8848": "MPLS with-assigned label",
    "8863": "PPPoE Discovery stage",
    "8864": "PPoE Session Stage"
}


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


def is_ethernet(n):
    if int(n, 16) > 1500:
        return True


def is_raw(n):
    if n == "ffff":
        return True


def is_llc_snap(n):
    if n == "aaaa03":
        return True


def detect_llc_sap(paket):
    return llc_sap.get(paket)


def detect_ether_type(paket):
    return EtherType.get(paket)


def detect_frame_type(order, paket, all_data):
    if is_ethernet(paket[24:28]):
        # display_ethernet(order, paket)
        display_info(order, paket, "ETHERNET II", all_data)
    elif is_raw(paket[28:32]):
        # print("frame type:  IEEE 802.3 RAW")
        display_info(order, paket, "IEEE 802.3 RAW", all_data)
    elif is_llc_snap(paket[28:34]):
        # print("frame type: IEEE 802.3 LLC & SNAP")
        detect_ether_type(paket[40:44])
        display_info(order, paket, "IEEE 802.3 LLC & SNAP", all_data)
    else:
        # print("frame type: IEEE 802.3 LLC")
        detect_llc_sap(paket[30:32])
        display_info(order, paket, "IEEE 802.3 LLC", all_data)


def main():
    pcap_file = "./vzorky_pcap_na_analyzu/trace-26.pcap"
    packets = rdpcap(pcap_file)

    all_data = []

    yaml_file_path = './output.yaml'

    for order, frame_data in enumerate(packets):
        raw_packet = bytes(frame_data)
        hex_packet = raw_packet.hex()

        detect_frame_type(order, hex_packet, all_data)

    data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_file,
        'packets': all_data
    }

    with open(yaml_file_path, 'w') as yaml_file:
        yaml.dump(data, yaml_file)


if __name__ == "__main__":
    main()
