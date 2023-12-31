# 16进制对应的10进制
HEX = {'0': 0,
       '1': 1,
       '2': 2,
       '3': 3,
       '4': 4,
       '5': 5,
       '6': 6,
       '7': 7,
       '8': 8,
       '9': 9,
       'a': 10,
       'b': 11,
       'c': 12,
       'd': 13,
       'e': 14,
       'f': 15, }
# 网络链接协议类型
HARDWARE_TYPES = {
    1: "Ethernet (10Mb)",
    2: "Ethernet (3Mb)",
    3: "AX.25",
    4: "Proteon ProNET Token Ring",
    5: "Chaos",
    6: "IEEE 802 Networks",
    7: "ARCNET",
    8: "Hyperchannel",
    9: "Lanstar",
    10: "Autonet Short Address",
    11: "LocalTalk",
    12: "LocalNet",
    13: "Ultra link",
    14: "SMDS",
    15: "Frame relay",
    16: "ATM",
    17: "HDLC",
    18: "Fibre Channel",
    19: "ATM",
    20: "Serial Line",
    21: "ATM",
}
# 以太网类型
ETHER_TYPES = {
    2048: 'Internet Protocol version 4',
    2054: 'Address Resolution Protocol',
    2114: 'Wake-on-LAN',
    8944: 'Audio Video Transport Protocol as defined in IEEE Std 1722-2011',
    8947: 'IETF TRILL Protocol',
    24579: 'DECnet',
    32821: 'Reverse Address Resolution Protocol',
    32923: 'AppleTalk',
    33011: 'AppleTalk',
    33024: 'IEEE 802.1Q',
    33079: 'IPX',
    33080: 'IPX',
    33284: 'QNX Qnet',
    34525: 'Internet Protocol Version 6',
    34824: 'Ethernet flow control',
    34825: 'IEEE 802.3',
    34841: 'CobraNet',
    34887: 'MPLS',
    34888: 'MPLS',
    34915: 'PPPoE',
    34916: 'PPPoE',
    34928: 'Jumbo Frames',
    34939: 'HomePlug 1.0 MME',
    34958: 'IEEE 802.1X',
    34962: 'PROFINET',
    34970: 'HyperSCSI',
    34978: 'ATA over Ethernet',
    34980: 'EtherCAT',
    34984: 'IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)',
    34987: 'Ethernet Powerlink',
    35020: '链路层发现协议',
    35021: 'SERCOS III',
    35041: 'HomePlug AV MME',
    35043: 'Media Redundancy Protocol (IEC62439-2)',
    35045: 'IEEE 802.1AE',
    35047: 'IEEE 802.1ah',
    35063: 'Precision Time Protocol',
    35074: 'IEEE 802.1ag',
    35078: 'Fibre Channel over Ethernet',
    35092: 'FCoE',
    35093: 'RDMA over Converged Ethernet',
    35119: 'High-availability Seamless Redundancy',
    36864: 'Ethernet Configuration Testing Protocol',
    37120: 'double tagging'
}
# IP协议
IP_PROTOS = {0: 'IPv6逐跳选项', 1: '互联网控制消息协议 (ICMP)', 2: '因特网组管理协议 (IGMP)',
             3: '网关对网关协议', 4: 'IPv4 (封装)', 5: '因特网流协议', 6: '传输控制协议 (TCP)',
             7: '有核树组播路由协议', 8: '外部网关协议', 9: '内部网关协议 (任意私有内部网关 (用于思科的IGRP) )',
             10: 'BBN RCC 监视', 11: '网络语音协议', 12: 'Xerox PUP', 13: 'ARGUS', 14: 'EMCON',
             15: 'Cross Net Debugger', 16: 'Chaos', 17: '用户数据报协议 (UDP)', 18: 'Multiplexing',
             19: 'DCN Measurement Subsystems', 20: 'Host Monitoring Protocol', 21: 'Packet Radio Measurement',
             22: 'XEROX NS IDP', 23: 'Trunk-1', 24: 'Trunk-2', 25: 'Leaf-1', 26: 'Leaf-2',
             27: 'Reliable Datagram Protocol', 28: 'Internet Reliable Transaction Protocol',
             29: 'ISO Transport Protocol Class 4', 30: 'Bulk Data Transfer Protocol',
             31: 'MFE Network Services Protocol', 32: 'MERIT Internodal Protocol',
             33: 'Datagram Congestion Control Protocol', 34: 'Third Party Connect Protocol',
             35: 'Inter-Domain Policy Routing Protocol', 36: 'Xpress Transport Protocol',
             37: 'Datagram Delivery Protocol', 38: 'IDPR Control Message Transport Protocol',
             39: 'TP++ Transport Protocol', 40: 'IL Transport Protocol', 41: 'IPv6 封装',
             42: 'Source Demand Routing Protocol', 43: 'IPv6路由拓展头', 44: 'IPv6分片扩展头',
             45: 'Inter-Domain Routing Protocol', 46: 'Resource Reservation Protocol', 47: '通用路由封装 (GRE)',
             48: 'Mobile Host Routing Protocol', 49: 'BNA', 50: '封装安全协议 (ESP)', 51: '认证头协议 (AH)',
             52: 'Integrated Net Layer Security Protocol', 53: 'SwIPe', 54: 'NBMA Address Resolution Protocol',
             55: 'IP Mobility (Min Encap)',
             56: 'Transport Layer Security Protocol (using Kryptonet key management)',
             57: 'Simple Key-Management for Internet Protocol', 58: '互联网控制消息协议第六版 (ICMPv6)',
             59: 'IPv6无负载头', 60: 'IPv6目标选项扩展头', 61: 'Any host internal protocol', 62: 'CFTP',
             63: 'Any local network', 64: 'SATNET and Backroom EXPAK', 65: 'Kryptolan',
             66: 'MIT Remote Virtual Disk Protocol', 67: 'Internet Pluribus Packet Core',
             68: 'Any distributed file system', 69: 'SATNET Monitoring', 70: 'VISA协议',
             71: 'Internet Packet Core Utility', 72: 'Computer Protocol Network Executive',
             73: 'Computer Protocol Heart Beat', 74: 'Wang Span Network', 75: 'Packet Video Protocol',
             76: 'Backroom SATNET Monitoring', 77: 'SUN ND PROTOCOL-Temporary', 78: 'WIDEBAND Monitoring',
             79: 'WIDEBAND EXPAK', 80: '国际标准化组织互联网协议', 81: 'Versatile Message Transaction Protocol',
             82: 'Secure Versatile Message Transaction Protocol', 83: 'VINES',
             84: 'Internet Protocol Traffic Manager', 85: 'NSFNET-IGP', 86: 'Dissimilar Gateway Protocol',
             87: 'TCF', 88: '增强型内部网关路由协议 (EIGRP)', 89: '开放式最短路径优先 (OSPF)',
             90: 'Sprite RPC Protocol', 91: 'Locus Address Resolution Protocol',
             92: 'Multicast Transport Protocol', 93: 'AX.25', 94: 'IP-within-IP 封装协议',
             95: 'Mobile Internetworking Control Protocol', 96: 'Semaphore Communications Sec. Pro',
             97: 'Ethernet-within-IP 封装协议', 98: 'Encapsulation Header', 99: 'Any private encryption scheme',
             100: 'GMTP', 101: 'Ipsilon Flow Management Protocol', 102: 'PNNI over IP',
             103: 'Protocol Independent Multicast', 104: "IBM's ARIS (Aggregate Route IP Switching) Protocol",
             105: 'SCPS (Space Communications Protocol Standards)', 106: 'QNX', 107: 'Active Networks',
             108: 'IP Payload Compression Protocol', 109: 'Sitara Networks Protocol',
             110: 'Compaq Peer Protocol', 111: 'IPX in IP',
             112: 'Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (没在IANA注册)',
             113: 'PGM Reliable Transport Protocol', 114: 'Any 0-hop protocol',
             115: 'Layer Two Tunneling Protocol Version 3', 116: 'D-II Data Exchange (DDX)',
             117: 'Interactive Agent Transfer Protocol', 118: 'Schedule Transfer Protocol',
             119: 'SpectraLink Radio Protocol', 120: 'Universal Transport Interface Protocol',
             121: 'Simple Message Protocol', 122: 'Simple Multicast Protocol',
             123: 'Performance Transparency Protocol',
             124: 'Intermediate System to Intermediate System (IS-IS) Protocol over IPv4',
             125: 'Flexible Intra-AS Routing Environment', 126: 'Combat Radio Transport Protocol',
             127: 'Combat Radio User Datagram',
             128: 'Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment',
             129: '', 130: 'Secure Packet Shield', 131: 'Private IP Encapsulation within IP',
             132: 'Stream Control Transmission Protocol', 133: 'Fibre Channel',
             134: 'Reservation Protocol (RSVP) End-to-End Ignore', 135: 'IPv6移动IP扩展头',
             136: 'Lightweight User Datagram Protocol', 137: 'Multiprotocol Label Switching Encapsulated in IP',
             138: 'MANET Protocols', 139: 'Host Identity Protocol',
             140: 'Site Multihoming by IPv6 Intermediation', 141: 'Wrapped Encapsulating Security Payload',
             142: 'Robust Header Compression', 253: 'RFC 3692', 254: 'RFC 3692'}
# ICMP类型
ICMP_TYPES = {0: "echo-reply",
              3: "dest-unreach",
              4: "source-quench",
              5: "redirect",
              8: "echo-request",
              9: "router-advertisement",
              10: "router-solicitation",
              11: "time-exceeded",
              12: "parameter-problem",
              13: "timestamp-request",
              14: "timestamp-reply",
              15: "information-request",
              16: "information-response",
              17: "address-mask-request",
              18: "address-mask-reply",
              30: "traceroute",
              31: "datagram-conversion-error",
              32: "mobile-host-redirect",
              33: "ipv6-where-are-you",
              34: "ipv6-i-am-here",
              35: "mobile-registration-request",
              36: "mobile-registration-reply",
              37: "domain-name-request",
              38: "domain-name-reply",
              39: "skip",
              40: "photuris"}
# ICMP类型细分代码
ICMP_CODES = {3: {0: "network-unreachable",
                  1: "host-unreachable",
                  2: "protocol-unreachable",
                  3: "port-unreachable",
                  4: "fragmentation-needed",
                  5: "source-route-failed",
                  6: "network-unknown",
                  7: "host-unknown",
                  9: "network-prohibited",
                  10: "host-prohibited",
                  11: "TOS-network-unreachable",
                  12: "TOS-host-unreachable",
                  13: "communication-prohibited",
                  14: "host-precedence-violation",
                  15: "precedence-cutoff", },
              5: {0: "network-redirect",
                  1: "host-redirect",
                  2: "TOS-network-redirect",
                  3: "TOS-host-redirect", },
              11: {0: "ttl-zero-during-transit",
                   1: "ttl-zero-during-reassembly", },
              12: {0: "ip-header-bad",
                   1: "required-option-missing", },
              40: {0: "bad-spi",
                   1: "authentication-failed",
                   2: "decompression-failed",
                   3: "decryption-failed",
                   4: "need-authentification",
                   5: "need-authorization", }, }
# IPv6 中 ENC字段
"""00 – 不支持 ECN 的传输，非 ECT(Non ECN-Capable Transport)
10 – 支持 ECN 的传输，ECT(0)
01 – 支持 ECN 的传输，ECT(1)
11 – 发生拥塞，CE(Congestion Experienced)。"""
ECN_TYPES = {
    "00": ["Not-ECT", "Not ECN-Capable Transport (0)"],
    "01": ["ECT(1)", "ECT-1 (1)"],
    "10": ["ECT(0)", "ECT-0 (2)"],
    "11": ["CE", "Congestion Experienced(3)"]
}
# IPv6 DSCP字段 https://en.wikipedia.org/wiki/Differentiated_services
DSCP_TYPES = {
    "000000": "Default, CS0",
    "001000": "CS1",
    "010000": "CS2",
    "011000": "CS3",
    "100000": "CS4",
    "101000": "CS5",
    "110000": "CS6",
    "111000": "CS7",
    "001010": "AF11, AF12, AF13",
    "001100": "AF11, AF12, AF13",
    "001110": "AF11, AF12, AF13",
    "010010": "AF21, AF22, AF23",
    "010100": "AF21, AF22, AF23",
    "010110": "AF21, AF22, AF23",
    "011010": "AF31, AF32, AF33",
    "011100": "AF31, AF32, AF33",
    "011110": "AF31, AF32, AF33",
    "100010": "AF41, AF42, AF43",
    "100100": "AF41, AF42, AF43",
    "100110": "AF41, AF42, AF43",
    "101110": "EF"
}
# qr：表示DNS报文的类型，0表示查询报文，1表示响应报文
DNS_TYPES = {0: "query", 1: "response"}
# DNS请求或响应的操作码
"""QUERY (0)：标识DNS查询操作，用于发送DNS查询请求。
IQUERY (1)：标识反向查询操作，用于从IP地址查找主机名。
STATUS (2)：标识DNS状态查询操作，用于获取DNS服务器的状态信息。
NOTIFY (4)：DNS通知操作，用于通知从属DNS服务器有关资源记录的变更。
UPDATE (5)：DNS更新操作，用于向DNS服务器添加或删除资源记录。"""
DNS_OPCODE_TYPES = {
    0: "Standard query",
    1: "Inverse query",
    2: "Server status request",
    4: "Notify",
    5: "Update"
}
# DNS 响应码（Response Code），用于指示 DNS 响应的状态或结果
"""NoError (0)：没有错误。表示 DNS 查询成功，并且有回答部分。
FormErr (1)：格式错误。表示 DNS 查询的格式不正确，无法处理。
ServFail (2)：服务器故障。表示 DNS 服务器无法执行查询操作，可能是因为服务器内部问题。
NXDomain (3)：域名不存在。表示查询的域名不存在。
NotImp (4)：不支持的查询。表示 DNS 服务器不支持查询类型或操作码。
Refused (5)：拒绝查询。表示 DNS 服务器拒绝执行查询操作，可能是出于安全或策略原因。
YXDomain (6)：域名已存在。表示尝试创建的域名已存在。
YXRRSet (7)：资源记录集已存在。表示尝试创建的资源记录集已存在。
NXRRSet (8)：资源记录集不存在。表示资源记录集不存在。
NotAuth (9)：不授权。表示DNS服务器不是指定域名的权威服务器，无权执行查询操作。
NotZone (10)：不是区域。表示查询不是该DNS服务器的区域。"""
DNS_RCODE_TYPES = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone"
}
