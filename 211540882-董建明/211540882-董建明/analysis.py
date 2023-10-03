import scapy.utils
from scapy.layers.dns import DNS
from scapy.layers.l2 import Ether, ARP

from tools import *


# TODO MAC 数据报分析
def ether_pdu_analysis(app, mac_packet):
    analysis_text = ""
    analysis_text += f"Ethernet II, Src: {mac_packet[Ether].src}, Dst: {mac_packet[Ether].dst}\n"
    analysis_text += f"  Destination: {mac_packet[Ether].dst}\n"  # Destination MAC
    analysis_text += f"  Source: {mac_packet[Ether].src}\n"  # Source MAC(48 bits)
    analysis_text += f"  Type: {ETHER_TYPES[mac_packet[Ether].type]} ({mac_packet[Ether].type})\n"  # 以太类型
    analysis_text += f"  payload: {bytes(mac_packet.payload)}\n"  # 负载数据

    app.PDUAnalysisText.insert(END, analysis_text)
    app.PDUCodeText.insert(END, scapy.utils.hexdump(mac_packet, True))


# TODO ARP 数据报分析
def arp_pdu_analysis(app, arp_packet, sniff_time):
    analysis_text = "\n"
    analysis_text += f"捕获时间: {sniff_time}\n"

    # analysis_text += f"Ethernet II, Src: {arp_packet[Ether].src}, Dst: {arp_packet[Ether].dst}\n"
    # analysis_text += f"  Destination: {arp_packet[Ether].dst}\n"  # Destination MAC
    # analysis_text += f"  Source: {arp_packet[Ether].src}\n"  # Source MAC(48 bits)
    # analysis_text += f"  Type: {str(arp_packet[Ether].type) + ' ' + ETHER_TYPES[arp_packet[Ether].type]}\n"  # 以太类型
    ether_pdu_analysis(app, arp_packet)  # 直接调用mac分析函数

    # op: 指定发送方执行的操作:1表示请求, 2表示应答.
    analysis_text += f"Address Resolution Protocol ({'request' if arp_packet[ARP].op == 1 else 'reply'})\n"
    analysis_text += f"  Hardware type: {scapy.layers.l2.HARDWARE_TYPES[arp_packet[ARP].hwtype]}\n"  # 网络链接协议类型
    analysis_text += f"  Protocol type: {arp_packet[ARP].ptype}\n"  # 此字段指定ARP请求所针对的网络协议. 对于IPv4, 它的值是0x0800.
    analysis_text += f"  Hardware size: {arp_packet[ARP].hwlen}\n"  # 硬件地址的长度(以字节为单位). 以太网地址长度为6.
    analysis_text += f"  Protocol size: {arp_packet[ARP].plen}\n"  # 网络地址的长度(以字节为单位). 网络协议在PTYPE中指定. 示例:IPv4地址长度为4.
    analysis_text += f"  Opcode: {'request (1)' if arp_packet[ARP].op == 1 else 'reply (2)'}\n"
    analysis_text += f"  Sender MAC address: {arp_packet[ARP].hwsrc}\n"  # 发送方硬件地址
    analysis_text += f"  Sender IP address: {arp_packet[ARP].psrc}\n"  # 发送方IP地址
    analysis_text += f"  Target MAC address: {arp_packet[ARP].hwdst}\n"  # 目标硬件地址
    analysis_text += f"  Target IP address: {arp_packet[ARP].pdst}\n"  # 目标IP

    app.PDUAnalysisText.insert(END, analysis_text)


# TODO IP 数据报分析
def ip_pdu_analysis(app, ip_packet):
    analysis_text = "\n"

    # analysis_text += f"Ethernet II, Src: {ip_packet[Ether].src}, Dst: {ip_packet[Ether].dst}\n"
    # analysis_text += f"  Destination: {ip_packet[Ether].dst}\n"  # Destination MAC
    # analysis_text += f"  Source: {ip_packet[Ether].src}\n"  # Source MAC(48 bits)
    # analysis_text += f"  Type: {str(ip_packet[Ether].type) + ' ' + ETHER_TYPES[ip_packet[Ether].type]}\n"  # 以太类型
    ether_pdu_analysis(app, ip_packet)  # 直接调用mac分析函数

    analysis_text += f"Internet Protocol Version {ip_packet[IP].version}, Src: {ip_packet[IP].src}, " \
                     f"Dst: {ip_packet[IP].dst}\n"  # 版本和地址
    analysis_text += f"  {int_bin(ip_packet[IP].version, 4)}.... = Version: {ip_packet[IP].version}\n"  # IP的版本
    analysis_text += f"  ....{int_bin(ip_packet[IP].ihl, 4)} = Header Length: {ip_packet[IP].ihl * 4} " \
                     f"bytes ({ip_packet[IP].ihl})\n"  # 首部长度
    analysis_text += f"  Differentiated Service Field: 0x{ip_packet[IP].tos:04x}\n"  # 服务类型
    analysis_text += f"  Total Length: {ip_packet[IP].len}\n"  # 总长度
    analysis_text += f"  Identification: 0x{ip_packet[IP].id:04x} ({ip_packet[IP].id:d})\n"  # 标识,IP包发送时被给定特有的ID
    # 标志位
    analysis_text += f"  {ip_flags(ip_packet[IP].flags)[0]}. .... = Flags: {ip_flags(ip_packet[IP].flags)[1]}" \
                     f"{ip_flags(ip_packet[IP].flags)[2]}\n"
    analysis_text += f"    0... .... = Reserved bit: Not set\n"
    analysis_text += f"    .{ip_flags(ip_packet[IP].flags)[0][1]}.. .... = Don't fragment: " \
                     f"{'Not ' if ip_packet[IP].flags != 'DF' else ''}Set\n"
    analysis_text += f"    ..{ip_flags(ip_packet[IP].flags)[0][2]}. .... = More fragment: " \
                     f"{'Not ' if ip_packet[IP].flags != 'MF' else ''}Set\n"
    # 片偏移
    analysis_text += f"  ...{int_bin(ip_packet[IP].frag, 13)} = Fragment offset: {ip_packet[IP].frag * 8} " \
                     f"({ip_packet[IP].frag})\n"

    analysis_text += f"  Time to live: {ip_packet[IP].ttl}\n"  # 生存时间
    analysis_text += f"  Protocol: {IP_PROTOS[ip_packet[IP].proto]} ({ip_packet[IP].proto})\n"  # 协议
    #  ip 首部校验和
    analysis_text += f"  Header  Checksum: {ip_head_checksum(ip_packet)[0]} {ip_head_checksum(ip_packet)[2]}\n"  # 首部校验和
    analysis_text += f"  [Header checksum status: {ip_head_checksum(ip_packet)[3]}]\n"
    analysis_text += f"  [Calculated checksum: {ip_head_checksum(ip_packet)[1]}]\n"

    analysis_text += f"  Source Address: {ip_packet[IP].src}\n"  # 源地址
    analysis_text += f"  Destination Address: {ip_packet[IP].dst}\n"  # 目的地址

    app.PDUAnalysisText.insert(END, analysis_text)


# TODO IPv6
def ipv6_pdu_analysis(app, ipv6_packet):
    analysis_text = "\n"

    ether_pdu_analysis(app, ipv6_packet)  # 直接调用mac分析函数

    analysis_text += f"Internet Protocol Version {ipv6_packet[IPv6].version}, Src: {ipv6_packet[IPv6].src}, " \
                     f"Dst: {ipv6_packet[IPv6].dst}\n"
    analysis_text += f"  {int_bin(ipv6_packet[IPv6].version, 4)} .... = Version: {ipv6_packet[IPv6].version}\n"
    # IPv6 流量类别（Traffic Class），占 8 位。它用于指定数据包的流量类别，类似于 IPv4 中的服务类型字段（Type of Service，TOS）。
    analysis_text += f"  .... {int_bin(ipv6_packet[IPv6].tc, 8, True)} .... .... .... .... .... = Traffic Class: " \
                     f"{ipv6_packet[IPv6].tc} (DSCP: {DSCP_TYPES[int_bin(ipv6_packet[IPv6].tc, 8)[:6]]}, " \
                     f"ECN: {ECN_TYPES[int_bin(ipv6_packet[IPv6].tc, 8)[6:]][0]})\n"
    """
    前6位被用于表示DSCP（Differentiated Services Code Point），也称为Class Selector。
    DSCP定义了IPv6数据包的服务类别，以决定数据包在网络中的优先级和处理方式。不同的DSCP值对应不同的服务质量，例如，低延迟、高吞吐量等。
    https://en.wikipedia.org/wiki/Differentiated_services
    """
    analysis_text += f"    .... {int_bin(ipv6_packet[IPv6].tc, 8, True)[:7]}" \
                     f".. .... .... .... .... .... = Differentiated Services Codepoint: " \
                     f"{DSCP_TYPES[int_bin(ipv6_packet[IPv6].tc, 8)[:6]]} " \
                     f"({int(int_bin(ipv6_packet[IPv6].tc, 8)[:6], 2)})\n"
    """
    ECN 使用 IPv4 首部或 IPv6 首部中 ToS (Type of Service，位于首部第 9 到 16 比特位) 字段的两个最低有效位（最右侧的位编码）来表示四个状态码：
    00 – 不支持 ECN 的传输，非 ECT(Non ECN-Capable Transport)
    10 – 支持 ECN 的传输，ECT(0)
    01 – 支持 ECN 的传输，ECT(1)
    11 – 发生拥塞，CE(Congestion Experienced)。
    当两端支持 ECN 时，它将数据包标为 ECT(0) 或 ECT(1)。如果分组穿过一个遇到阻塞并且相应路由器支持 ECN 的活动队列管理（AQM）队列
    （例如一个使用随机早期检测，即 RED 的队列），它可以将代码点更改为CE而非丢包。这种行为就是“标记”，其目的是通知接收端即将发生拥塞。
    在接收端，该拥塞指示由上层协议（传输层协议）处理，并且需要将信号回传给发送端，以通知其降低传输速率。
    因为 CE 指示只能由支持它的上层协议有效处理，ECN 只能配合上层协议使用。例如 TCP 协议，它支持阻塞控制并且有方法将 CE 指示回传给发送端。
    https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    """
    analysis_text += f"    .... .... ..{int_bin(ipv6_packet[IPv6].tc, 8)[6:]} " \
                     f".... .... .... .... .... = Explicit Congestion Notification: " \
                     f"{ECN_TYPES[int_bin(ipv6_packet[IPv6].tc, 8)[6:]][1]}\n"
    # IPv6 流标签（Flow Label），占 20 位。流标签字段用于标识属于同一流的数据包，以便路由器在处理数据包时可以将它们分配给相同的处理路径。
    analysis_text += f"  .... {int_bin(ipv6_packet[IPv6].fl, 20, True)} = Flow Label: {ipv6_packet[IPv6].fl}\n"
    # IPv6 负载长度（Payload Length），占 16 位。该字段指示了 IPv6 报文头部之后的负载部分的长度，以字节为单位。
    analysis_text += f"  Payload Length: {ipv6_packet[IPv6].plen}\n"
    # 下一个头部（Next Header），占 8 位。该字段指示了紧随 IPv6 头部之后的下一个头部的类型，例如 TCP、UDP、ICMPv6 等。
    analysis_text += f"  Next Header: {ipv6_packet[IPv6].nh}\n"
    #  IPv6 跳数限制（Hop Limit），占 8 位。跳数限制字段类似于 IPv4 中的 TTL（Time to Live）字段，它限制了数据包在网络中的最大跳数，以防止数据包无限循环。
    analysis_text += f"  Hop Limit: {ipv6_packet[IPv6].hlim}\n"
    # IPv6 源地址（Source Address），占 128 位。该字段表示数据包的源地址。
    analysis_text += f"  Source Address: {ipv6_packet[IPv6].src}\n"
    # IPv6 目标地址（Destination Address），占 128 位。该字段表示数据包的目标地址。
    analysis_text += f"  Destination Address: {ipv6_packet[IPv6].dst}\n"

    app.PDUAnalysisText.insert(END, analysis_text)


# TODO TCP 数据报分析
def tcp_pdu_analysis(app, tcp_packet):
    analysis_text = "\n"

    if tcp_packet.haslayer('IP'):
        ip_pdu_analysis(app, tcp_packet)
    elif tcp_packet.haslayer('IPv6'):
        ipv6_pdu_analysis(app, tcp_packet)

    analysis_text += f"Transmission Control Protocol, Src Port: {tcp_packet[TCP].sport}, " \
                     f"Dst Port: {tcp_packet[TCP].dport}, Seq: {tcp_packet[TCP].seq}, " \
                     f"Ack: {tcp_packet[TCP].ack}, Len: {tcp_len(tcp_packet)}\n"
    analysis_text += f"  Source Port: {tcp_packet[TCP].sport}\n"  # 发送连接端口
    analysis_text += f"  Destination Port: {tcp_packet[TCP].dport}\n"  # 接收连接端口

    # analysis_text += f"  [Stream index: ???]\n"  # 流索引
    # analysis_text += f"  [Conversation completeness: ??? Incomplete (12)]\n"

    analysis_text += f"  [TCP Segment Len: {tcp_len(tcp_packet)}\n"  # tcp长度

    # 如果SYN标志设置为1, 则这是初始序列号
    # 如果SYN标志设置为0, 则这是当前会话该段的第一个数据字节的累计序列号
    # analysis_text += f"  Sequence Number: ??? (relative sequence number)\n"
    analysis_text += f"  Sequence Number (raw): {tcp_packet[TCP].seq}\n"
    # analysis_text += f"  [Next Sequence Number: ???    (relative sequence number)]\n"

    # 如果设置了ACK标志, 那么这个字段的值就是ACK发送者期望的下一个序列号
    # analysis_text += f"  Acknowledgment Number: ???    (relative ack number)\n"
    analysis_text += f"  Acknowledgment Number (raw): {tcp_packet[TCP].ack}\n"

    # 首部长度
    analysis_text += f"  {int_bin(tcp_packet[TCP].dataofs, 4)} .... = " \
                     f"Header Length: {tcp_packet[TCP].dataofs * 4} bytes ({tcp_packet[TCP].dataofs})\n"

    # 标志位
    analysis_text += f"  Flags: {tcp_flags(tcp_packet[TCP].flags)['hex']} " \
                     f"({tcp_flags(tcp_packet[TCP].flags)['result']})\n"
    analysis_text += f"    000. .... .... = Reserved: Not set\n"
    analysis_text += f"    ...{tcp_flags(tcp_packet[TCP].flags)['bin'][3]} " \
                     f".... .... = Accurate ECN: {tcp_flags(tcp_packet[TCP].flags)['NS']}\n"
    analysis_text += f"    .... {tcp_flags(tcp_packet[TCP].flags)['bin'][4]}" \
                     f"... .... = Congestion Window Reduced: {tcp_flags(tcp_packet[TCP].flags)['CWR']}\n"
    analysis_text += f"    .... .{tcp_flags(tcp_packet[TCP].flags)['bin'][5]}" \
                     f".. .... = ECN-Echo: {tcp_flags(tcp_packet[TCP].flags)['ECE']}\n"
    analysis_text += f"    .... ..{tcp_flags(tcp_packet[TCP].flags)['bin'][6]}" \
                     f". .... = Urgent: {tcp_flags(tcp_packet[TCP].flags)['URG']}\n"
    analysis_text += f"    .... ...{tcp_flags(tcp_packet[TCP].flags)['bin'][7]}" \
                     f" .... = Acknowledgment: {tcp_flags(tcp_packet[TCP].flags)['ACK']}\n"
    analysis_text += f"    .... .... {tcp_flags(tcp_packet[TCP].flags)['bin'][8]}" \
                     f".. .... = Push: {tcp_flags(tcp_packet[TCP].flags)['PSH']}\n"
    analysis_text += f"    .... .... .{tcp_flags(tcp_packet[TCP].flags)['bin'][9]}" \
                     f" .... = Reset: {tcp_flags(tcp_packet[TCP].flags)['RST']}\n"
    analysis_text += f"    .... .... ..{tcp_flags(tcp_packet[TCP].flags)['bin'][10]}" \
                     f" .... = Syn: {tcp_flags(tcp_packet[TCP].flags)['SYN']}\n"
    analysis_text += f"    .... .... ...{tcp_flags(tcp_packet[TCP].flags)['bin'][11]}" \
                     f" .... = Fin: {tcp_flags(tcp_packet[TCP].flags)['FIN']}\n"
    analysis_text += f"    [TCP Flags: {tcp_flags(tcp_packet[TCP].flags)['letter']}]\n"

    # 接收窗口的大小, 它指定此段的发送方当前愿意接收的窗口大小单元的数量(默认情况下为字节)
    analysis_text += f"  Window: {tcp_packet[TCP].window}\n"
    # analysis_text += f"  [Calculated window size: ???]\n"
    # analysis_text += f"  [Window size scaling factor: ???]\n"

    # 校验和
    analysis_text += f"  Checksum: {tcp_checksum(tcp_packet)[0]} {tcp_checksum(tcp_packet)[2]}\n"
    analysis_text += f"  [Checksum Status: {tcp_checksum(tcp_packet)[3]}]\n"
    analysis_text += f"  [Calculated Checksum: {tcp_checksum(tcp_packet)[1]}]\n"

    # 如果设置了URG标志, 那么这个16位字段就是表示最后一个紧急数据字节的序列号的偏移量
    analysis_text += f"  Urgent Pointer: {tcp_packet[TCP].urgptr}\n"

    # TCP 数据包的选项字段（Options Field）。TCP 选项字段是 TCP 头部中的一部分，用于在 TCP 连接建立和维护过程中传输附加信息。
    analysis_text += f"  Options: {tcp_packet[TCP].options}\n"

    app.PDUAnalysisText.insert(END, analysis_text)


# TODO UDP 数据报分析
def udp_pdu_analysis(app, udp_packet):
    analysis_text = "\n"

    if udp_packet.haslayer('IP'):
        ip_pdu_analysis(app, udp_packet)
    elif udp_packet.haslayer('IPv6'):
        ipv6_pdu_analysis(app, udp_packet)

    analysis_text += f"User Datagram Protocol, Src Port: {udp_packet[UDP].sport}, Dst Port: {udp_packet[UDP].dport}\n"
    analysis_text += f"  Source Port: {udp_packet[UDP].sport}\n"
    analysis_text += f"  Destination Port: {udp_packet[UDP].dport}\n"
    analysis_text += f"  Length: {udp_packet[UDP].len}\n"
    analysis_text += udp_checksum(udp_packet)
    # analysis_text += f"  [Stream index: ???]\n"
    analysis_text += f"  UDP payload ({len(udp_packet[UDP].payload)} bytes)\n"

    app.PDUAnalysisText.insert(END, analysis_text)


# TODO ICMP
def icmp_pdu_analysis(app, icmp_packet):
    analysis_text = "\n"

    ip_pdu_analysis(app, icmp_packet)

    analysis_text += f"Internet Control Message Protocol\n"
    analysis_text += f"  Type: {icmp_packet[ICMP].type} ({ICMP_TYPES[icmp_packet[ICMP].type]})\n"
    analysis_text += f"  Code: {icmp_packet[ICMP].code} {'(' + ICMP_CODES[icmp_packet[ICMP].type][icmp_packet[ICMP].code] + ')' if (icmp_packet[ICMP].type in ICMP_CODES.keys()) else ''}\n"
    analysis_text += f"  Checksum: {icmp_checksum(icmp_packet)[0]} {icmp_checksum(icmp_packet)[2]}\n"
    analysis_text += f"  [Checksum Status: {icmp_checksum(icmp_packet)[3]}]\n"
    analysis_text += f"  [Calculated Checksum:  {icmp_checksum(icmp_packet)[1]}]\n"
    analysis_text += f"  Identifier (BE): {icmp_packet[ICMP].id} " \
                     f"(0x{icmp_packet[ICMP].id:04x})\n"  # linux 用于匹配 Request/Reply 的标识符 大端字节序
    analysis_text += f"  Identifier (LE): {swap_endianness(icmp_packet[ICMP].id)} " \
                     f"(0x{swap_endianness(icmp_packet[ICMP].id):04x})\n"  # windows 小端字节序
    analysis_text += f"  Sequence Number (BE): {icmp_packet[ICMP].seq} " \
                     f"(0x{icmp_packet[ICMP].seq:04x})\n"  # 用于匹配 Request/Reply 的序列号
    analysis_text += f"  Sequence Number (LE): {swap_endianness(icmp_packet[ICMP].seq)} " \
                     f"(0x{swap_endianness(icmp_packet[ICMP].seq):04x})\n"

    app.PDUAnalysisText.insert(END, analysis_text)


# TODO DNS
def dns_pdu_analysis(app, dns_packet):
    analysis_text = "\n"

    if dns_packet.haslayer('IP'):
        ip_pdu_analysis(app, dns_packet)
    elif dns_packet.haslayer('IPv6'):
        ipv6_pdu_analysis(app, dns_packet)

    # 打印属性值
    # dns_packet = dns_packet[DNS]
    # print("length:", dns_packet.length)
    # print("id:", dns_packet.id)
    # print("qr:", dns_packet.qr)
    # print("opcode:", dns_packet.opcode)
    # print("aa:", dns_packet.aa)
    # print("tc:", dns_packet.tc)
    # print("rd:", dns_packet.rd)
    # print("ra:", dns_packet.ra)
    # print("z:", dns_packet.z)
    # print("ad:", dns_packet.ad)
    # print("cd:", dns_packet.cd)
    # print("rcode:", dns_packet.rcode)
    # print("qdcount:", dns_packet.qdcount)
    # print("ancount:", dns_packet.ancount)
    # print("nscount:", dns_packet.nscount)
    # print("arcount:", dns_packet.arcount)
    # print("qd:", dns_packet.qd)
    # print("an:", dns_packet.an)
    # print("ns:", dns_packet.ns)
    # print("ar:", dns_packet.ar)
    """qr == 0, query ->
    length: None
    id: 2335
    -qr: 0
    -opcode: 0
    -aa: 0
    -tc: 0
    -rd: 1
    -ra: 0
    -z: 0
    -ad: 0
    -cd: 0
    -rcode: 0
    qdcount: 1
    ancount: 0
    nscount: 0
    arcount: 0
    qd: DNSQR
    an: None
    ns: None
    ar: None"""
    """qr == 1,  response ->
    length: None
    id: 59526
    qr: 1
    opcode: 0
    aa: 0
    tc: 0
    rd: 1
    ra: 1
    z: 0
    ad: 0
    cd: 0
    rcode: 0
    qdcount: 1
    ancount: 2
    nscount: 1
    arcount: 0
    qd: DNSQR
    an: DNSRR / DNSRR
    ns: DNSRRSOA
    ar: None"""

    analysis_text += f"Domain Name System ({DNS_TYPES[dns_packet[DNS].qr]})\n"  # 类型：查询或响应
    analysis_text += f"  Transaction ID: 0x{dns_packet[DNS].id:04x}\n"  # DNS报文的标识字段，用于将查询和响应匹配在一起
    analysis_text += dns_flags(dns_packet)
    # qdcount：DNS请求计数，表示查询部分的记录数。
    analysis_text += f"  Questions: {dns_packet[DNS].qdcount}\n"
    # ancount：DNS回答计数，表示回答部分的记录数。
    analysis_text += f"  Answer RRs: {dns_packet[DNS].ancount}\n"
    # nscount：DNS授权计数，表示权威部分的记录数。
    analysis_text += f"  Authority RRs: {dns_packet[DNS].nscount}\n"
    # arcount：DNS附加计数，表示附加部分的记录数。
    analysis_text += f"  Additional RRs: {dns_packet[DNS].arcount}\n"
    # qd：DNS查询记录（Query），包含查询的域名和查询类型。
    analysis_text += f"  Queries: {dns_packet[DNS].qd}\n"
    # an：DNS回答记录（Answer），包含DNS响应的资源记录。
    analysis_text += f"  Answers: {dns_packet[DNS].an}\n"
    # ns：DNS授权记录（Authority），包含权威区域的资源记录。
    analysis_text += f"  Authoritative nameservers: {dns_packet[DNS].ns}\n"
    # ar：DNS附加记录（Additional），包含附加的资源记录。
    analysis_text += f"  Additional records: {dns_packet[DNS].ar}\n"

    app.PDUAnalysisText.insert(END, analysis_text)
