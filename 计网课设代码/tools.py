from tkinter import *
import tkinter.messagebox as messagebox
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from constants import *


def int_bin(n, count, is_split=False):
    """ TODO 10进制转2进制，n：输入的10进制，count：输出的2进制位数，is_split：可选，是否四位一隔"""
    result = "".join([str((n >> y) & 1) for y in range(count - 1, -1, -1)])
    if is_split:
        # 将二进制字符串从右到左分割成四位一组
        formatted_str = ''
        count = 0
        for bit in reversed(result):
            if count == 4:
                formatted_str = ' ' + formatted_str
                count = 0
            formatted_str = bit + formatted_str
            count += 1
        return formatted_str
    else:
        return result


def swap_endianness(n):
    """TODO 大端字节序转为小端字节序"""
    return ((n >> 8) & 0x00FF) | ((n << 8) & 0xFF00)


# 清空捕获数据
def clear_data(app):
    if app.sniffFlag is True:
        app.listbox.delete(0, END)
        app.sniffDataList = []
        app.PDUAnalysisText.delete(1.0, END)
        app.PDUCodeText.delete(1.0, END)
        app.count = 0
        app.countAct = 0
    else:
        messagebox.showinfo(title='友情提示', message="请先停止捕获！！")


# 分割条件的函数 按空格
def split_condition(app):
    conditionString = app.conditionInput.get()
    splitList = conditionString.split(' ')
    splitStrings = []
    for conString in splitList:
        splitStrings.append(conString)
    return splitStrings


# 分割条件的函数，按==
def split_dul_equal(dul):  # 按照等号划分后获得筛选的条件
    splitList = dul.split('==')
    return splitList[1]


def ip_flags(chosen_ip_flags):
    """TODO IP flags"""
    flags = 0
    if chosen_ip_flags == "DF":
        flags = 2
    elif chosen_ip_flags == "MF":
        flags = 1
    result = ""
    if flags == 2:
        result = ", Don't fragment"
    elif flags == 1:
        result = ", More fragments"
    return [int_bin(flags, 3), hex(flags), result]  # 标志位二进制和十六进制


def ip_head_checksum(ip_packet):
    """TODO IP校验和 计算和验证"""
    _f_ip_packet = copy.deepcopy(ip_packet)  # 使用深拷贝，以免影响原数据包
    # 计算检验和
    checksum1 = _f_ip_packet[IP].chksum

    _f_ip_packet[IP].chksum = 0
    ip_head = bytes(_f_ip_packet.getlayer(IP))[0:_f_ip_packet[IP].ihl * 4]

    _f_checksum = 0
    head_len = len(ip_head)
    if head_len % 2 == 1:
        # b:signed type
        ip_head += b"\0"
    i = 0
    while i < head_len:
        temp = struct.unpack('!H', ip_head[i:i + 2])[0]
        _f_checksum = _f_checksum + temp
        i = i + 2
    # 将高16bit与低16bit相加
    _f_checksum = (_f_checksum >> 16) + (_f_checksum & 0xffff)
    # 将高16bit与低16bit再相加
    _f_checksum = _f_checksum + (_f_checksum >> 16)
    checksum2 = ~_f_checksum & 0xffff
    result = [f"0x{checksum1:04x}", f"0x{checksum2:04x}", "", ""]
    print(
        f"IP {checksum1} == {checksum2}:{checksum1 == checksum2}, {result[0]} == {result[1]}: {result[0] == result[1]}")
    if result[0] == result[1]:
        result[2] = "[Correct]"
        result[3] = "Good"
    else:
        result[2] = f"incorrect, should be {result[1]}(may be caused by 'IP checksum offload'?)"
        result[3] = "Bad"
    return result


def tcp_flags(chosen_tcp_flags):
    """TODO 获取 TCP 的 Flag 每一位的值"""
    result = {"bin": "000", "hex": "", "Reserved": "Not set", "NS": "", "CWR": "", "ECE": "", "URG": "", "ACK": "",
              "PSH": "", "RST": "", "SYN": "", "FIN": "", "result": "", "letter": ""}
    # 保留字
    # NS
    if chosen_tcp_flags & 0x100:
        result["bin"] += "1"
        result["NS"] = "Set"
        result["result"] += " NS"
        result["letter"] += "N"
    else:
        result["bin"] += "0"
        result["NS"] = "Not set"
        result["letter"] += "."
    # CWR
    if chosen_tcp_flags & 0x80:
        result["bin"] += "1"
        result["CWR"] = "Set"
        result["result"] += " CWR"
        result["letter"] += "C"
    else:
        result["bin"] += "0"
        result["CWR"] = "Not set"
        result["letter"] += "."
    # ECE
    if chosen_tcp_flags & 0x40:
        result["bin"] += "1"
        result["ECE"] = "Set"
        result["result"] += " ECE"
        result["letter"] += "E"
    else:
        result["bin"] += "0"
        result["ECE"] = "Not set"
        result["letter"] += "."
    # URG
    if chosen_tcp_flags & 0x20:
        result["bin"] += "1"
        result["URG"] = "Set"
        result["result"] += " URG"
        result["letter"] += "U"
    else:
        result["bin"] += "0"
        result["URG"] = "Not set"
        result["letter"] += "."
    # ACK
    if chosen_tcp_flags & 0x10:
        result["bin"] += "1"
        result["ACK"] = "Set"
        result["result"] += " ACK"
        result["letter"] += "A"
    else:
        result["bin"] += "0"
        result["ACK"] = "Not set"
        result["letter"] += "."
    # PSH
    if chosen_tcp_flags & 0x08:
        result["bin"] += "1"
        result["PSH"] = "Set"
        result["result"] += " PSH"
        result["letter"] += "P"
    else:
        result["bin"] += "0"
        result["PSH"] = "Not set"
        result["letter"] += "."
    # RST
    if chosen_tcp_flags & 0x04:
        result["bin"] += "1"
        result["RST"] = "Set"
        result["result"] += " RST"
        result["letter"] += "R"
    else:
        result["bin"] += "0"
        result["RST"] = "Not set"
        result["letter"] += "."
    # SYN
    if chosen_tcp_flags & 0x02:
        result["bin"] += "1"
        result["SYN"] = "Set"
        result["result"] += " SYN"
        result["letter"] += "S"
    else:
        result["bin"] += "0"
        result["SYN"] = "Not set"
        result["letter"] += "."
    # FIN
    if chosen_tcp_flags & 0x01:
        result["bin"] += "1"
        result["FIN"] = "Set"
        result["result"] += " FIN"
        result["letter"] += "F"
    else:
        result["bin"] += "0"
        result["FIN"] = "Not set"
        result["letter"] += "."
    result["result"] += " "
    result["hex"] = f"0x{int(result['bin'], 2):03x}"
    return result


def pseudo_head(tcp_or_udp):
    """TODO TCP/UDP伪首部 部分数据"""
    pseudoHead = bytes()
    if tcp_or_udp.haslayer("IP"):
        s = [i for i in (tcp_or_udp[IP].src + '.' + tcp_or_udp[IP].dst).split('.')]
        for i in range(0, 8, 2):
            pseudoHead += struct.pack('!H', int(s[i]) * 2 ** 8 + int(s[i + 1]))
    elif tcp_or_udp.haslayer('IPv6'):
        s = [i for i in (tcp_or_udp[IPv6].src + ':' + tcp_or_udp[IPv6].dst).split(':')]
        for i in s:
            i = (4 - len(i)) * '0' + i
            pseudoHead += struct.pack('!H',
                                      HEX[i[0]] * 4096 +
                                      HEX[i[1]] * 256 +
                                      HEX[i[2]] * 16 +
                                      HEX[i[3]])
    return pseudoHead


def tcp_len(tcp_packet):
    """TODO tcp 长度"""
    if tcp_packet[TCP].haslayer('Padding'):
        length = len(tcp_packet[TCP].payload) - len(tcp_packet[Padding].load)
    else:
        length = len(tcp_packet[TCP].payload)
    return length


def tcp_checksum(tcp_packet):
    """TODO tcp校验和"""
    _f_tcp_packet = copy.deepcopy(tcp_packet)  # 使用深拷贝，以免影响原数据包
    checksum1 = _f_tcp_packet[TCP].chksum

    new_code = bytes()
    _f_tcp_packet[TCP].chksum = 0
    new_code += pseudo_head(_f_tcp_packet) + \
        struct.pack('!H', 6) + \
        struct.pack('!H', _f_tcp_packet[TCP].dataofs * 4 + tcp_len(_f_tcp_packet)) + \
        bytes(_f_tcp_packet.getlayer(TCP))[0:_f_tcp_packet[TCP].dataofs * 4 + tcp_len(_f_tcp_packet)]

    _f_checksum = 0
    code_len = len(new_code)
    if code_len % 2 == 1:
        # b:signed type
        new_code += b"\0"
    i = 0
    while i < code_len:
        temp = struct.unpack('!H', new_code[i:i + 2])[0]
        _f_checksum = _f_checksum + temp
        i = i + 2
    # 将高16bit与低16bit相加
    _f_checksum = (_f_checksum >> 16) + (_f_checksum & 0xffff)
    # 将高16bit与低16bit再相加
    _f_checksum = _f_checksum + (_f_checksum >> 16)
    checksum2 = ~_f_checksum & 0xffff

    result = [f"0x{checksum1:04x}", f"0x{checksum2:04x}", "", ""]
    print(
        f"{checksum1} == {checksum2}:{checksum1 == checksum2}, {result[0]} == {result[1]}: {result[0] == result[1]}")
    if result[0] == result[1]:
        result[2] = "[Correct]"
        result[3] = "Good"
    else:
        result[2] = f"incorrect, should be {result[1]}(may be caused by 'TCP checksum offload'?)"
        result[3] = "Bad"
    return result


def udp_checksum(udp_packet):
    """TODO udp校验和"""
    result_string = ""
    checksum1 = udp_packet[UDP].chksum
    if checksum1 == 0:
        result_string = "  Checksum: 0x0000[zero - value ignored]\n"
    else:
        _f_udp_packet = copy.deepcopy(udp_packet)  # 使用深拷贝，以免影响原数据包

        new_code = bytes()
        _f_udp_packet[UDP].chksum = 0
        new_code += pseudo_head(_f_udp_packet) + \
            struct.pack('!H', 17) + \
            struct.pack('!H', _f_udp_packet[UDP].len) + \
            bytes(_f_udp_packet.getlayer(UDP))[0:_f_udp_packet[UDP].len]

        _f_checksum = 0
        code_len = len(new_code)
        if code_len % 2 == 1:
            # b:signed type
            new_code += b"\0"
        i = 0
        while i < code_len:
            temp = struct.unpack('!H', new_code[i:i + 2])[0]
            _f_checksum = _f_checksum + temp
            i = i + 2
        # 将高16bit与低16bit相加
        _f_checksum = (_f_checksum >> 16) + (_f_checksum & 0xffff)
        # 将高16bit与低16bit再相加
        _f_checksum = _f_checksum + (_f_checksum >> 16)
        checksum2 = ~_f_checksum & 0xffff

        result = [f"0x{checksum1:04x}", f"0x{checksum2:04x}", "", ""]
        print(
            f"UDP {checksum1} == {checksum2}:{checksum1 == checksum2}, {result[0]} == {result[1]}: {result[0] == result[1]}")
        if result[0] == result[1]:
            result[2] = "[Correct]"
            result[3] = "Good"
        else:
            result[2] = f"incorrect, should be {result[1]}(may be caused by 'UDP checksum offload'?)"
            result[3] = "Bad"
        result_string += f"  Checksum: {result[0]} {result[2]}\n"
        result_string += f"  [Checksum Status: {result[3]}]\n"
        result_string += f"  [Calculated Checksum: {result[1]}]\n"
    return result_string


def icmp_checksum(icmp_packet):
    """TODO icmp校验和"""
    _f_icmp_packet = copy.deepcopy(icmp_packet)  # 使用深拷贝，以免影响原数据包
    # 计算检验和
    checksum1 = _f_icmp_packet[ICMP].chksum

    _f_icmp_packet[ICMP].chksum = 0
    ICMP_codes = bytes(_f_icmp_packet.getlayer(ICMP))[:]

    _f_checksum = 0
    code_len = len(ICMP_codes)
    if code_len % 2 == 1:
        # b:signed type
        ICMP_codes += b"\0"
    i = 0
    while i < code_len:
        temp = struct.unpack('!H', ICMP_codes[i:i + 2])[0]
        _f_checksum = _f_checksum + temp
        i = i + 2
    # 将高16bit与低16bit相加
    _f_checksum = (_f_checksum >> 16) + (_f_checksum & 0xffff)
    # 将高16bit与低16bit再相加
    _f_checksum = _f_checksum + (_f_checksum >> 16)
    checksum2 = ~_f_checksum & 0xffff
    result = [f"0x{checksum1:04x}", f"0x{checksum2:04x}", "", ""]
    print(
        f"ICMP {checksum1} == {checksum2}:{checksum1 == checksum2}, {result[0]} == {result[1]}: {result[0] == result[1]}")
    if result[0] == result[1]:
        result[2] = "[Correct]"
        result[3] = "Good"
    else:
        result[2] = f"[incorrect]"
        result[3] = "Bad"
    return result


def dns_flags(dns_packet):
    """TODO dns flags"""
    result_string = ""
    flags = ""
    # 1.qr 表示DNS报文的类型，0表示查询报文，1表示响应报文
    if dns_packet[DNS].qr == 0:
        flags += "0"
        result_string += "    0... .... .... .... = Response: Message is a query\n"
    else:
        flags += "1"
        result_string += "    1... .... .... .... = Response: Message is a response\n"
    # 2.opcode DNS请求或响应的操作码（Operation Code），用于指示DNS报文的操作类型
    flags += f"{dns_packet[DNS].opcode:04b}"
    result_string += f"    .{str(int_bin(dns_packet[DNS].opcode, 4))[0:3]} {str(int_bin(dns_packet[DNS].opcode, 4))[3]}... .... .... = Opcode: {DNS_OPCODE_TYPES[dns_packet[DNS].opcode]} ({dns_packet[DNS].opcode})\n"
    # 3.aa 表示DNS报文的aa（Authoritative Answer）标志位，值为1时表示DNS服务器的回答是权威性的，即该服务器是最终的服务器
    if dns_packet[DNS].aa == 0:
        flags += "0"
        if dns_packet[DNS].qr == 1:
            result_string += "    .... .0.. .... .... = Authoritative: Server is not an authority for domain\n"
    else:
        flags += "1"
        if dns_packet[DNS].qr == 1:
            result_string += "    .... .1.. .... .... = Authoritative: Server is an authority for domain\n"
    # 4.tc 表示DNS报文的tc（TrunCation）标志位，值为1时表示DNS报文中包含的资源数据被截断，该标志位用于提示DNS服务器的客户端，应该将后续的数据包发送给其他DNS服务器
    if dns_packet[DNS].tc == 0:
        flags += "0"
        result_string += "    .... ..0. .... .... = Truncated: Message is not truncated\n"
    else:
        flags += "1"
        result_string += "    .... ..1. .... .... = Truncated: Message is truncated\n"
    # 5.rd 当 rd 为1时，表示DNS客户端要求递归查询,当 rd 为0时，表示DNS客户端不要求递归查询
    if dns_packet[DNS].rd == 0:
        flags += "0"
        result_string += "    .... ...0 .... .... = Recursion desired: Do query recursively\n"
    else:
        flags += "1"
        result_string += "    .... ...1 .... .... = Recursion desired: Do query recursively\n"
    # 6.ra 表示DNS报文的ra（Recursion available）标志位，值为1时表示DNS服务器支持递归查询，值为0时表示DNS服务器不支持递归查询
    if dns_packet[DNS].ra == 0:
        flags += "0"
        if dns_packet[DNS].qr == 1:
            result_string += "    .... .... 0... .... = Recursion available: Not available\n"
    else:
        flags += "1"
        if dns_packet[DNS].qr == 1:
            result_string += "    .... .... 1... .... = Recursion available: Server can do recursive queries\n"
    # 7.z 保留位，必须置为0
    flags += "0"
    result_string += "    .... .... .0.. .... = Z: reserved (0)\n"
    # 8.ad 当 ad 为0时，表示响应中的数据未经过 DNSSEC（DNS Security Extensions）验证。当 ad 为1时，表示响应中的数据已经通过 DNSSEC 验证
    if dns_packet[DNS].ad == 0:
        flags += "0"
        if dns_packet[DNS].qr == 1:
            result_string += "    .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server\n"
    else:
        flags += "1"
        if dns_packet[DNS].qr == 1:
            result_string += "    .... .... ..1. .... = Answer authenticated: Answer/authority portion was authenticated by the server\n"
    # 9.cd 当 cd 为0时，表示DNS客户端要求进行DNSSEC（DNS Security Extensions）验证。当 cd 为1时，表示DNS客户端不要求DNSSEC验证
    if dns_packet[DNS].cd == 0:
        flags += "0"
        result_string += "    .... .... ...0 .... = Non-authenticated data: Unacceptable\n"
    else:
        flags += "1"
        result_string += "    .... .... ...1 .... = Non-authenticated data: Acceptable\n"
    # 10.rcode rcode 属性表示 DNS 响应码（Response Code），用于指示 DNS 响应的状态或结果
    flags += f"{dns_packet[DNS].rcode:04b}"
    if dns_packet[DNS].qr == 1:
        result_string += f"    .... .... .... 0000 = Reply code: {DNS_RCODE_TYPES[dns_packet[DNS].rcode]} ({dns_packet[DNS].rcode})\n"

    if dns_packet[DNS].qr == 0:
        result_string = f"  Flags: 0x{int(flags, 2):04x} {DNS_OPCODE_TYPES[dns_packet[DNS].opcode]}\n" + result_string
    else:
        result_string = f"  Flags: 0x{int(flags, 2):04x} {DNS_OPCODE_TYPES[dns_packet[DNS].opcode]} response, {DNS_RCODE_TYPES[dns_packet[DNS].rcode]}\n" + result_string
    return result_string
