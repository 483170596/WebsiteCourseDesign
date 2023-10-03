from tools import *
from scapy.all import *
from tkinter import *
import threading
import tkinter.messagebox as messagebox
import datetime


# 启动捕获线程
def start_sniff(app):
    if app.sniffFlag is True:
        answer = messagebox.askyesnocancel(title='确认窗口', message="是否开始报文捕获？")
        if answer is False:
            print("停止报文捕获！")
            return
        elif answer is True:
            print("开始新的报文捕获！")
            app.startListenButton["state"] = 'disabled'
            app.stopListenButton["state"] = 'normal'
            app.sniffFlag = False
            if app.startListenButton['text'] == '开始捕获':
                t = threading.Thread(target=lambda: pdu_sniff(app), name='LoopThread')
                t.start()
                print(threading.current_thread().name + ' 1')
    """
    https://blog.csdn.net/briblue/article/details/85101144
    """


# 停止捕获线程
def stop_sniff(app):
    app.startListenButton["state"] = 'normal'
    app.stopListenButton["state"] = 'disable'
    app.sniffFlag = True
    app.count = 0
    app.countAct = 0


# 捕获线程，捕获数据报，并调用回调函数
def pdu_sniff(app):
    app.count = int(app.countInput.get())
    if app.count == 0:
        app.count = float('inf')  # 无穷
    """sniff(filter='arp or ip or ip6 or tcp or udp',
    prn=(lambda x: self.ip_monitor_callback(x)),
    stop_filter=(lambda x: self.sniffFlag),
    store=0,
    iface='WLAN')
    指定无线网卡 一定要加filter='arp or ip or ip6 or tcp or udp'参数，协议名称一定要小写，否则无法顺利抓包
    (filter BPF过滤规则 BPF：柏克莱封包过滤器（Berkeley Packet Filter，缩写BPF），
    是类Unix系统上数据链路层的一种原始接口，提供原始链路层封包的收发。)
    回调函数：一个高层调用底层，底层再回过头来调用高层的过程。
    Scapy Sniffer的filter语法：https://blog.csdn.net/qwertyupoiuytr/article/details/54670477
    有时候TCP和UDP校验和会由网卡计算(https://blog.csdn.net/weixin_34308389/article/details/93114074)，
    因此wireshark抓到的本机发送的TCP/UDP数据包的校验和都是错误的，这样检验校验和根本没有意义。所以Wireshark不自动做TCP和UDP校验和的校验。
    如果要校验校验和：可以在edit->preference->protocols中选择相应的TCP或者UDP协议，在相应的地方打钩。
    Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html"""
    sniff(filter="arp or ip or ip6 or tcp or udp", prn=(lambda x: ip_monitor_callback(app, x)),
          stop_filter=(lambda x: app.sniffFlag),
          store=0)
    """iface=None 则代表所有网卡
    filter="arp or ip or ip6 or tcp or udp" 可选值：
    ether, fddi, tr, wlan, ip, ip6, arp, rarp, decnet, tcp, udp, icmp
    (fddi, tr, wlan是ether的别名, 包结构很类似)
    https://www.cnblogs.com/cheuhxg/p/15043117.html
    sniff(prn=self.ip_monitor_callback, stop_filter=self.sniffFlag, store=0)
    Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html"""


# 回调函数，根据筛选条件调用不同的分析函数
def ip_monitor_callback(app, pkt):
    print(pkt.show())
    print("pkt`s type = " + str(type(pkt)))
    pktSummaryInfo = str(app.countAct) + ' ' + pkt.summary()
    # TODO IPv6 回调函数，根据筛选条件调用不同的分析函数 注意IPv6要放在IP前面，否则会直接去判断IP
    if app.conditionInput.get().find('IPv6') != -1:
        src_IP = ''
        dst_IP = ''
        if pkt.haslayer('IPv6') and app.countAct < app.count:
            split_conditions = split_condition(app)
            for split_con in split_conditions:
                if split_con.find('src') != -1:
                    src_IP = split_dul_equal(split_con)
                if split_con.find('dst') != -1:
                    dst_IP = split_dul_equal(split_con)
            if src_IP != '' and dst_IP != '':
                if pkt['IPv6'].src == src_IP and pkt['IPv6'].dst == dst_IP:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP != '' and dst_IP == '':
                if pkt['IPv6'].src == src_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP == '' and dst_IP != '':
                if pkt['IPv6'].dst == dst_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP == '' and dst_IP == '':
                app.sniffDataList.append(pkt)
                app.listbox.insert(END, pktSummaryInfo)
                app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    # TODO DNS 回调函数，根据筛选条件调用不同的分析函数
    elif app.conditionInput.get().find('DNS') != -1:
        if pkt.haslayer('DNS') and app.countAct < app.count:
            app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
            app.listbox.insert(END, pktSummaryInfo)
            app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    elif app.conditionInput.get().find('IP') != -1:
        src_IP = ''
        dst_IP = ''
        proto_IP = ''
        if pkt.haslayer('IP') and app.countAct < app.count:
            split_conditions = split_condition(app)
            for split_con in split_conditions:
                if split_con.find('src') != -1:
                    src_IP = split_dul_equal(split_con)
                if split_con.find('dst') != -1:
                    dst_IP = split_dul_equal(split_con)
                if split_con.find('proto') != -1:
                    proto_IP = int(split_dul_equal(split_con))
            if src_IP != '' and dst_IP != '' and proto_IP != '':
                if pkt['IP'].src == src_IP and pkt['IP'].dst == dst_IP and pkt['IP'].proto == proto_IP:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP != '' and dst_IP != '' and proto_IP == '':
                if pkt['IP'].src == src_IP and pkt['IP'].dst == dst_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP != '' and dst_IP == '' and proto_IP != '':
                if pkt['IP'].src == src_IP and pkt['IP'].proto == proto_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP == '' and dst_IP != '' and proto_IP != '':
                if pkt['IP'].dst == dst_IP and pkt['IP'].proto == proto_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP != '' and dst_IP == '' and proto_IP == '':
                if pkt['IP'].src == src_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP == '' and dst_IP == '' and proto_IP != '':
                if pkt['IP'].proto == proto_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP == '' and dst_IP != '' and proto_IP == '':
                if pkt['IP'].dst == dst_IP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_IP == '' and dst_IP == '' and proto_IP == '':
                app.sniffDataList.append(pkt)
                app.listbox.insert(END, pktSummaryInfo)
                app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    elif app.conditionInput.get().find('ARP') != -1:
        hwsrc_ARP = ''
        hwdst_ARP = ''
        psrc_ARP = ''
        pdst_ARP = ''
        op_ARP = ''
        if pkt.haslayer('ARP') and app.countAct < app.count:
            split_conditions = split_condition(app)
            for split_con in split_conditions:
                if split_con.find('hwsrc') != -1:
                    hwsrc_ARP = split_dul_equal(split_con)
                if split_con.find('hwdst') != -1:
                    hwdst_ARP = split_dul_equal(split_con)
                if split_con.find('psrc') != -1:
                    psrc_ARP = split_dul_equal(split_con)
                if split_con.find('pdst') != -1:
                    pdst_ARP = split_dul_equal(split_con)
                if split_con.find('op') != -1:
                    op_ARP = split_dul_equal(split_con)
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and \
                        pkt[
                            'ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and \
                        pkt[
                            'ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and \
                        pkt[
                            'ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP and \
                        pkt[
                            'ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and \
                        pkt[
                            'ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                    'ARP'].psrc == psrc_ARP and \
                        pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].op == op_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                if pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                if pkt['ARP'].pdst == pdst_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                if pkt['ARP'].psrc == psrc_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                if pkt['ARP'].hwdst == hwdst_ARP:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                if pkt['ARP'].hwsrc == hwsrc_ARP:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                if pkt['ARP'].op == op_ARP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                app.sniffDataList.append(pkt)
                app.listbox.insert(END, pktSummaryInfo)
                app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    elif app.conditionInput.get().find('Ether') != -1:
        src_Ether = ''
        dst_Ether = ''
        if pkt.haslayer('Ether') and app.countAct < app.count:
            split_conditions = split_condition(app)
            for split_con in split_conditions:
                if split_con.find('src') != -1:
                    src_Ether = split_dul_equal(split_con)
                if split_con.find('dst') != -1:
                    dst_Ether = split_dul_equal(split_con)
            if src_Ether != '' and dst_Ether != '':
                if pkt['Ether'].src == src_Ether and pkt['Ether'].dst == dst_Ether:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_Ether != '' and dst_Ether == '':
                if pkt['Ether'].src == src_Ether:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_Ether == '' and dst_Ether != '':
                if pkt['Ether'].dst == dst_Ether:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if src_Ether == '' and dst_Ether == '':
                app.sniffDataList.append(pkt)
                app.listbox.insert(END, pktSummaryInfo)
                app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    elif app.conditionInput.get().find('TCP') != -1:
        sport_TCP = ''
        dport_TCP = ''
        if pkt.haslayer('TCP') and app.countAct < app.count:
            split_conditions = split_condition(app)
            for split_con in split_conditions:
                if split_con.find('sport') != -1:
                    sport_TCP = int(split_dul_equal(split_con))
                if split_con.find('dport') != -1:
                    dport_TCP = int(split_dul_equal(split_con))
            if sport_TCP != '' and dport_TCP != '':
                if pkt['TCP'].sport == sport_TCP and pkt['TCP'].dport == dport_TCP:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if sport_TCP != '' and dport_TCP == '':
                if pkt['TCP'].sport == sport_TCP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if sport_TCP == '' and dport_TCP != '':
                if pkt['TCP'].dport == dport_TCP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if sport_TCP == '' and dport_TCP == '':
                app.sniffDataList.append(pkt)
                app.listbox.insert(END, pktSummaryInfo)
                app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    elif app.conditionInput.get().find('UDP') != -1:
        sport_UDP = ''
        dport_UDP = ''
        if pkt.haslayer('UDP') and app.countAct < app.count:
            split_conditions = split_condition(app)
            for split_con in split_conditions:
                if split_con.find('sport') != -1:
                    sport_UDP = int(split_dul_equal(split_con))
                if split_con.find('dport') != -1:
                    dport_UDP = int(split_dul_equal(split_con))
            if sport_UDP != '' and dport_UDP != '':
                if pkt['UDP'].sport == sport_UDP and pkt['UDP'].dport == dport_UDP:
                    app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if sport_UDP != '' and dport_UDP == '':
                if pkt['UDP'].sport == sport_UDP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if sport_UDP == '' and dport_UDP != '':
                if pkt['UDP'].dport == dport_UDP:
                    app.sniffDataList.append(pkt)
                    app.listbox.insert(END, pktSummaryInfo)
                    app.countAct += 1
            if sport_UDP == '' and dport_UDP == '':
                app.sniffDataList.append(pkt)
                app.listbox.insert(END, pktSummaryInfo)
                app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    # TODO ICMP 回调函数，根据筛选条件调用不同的分析函数
    elif app.conditionInput.get().find('ICMP') != -1:
        if pkt.haslayer('ICMP') and app.countAct < app.count:
            app.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
            app.listbox.insert(END, pktSummaryInfo)
            app.countAct += 1
        if app.countAct == app.count:
            stop_sniff(app)

    else:
        if app.count > app.countAct:
            app.countAct += 1
            app.sniffDataList.append(pkt)
            app.listbox.insert(END, pktSummaryInfo)
    app.sniff_times.append(datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))  # 捕获时间
    print(threading.current_thread().name + ' 2')
    # https://blog.csdn.net/briblue/article/details/85101144
    # time.sleep(1) # 最好不要延时，否则好多包抓不到
