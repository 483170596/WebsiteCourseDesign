import copy
import datetime
from tkinter.ttk import Combobox
from common.constants.CommonConstants import *
import scapy.utils
from scapy.all import *
from tkinter import *
import tkinter as tk
import threading
import tkinter.messagebox as messagebox
import datetime

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, TCP, in4_chksum, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP


# 对应进制转换
def intbin(n, count, is_split=False):
    # 添加可选字段：是否四位一隔
    """returns the binary of integer n, using count number of digits"""
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


# 大端字节序转为小端字节序
def swap_endianness(n):
    return ((n >> 8) & 0x00FF) | ((n << 8) & 0xFF00)


class Application(tk.Tk):
    # 初始化
    def __init__(self):
        tk.Tk.__init__(self)
        self.sniffDataList = []
        self.createWidgets()
        self.sniffFlag = True  # 设置控制捕获线程运行的标志变量
        self.sniff_times = []

    # 创建分析器界面
    def createWidgets(self):
        self.geometry('1080x800')  # 设置宽高
        self.title('协议分析器')
        self.count = 0  # 记录捕获数据帧的个数
        self.countAct = 0  # 实际捕获数据帧的个数
        # 创建并添加协议分析器控制组件及面板
        self.createControlWidgets()
        # 创建并添加协议分析主面板
        self.mainPDUShowWindow = PanedWindow(self, orient=tk.VERTICAL, sashrelief=RAISED, sashwidth=5)
        '''
        创建并添加协议分析各动态窗口，包括：
         协议摘要信息窗口PDUSumPanedWindow
         协议详细解析窗口PDUAnalysisPanedWindow
         协议报文编码窗口PDUCodePanedWindow
         '''
        self.createPDUSumPanedWindow()
        self.createPDUAnalysisPanedWindow()
        self.createPDUCodePanedWindow()
        self.mainPDUShowWindow.pack(fill=BOTH, expand=1)

    # 创建控制面板
    def createControlWidgets(self):
        # 创建控制面板
        controlFrame = Frame()
        self.countLabel = Label(controlFrame, text='请输入待捕获的数据帧数：')
        self.countLabel.pack()
        countvar = StringVar(value='0')
        self.countInput = Entry(controlFrame, textvariable=countvar, width=6)
        self.countInput.pack()
        self.conditionLabel = Label(controlFrame, text='请输入捕获条件：')
        self.conditionLabel.pack()
        self.conditionInput = Entry(controlFrame, width=60)
        self.conditionInput.pack()
        # 在创建控制面板设置startListenButton按键
        self.startListenButton = Button(controlFrame, text='开始捕获', command=self.start_sniff)
        self.startListenButton.pack()
        # 在创建控制面板放置clearButton按钮
        self.clearButton = Button(controlFrame, text='清空数据', command=self.clearData)
        self.clearButton.pack()
        # 在创建控制面板放置stopListenButton按钮
        self.stopListenButoon = Button(controlFrame, text='停止捕获', command=self.stop_sniff)
        self.stopListenButoon.pack()
        controlFrame.pack(side=TOP, fill=Y)

    # 创建显示捕获报文的摘要的窗口
    def createPDUSumPanedWindow(self):
        PDUSumFrame = Frame()
        yScroll = Scrollbar(PDUSumFrame, orient=VERTICAL)
        xScroll = Scrollbar(PDUSumFrame, orient=HORIZONTAL)
        # 创建列表框显示捕获报文的摘要
        self.listbox = tk.Listbox(PDUSumFrame,
                                  xscrollcommand=xScroll.set,
                                  yscrollcommand=yScroll.set)
        xScroll['command'] = self.listbox.xview
        yScroll['command'] = self.listbox.yview
        # 显示波动条
        yScroll.pack(side=RIGHT, fill=Y)
        xScroll.pack(side=BOTTOM, fill=X)
        # 关联用户选择报文进行详细解析的事件
        self.listbox.bind('<Double-ButtonPress>', self.choosedPDUAnalysis)
        self.listbox.pack(fill=BOTH)
        PDUSumFrame.pack(fill=BOTH)
        self.mainPDUShowWindow.add(PDUSumFrame)

    # 创建显示捕获报文分层解析的窗口
    def createPDUAnalysisPanedWindow(self):
        PDUAnalysisFrame = Frame()
        self.PDUAnalysisText = Text(PDUAnalysisFrame)
        # TODO 创建显示捕获报文分层解析的窗口
        # 添加滚动条
        s1 = Scrollbar(PDUAnalysisFrame, orient=VERTICAL)
        s1.pack(side=RIGHT, fill=Y)
        s1.config(command=self.PDUAnalysisText.yview)
        self.PDUAnalysisText['yscrollcommand'] = s1.set
        # 显示组件
        self.PDUAnalysisText.pack(fill=BOTH)
        self.mainPDUShowWindow.add(PDUAnalysisFrame)

    # 创建显示捕获报文原始编码信息的窗口
    def createPDUCodePanedWindow(self):
        # 创建显示捕获数据的窗口
        PDUCodeFrame = Frame()
        # 创建显示捕获数据的文本框
        self.PDUCodeText = Text(PDUCodeFrame)
        # TODO 创建显示捕获报文原始编码信息的窗口
        # 创建一个纵向滚动的滚动条，铺满Y方向
        s1 = Scrollbar(PDUCodeFrame, orient=VERTICAL)
        s1.pack(side=RIGHT, fill=Y)
        s1.config(command=self.PDUCodeText.yview)
        self.PDUCodeText['yscrollcommand'] = s1.set
        self.PDUCodeText.pack(fill=BOTH)
        self.mainPDUShowWindow.add(PDUCodeFrame)

    # 启动捕获线程
    def start_sniff(self):
        if self.sniffFlag is True:
            answer = messagebox.askyesnocancel(title='确认窗口', message="是否开始报文捕获？")
            if answer is False:
                print("停止报文捕获！")
                return
            elif answer is True:
                print("开始新的报文捕获！")
                self.startListenButton["state"] = 'disabled'
                self.stopListenButoon["state"] = 'normal'
                self.sniffFlag = False
                if self.startListenButton['text'] == '开始捕获':
                    t = threading.Thread(target=self.PDU_sniff, name='LoopThread')
                    t.start()
                    print(threading.current_thread().name + ' 1')
                    # https://blog.csdn.net/briblue/article/details/85101144

    # 捕获线程，捕获数据报，并调用回调函数
    def PDU_sniff(self):
        self.count = int(self.countInput.get())
        if self.count == 0:
            self.count = float('inf')  # 无穷
        # sniff(filter='arp or ip or ip6 or tcp or udp',
        # prn=(lambda x: self.ip_monitor_callback(x)),
        # stop_filter=(lambda x: self.sniffFlag),
        # store=0,
        # iface='WLAN')
        # 指定无线网卡 一定要加filter='arp or ip or ip6 or tcp or udp'参数，
        # 协议名称一定要小写，否则无法顺利抓包
        # (filter BPF过滤规则 BPF：柏克莱封包过滤器（Berkeley Packet Filter，缩写BPF），
        # 是类Unix系统上数据链路层的一种原始接口，提供原始链路层封包的收发。)
        # 回调函数：一个高层调用底层，底层再回过头来调用高层的过程。
        # Scapy Sniffer的filter语法：
        # https://blog.csdn.net/qwertyupoiuytr/article/details/54670477
        # 有时候TCP和UDP校验和会由网卡计算(https://blog.csdn.net/weixin_34308389/article/details/93114074)
        # ，因此wireshark抓到的本机发送的TCP/UDP数据包的校验和都是错误的，这样检验校验和根本没有意义。
        # 所以Wireshark不自动做TCP和UDP校验和的校验。
        # 如果要校验校验和：可以在edit->preference->protocols中选择相应的TCP或者UDP协议，在相应的地方打钩。
        # Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html
        sniff(filter="arp or ip or ip6 or tcp or udp", prn=(lambda x: self.ip_monitor_callback(x)),
              stop_filter=(lambda x: self.sniffFlag),
              store=0)
        # iface=None 则代表所有网卡
        # filter="arp or ip or ip6 or tcp or udp" 可选值：
        # ether, fddi, tr, wlan, ip, ip6, arp, rarp, decnet, tcp, udp, icmp
        # (fddi, tr, wlan是ether的别名, 包结构很类似)
        # https://www.cnblogs.com/cheuhxg/p/15043117.html
        # sniff(prn=self.ip_monitor_callback, stop_filter=self.sniffFlag, store=0)
        # Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html

    # 停止捕获线程
    def stop_sniff(self):
        self.startListenButton["state"] = 'normal'
        self.stopListenButoon["state"] = 'disable'
        self.sniffFlag = True
        self.count = 0
        self.countAct = 0

    # 清空捕获数据
    def clearData(self):
        if self.sniffFlag is True:
            self.listbox.delete(0, END)
            self.sniffDataList = []
            self.PDUAnalysisText.delete(1.0, END)
            self.PDUCodeText.delete(1.0, END)
            self.count = 0
            self.countAct = 0
        else:
            messagebox.showinfo(title='友情提示', message="请先停止捕获！！")

    # 分割条件的函数
    def split_condition(self):
        conditionString = self.conditionInput.get()
        splitList = conditionString.split(' ')
        splitStrings = []
        for conString in splitList:
            splitStrings.append(conString)
        return splitStrings

    # 分割条件的函数，分别是按空格和==分割
    def split_dulequal(self, dul):  # 按照等号划分后获得筛选的条件
        splitList = dul.split('==')
        return splitList[1]

    # 回调函数，根据筛选条件调用不同的分析函数
    def ip_monitor_callback(self, pkt):
        print(pkt.show())
        print("pkt`s type = " + str(type(pkt)))
        pktSummaryInfo = str(self.countAct) + ' ' + pkt.summary()
        # TODO IPv6 回调函数，根据筛选条件调用不同的分析函数 注意IPv6要放在IP前面，否则会直接去判断IP
        if self.conditionInput.get().find('IPv6') != -1:
            src_IP = ''
            dst_IP = ''
            if pkt.haslayer('IPv6') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('src') != -1:
                        src_IP = self.split_dulequal(split_con)
                    if split_con.find('dst') != -1:
                        dst_IP = self.split_dulequal(split_con)
                if src_IP != '' and dst_IP != '':
                    if pkt['IPv6'].src == src_IP and pkt['IPv6'].dst == dst_IP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP != '' and dst_IP == '':
                    if pkt['IPv6'].src == src_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP != '':
                    if pkt['IPv6'].dst == dst_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        # TODO DNS 回调函数，根据筛选条件调用不同的分析函数
        elif self.conditionInput.get().find('DNS') != -1:
            if pkt.haslayer('DNS') and self.countAct < self.count:
                self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                self.listbox.insert(END, pktSummaryInfo)
                self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('IP') != -1:
            src_IP = ''
            dst_IP = ''
            proto_IP = ''
            if pkt.haslayer('IP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('src') != -1:
                        src_IP = self.split_dulequal(split_con)
                    if split_con.find('dst') != -1:
                        dst_IP = self.split_dulequal(split_con)
                    if split_con.find('proto') != -1:
                        proto_IP = int(self.split_dulequal(split_con))
                if src_IP != '' and dst_IP != '' and proto_IP != '':
                    if pkt['IP'].src == src_IP and pkt['IP'].dst == dst_IP and pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP != '' and dst_IP != '' and proto_IP == '':
                    if pkt['IP'].src == src_IP and pkt['IP'].dst == dst_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP != '' and dst_IP == '' and proto_IP != '':
                    if pkt['IP'].src == src_IP and pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP != '' and proto_IP != '':
                    if pkt['IP'].dst == dst_IP and pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP != '' and dst_IP == '' and proto_IP == '':
                    if pkt['IP'].src == src_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP == '' and proto_IP != '':
                    if pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP != '' and proto_IP == '':
                    if pkt['IP'].dst == dst_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP == '' and proto_IP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('ARP') != -1:
            hwsrc_ARP = ''
            hwdst_ARP = ''
            psrc_ARP = ''
            pdst_ARP = ''
            op_ARP = ''
            if pkt.haslayer('ARP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('hwsrc') != -1:
                        hwsrc_ARP = self.split_dulequal(split_con)
                    if split_con.find('hwdst') != -1:
                        hwdst_ARP = self.split_dulequal(split_con)
                    if split_con.find('psrc') != -1:
                        psrc_ARP = self.split_dulequal(split_con)
                    if split_con.find('pdst') != -1:
                        pdst_ARP = self.split_dulequal(split_con)
                    if split_con.find('op') != -1:
                        op_ARP = self.split_dulequal(split_con)
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and \
                            pkt[
                                'ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and \
                            pkt[
                                'ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and \
                            pkt[
                                'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP and \
                            pkt[
                                'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and \
                            pkt[
                                'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                        'ARP'].psrc == psrc_ARP and \
                            pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('Ether') != -1:
            src_Ether = ''
            dst_Ether = ''
            if pkt.haslayer('Ether') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('src') != -1:
                        src_Ether = self.split_dulequal(split_con)
                    if split_con.find('dst') != -1:
                        dst_Ether = self.split_dulequal(split_con)
                if src_Ether != '' and dst_Ether != '':
                    if pkt['Ether'].src == src_Ether and pkt['Ether'].dst == dst_Ether:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_Ether != '' and dst_Ether == '':
                    if pkt['Ether'].src == src_Ether:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_Ether == '' and dst_Ether != '':
                    if pkt['Ether'].dst == dst_Ether:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_Ether == '' and dst_Ether == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('TCP') != -1:
            sport_TCP = ''
            dport_TCP = ''
            if pkt.haslayer('TCP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('sport') != -1:
                        sport_TCP = int(self.split_dulequal(split_con))
                    if split_con.find('dport') != -1:
                        dport_TCP = int(self.split_dulequal(split_con))
                if sport_TCP != '' and dport_TCP != '':
                    if pkt['TCP'].sport == sport_TCP and pkt['TCP'].dport == dport_TCP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_TCP != '' and dport_TCP == '':
                    if pkt['TCP'].sport == sport_TCP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_TCP == '' and dport_TCP != '':
                    if pkt['TCP'].dport == dport_TCP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_TCP == '' and dport_TCP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('UDP') != -1:
            sport_UDP = ''
            dport_UDP = ''
            if pkt.haslayer('UDP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('sport') != -1:
                        sport_UDP = int(self.split_dulequal(split_con))
                    if split_con.find('dport') != -1:
                        dport_UDP = int(self.split_dulequal(split_con))
                if sport_UDP != '' and dport_UDP != '':
                    if pkt['UDP'].sport == sport_UDP and pkt['UDP'].dport == dport_UDP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_UDP != '' and dport_UDP == '':
                    if pkt['UDP'].sport == sport_UDP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_UDP == '' and dport_UDP != '':
                    if pkt['UDP'].dport == dport_UDP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_UDP == '' and dport_UDP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        # TODO ICMP 回调函数，根据筛选条件调用不同的分析函数
        elif self.conditionInput.get().find('ICMP') != -1:
            if pkt.haslayer('ICMP') and self.countAct < self.count:
                self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                self.listbox.insert(END, pktSummaryInfo)
                self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        else:
            if self.count > self.countAct:
                self.countAct += 1
                self.sniffDataList.append(pkt)
                self.listbox.insert(END, pktSummaryInfo)
        self.sniff_times.append(datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))  # 捕获时间
        print(threading.current_thread().name + ' 2')
        # https://blog.csdn.net/briblue/article/details/85101144
        # time.sleep(1) # 最好不要延时，否则好多包抓不到

    # 对选择的报文，判断其协议调用不同的分析函数
    def choosedPDUAnalysis(self, event):
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        sniff_time = self.sniff_times[choosePDUNum]
        self.PDUAnalysisText.delete('1.0', 'end')
        self.PDUCodeText.delete('1.0', 'end')  # 清空PDUAnalysisText，PDUCodeText控件内容
        # TODO IPv6 对选择的报文，判断其协议调用不同的分析函数
        if self.conditionInput.get().find('IPv6') != -1:
            self.choosedIPv6PDUAnalysis(choosedPacket)
        # TODO DNS 对选择的报文，判断其协议调用不同的分析函数
        elif self.conditionInput.get().find('DNS') != -1:
            self.choosedDNSPDUAnalysis(choosedPacket)
        elif self.conditionInput.get().find('ARP') != -1:
            self.choosedARPPDUAnalysis(choosedPacket, sniff_time)
        elif self.conditionInput.get().find('Ether') != -1:  # 以太网MAC协议
            self.choosedEtherPDUAnalysis(choosedPacket)
        elif self.conditionInput.get().find('TCP') != -1:
            self.choosedTCPPDUAnalysis(choosedPacket)
        elif self.conditionInput.get().find('UDP') != -1:
            self.choosedUDPPDUAnalysis(choosedPacket)
        # TODO ICMP对选择的报文，判断其协议调用不同的分析函数
        elif self.conditionInput.get().find('ICMP') != -1:
            self.choosedICMPPDUAnalysis(choosedPacket)
        elif self.conditionInput.get().find('IP') != -1:
            self.choosedIPPDUAnalysis(choosedPacket)
        elif self.conditionInput.get() == '':
            if choosedPacket.haslayer('IPv6'):  # TODO IPv6
                self.choosedIPv6PDUAnalysis(choosedPacket)
            elif choosedPacket.haslayer('DNS'):
                self.choosedDNSPDUAnalysis(choosedPacket)  # TODO DNS
            elif choosedPacket.haslayer('ARP'):
                self.choosedARPPDUAnalysis(choosedPacket, sniff_time)
            elif choosedPacket.haslayer('Ether'):  # 以太网MAC协议
                self.choosedEtherPDUAnalysis(choosedPacket)
            elif choosedPacket.haslayer('TCP'):
                self.choosedTCPPDUAnalysis(choosedPacket)
            elif choosedPacket.haslayer('UDP'):
                self.choosedUDPPDUAnalysis(choosedPacket)
            elif choosedPacket.haslayer('ICMP'):  # TODO ICMP
                self.choosedICMPPDUAnalysis(choosedPacket)
            elif choosedPacket.haslayer('IP'):
                self.choosedIPPDUAnalysis(choosedPacket)

    # TODO MAC 数据报分析
    def choosedEtherPDUAnalysis(self, mac_packet):
        # 请在此处完成MAC协议的分析器(分析数据包功能)，并添加详细代码注释
        analysis_text = ""
        analysis_text += f"Ethernet II, Src: {mac_packet[Ether].src}, Dst: {mac_packet[Ether].dst}\n"
        analysis_text += f"  Destination: {mac_packet[Ether].dst}\n"  # Destination MAC
        analysis_text += f"  Source: {mac_packet[Ether].src}\n"  # Source MAC(48 bits)
        analysis_text += f"  Type: {ETHER_TYPES[mac_packet[Ether].type]} ({mac_packet[Ether].type})\n"  # 以太类型
        analysis_text += f"  payload: {bytes(mac_packet.payload)}\n"  # 负载数据

        self.PDUAnalysisText.insert(END, analysis_text)
        self.PDUCodeText.insert(END, scapy.utils.hexdump(mac_packet, True))
        pass

    # IP flags
    def ipflags(self, ip_flags):
        flags = 0
        if ip_flags == "DF":
            flags = 2
        elif ip_flags == "MF":
            flags = 1
        result = ""
        if flags == 2:
            result = ", Don't fragment"
        elif flags == 1:
            result = ", More fragments"
        return [intbin(flags, 3), hex(flags), result]  # 标志位二进制和十六进制

    # 检验和计算和验证
    def IP_headchecksum(self, ip_packet):
        _f_ip_packet = copy.deepcopy(ip_packet)  # 使用深拷贝，以免影响原数据包
        # 计算检验和
        checksum1 = _f_ip_packet[IP].chksum

        _f_ip_packet[IP].chksum = 0
        IP_head = bytes(_f_ip_packet.getlayer(IP))[0:_f_ip_packet[IP].ihl * 4]

        checksum = 0
        headlen = len(IP_head)
        if headlen % 2 == 1:
            # b:signed type
            IP_head += b"\0"
        i = 0
        while i < headlen:
            temp = struct.unpack('!H', IP_head[i:i + 2])[0]
            checksum = checksum + temp
            i = i + 2
        # 将高16bit与低16bit相加
        checksum = (checksum >> 16) + (checksum & 0xffff)
        # 将高16bit与低16bit再相加
        checksum = checksum + (checksum >> 16)
        checksum2 = ~checksum & 0xffff
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

    # TODO IP 数据报分析
    def choosedIPPDUAnalysis(self, ip_packet):
        # 请在此处完成IP协议的分析器(分析数据包功能)，并添加详细代码注释
        analysis_text = "\n"

        # analysis_text += f"Ethernet II, Src: {ip_packet[Ether].src}, Dst: {ip_packet[Ether].dst}\n"
        # analysis_text += f"  Destination: {ip_packet[Ether].dst}\n"  # Destination MAC
        # analysis_text += f"  Source: {ip_packet[Ether].src}\n"  # Source MAC(48 bits)
        # analysis_text += f"  Type: {str(ip_packet[Ether].type) + ' ' + ETHER_TYPES[ip_packet[Ether].type]}\n"  # 以太类型
        self.choosedEtherPDUAnalysis(ip_packet)  # 直接调用mac分析函数

        analysis_text += f"Internet Protocol Version {ip_packet[IP].version} Src: {ip_packet[IP].src}, Dst: {ip_packet[IP].dst}\n"  # 版本和地址
        analysis_text += f"  {intbin(ip_packet[IP].version, 4)}.... = Version: {ip_packet[IP].version}\n"  # IP的版本
        analysis_text += f"  ....{intbin(ip_packet[IP].ihl, 4)} = Header Length: {ip_packet[IP].ihl * 4} bytes ({ip_packet[IP].ihl})\n"  # 首部长度
        analysis_text += f"  Differentiated Service Field: 0x{ip_packet[IP].tos:04x}\n"  # 服务类型
        analysis_text += f"  Total Length: {ip_packet[IP].len}\n"  # 总长度
        analysis_text += f"  Identification: 0x{ip_packet[IP].id:04x} ({ip_packet[IP].id:d})\n"  # 标识,每一个IP数据包在发送时被给定特有的ID值
        # 标志位
        analysis_text += f"  {self.ipflags(ip_packet[IP].flags)[0]}. .... = Flags: {self.ipflags(ip_packet[IP].flags)[1]}{self.ipflags(ip_packet[IP].flags)[2]}\n"
        analysis_text += f"    0... .... = Reserved bit: Not set\n"
        analysis_text += f"    .{self.ipflags(ip_packet[IP].flags)[0][1]}.. .... = Don't fragment: {'Not ' if ip_packet[IP].flags != 'DF' else ''}Set\n"
        analysis_text += f"    ..{self.ipflags(ip_packet[IP].flags)[0][2]}. .... = More fragment: {'Not ' if ip_packet[IP].flags != 'MF' else ''}Set\n"
        # 片偏移
        analysis_text += f"  ...{intbin(ip_packet[IP].frag, 13)} = Fragment offset: {ip_packet[IP].frag * 8} ({ip_packet[IP].frag})\n"

        analysis_text += f"  Time to live: {ip_packet[IP].ttl}\n"  # 生存时间
        analysis_text += f"  Protocol: {IP_PROTOS[ip_packet[IP].proto]} ({ip_packet[IP].proto})\n"  # 协议
        # TODO ip 首部校验和
        analysis_text += f"  Header  Checksum: {self.IP_headchecksum(ip_packet)[0]} {self.IP_headchecksum(ip_packet)[2]}\n"  # 首部校验和
        analysis_text += f"  [Header checksum status: {self.IP_headchecksum(ip_packet)[3]}]\n"
        analysis_text += f"  [Calculated checksum: {self.IP_headchecksum(ip_packet)[1]}]\n"

        analysis_text += f"  Source Address: {ip_packet[IP].src}\n"  # 源地址
        analysis_text += f"  Destination Address: {ip_packet[IP].dst}\n"  # 目的地址

        self.PDUAnalysisText.insert(END, analysis_text)

    # TODO IPv6
    def choosedIPv6PDUAnalysis(self, ipv6_packet):
        analysis_text = "\n"

        self.choosedEtherPDUAnalysis(ipv6_packet)  # 直接调用mac分析函数

        analysis_text += f"Internet Protocol Version {ipv6_packet[IPv6].version}, Src: {ipv6_packet[IPv6].src}, Dst: {ipv6_packet[IPv6].dst}\n"
        analysis_text += f"  {intbin(ipv6_packet[IPv6].version, 4)} .... = Version: {ipv6_packet[IPv6].version}\n"
        # IPv6 流量类别（Traffic Class），占 8 位。它用于指定数据包的流量类别，类似于 IPv4 中的服务类型字段（Type of Service，TOS）。
        analysis_text += f"  .... {intbin(ipv6_packet[IPv6].tc, 8, True)} .... .... .... .... .... = Traffic Class: {ipv6_packet[IPv6].tc} (DSCP: {DSCP_TYPES[intbin(ipv6_packet[IPv6].tc, 8)[:6]]}, ECN: {ECN_TYPES[intbin(ipv6_packet[IPv6].tc, 8)[6:]][0]})\n"
        """
        前6位被用于表示DSCP（Differentiated Services Code Point），也称为Class Selector。
        DSCP定义了IPv6数据包的服务类别，以决定数据包在网络中的优先级和处理方式。不同的DSCP值对应不同的服务质量，例如，低延迟、高吞吐量等。
        https://en.wikipedia.org/wiki/Differentiated_services
        """
        analysis_text += f"    .... {intbin(ipv6_packet[IPv6].tc, 8, True)[:7]}.. .... .... .... .... .... = Differentiated Services Codepoint: {DSCP_TYPES[intbin(ipv6_packet[IPv6].tc, 8)[:6]]} ({int(intbin(ipv6_packet[IPv6].tc, 8)[:6], 2)})\n"
        """
        ECN 使用 IPv4 首部或 IPv6 首部中 ToS (Type of Service，位于首部第 9 到 16 比特位) 字段的两个最低有效位（最右侧的位编码）来表示四个状态码：
        00 – 不支持 ECN 的传输，非 ECT(Non ECN-Capable Transport)
        10 – 支持 ECN 的传输，ECT(0)
        01 – 支持 ECN 的传输，ECT(1)
        11 – 发生拥塞，CE(Congestion Experienced)。
        当两端支持 ECN 时，它将数据包标为 ECT(0) 或 ECT(1)。如果分组穿过一个遇到阻塞并且相应路由器支持 ECN 的活动队列管理（AQM）队列（例如一个使用随机早期检测，即 RED 的队列），它可以将代码点更改为CE而非丢包。这种行为就是“标记”，其目的是通知接收端即将发生拥塞。在接收端，该拥塞指示由上层协议（传输层协议）处理，并且需要将信号回传给发送端，以通知其降低传输速率。
        因为 CE 指示只能由支持它的上层协议有效处理，ECN 只能配合上层协议使用。例如 TCP 协议，它支持阻塞控制并且有方法将 CE 指示回传给发送端。
        https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
        """
        analysis_text += f"    .... .... ..{intbin(ipv6_packet[IPv6].tc, 8)[6:]} .... .... .... .... .... = Explicit Congestion Notification: {ECN_TYPES[intbin(ipv6_packet[IPv6].tc, 8)[6:]][1]}\n"
        # IPv6 流标签（Flow Label），占 20 位。流标签字段用于标识属于同一流的数据包，以便路由器在处理数据包时可以将它们分配给相同的处理路径。
        analysis_text += f"  .... {intbin(ipv6_packet[IPv6].fl, 20, True)} = Flow Label: {ipv6_packet[IPv6].fl}\n"
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

        self.PDUAnalysisText.insert(END, analysis_text)

    # TODO ARP 数据报分析
    def choosedARPPDUAnalysis(self, arp_packet, sniff_time):
        # 请在此处完成ARP协议的分析器(分析数据包功能)，并添加详细代码注释

        analysis_text = "\n"
        analysis_text += f"捕获时间: {sniff_time}\n"

        # analysis_text += f"Ethernet II, Src: {arp_packet[Ether].src}, Dst: {arp_packet[Ether].dst}\n"
        # analysis_text += f"  Destination: {arp_packet[Ether].dst}\n"  # Destination MAC
        # analysis_text += f"  Source: {arp_packet[Ether].src}\n"  # Source MAC(48 bits)
        # analysis_text += f"  Type: {str(arp_packet[Ether].type) + ' ' + ETHER_TYPES[arp_packet[Ether].type]}\n"  # 以太类型
        self.choosedEtherPDUAnalysis(arp_packet)  # 直接调用mac分析函数

        analysis_text += f"Address Resolution Protocol ({'request' if arp_packet[ARP].op == 1 else 'reply'})\n"  # 指定发送方执行的操作:1表示请求, 2表示应答.
        analysis_text += f"  Hardware type: {scapy.layers.l2.HARDWARE_TYPES[arp_packet[ARP].hwtype]}\n"  # 网络链接协议类型
        analysis_text += f"  Protocol type: {arp_packet[ARP].ptype}\n"  # 此字段指定ARP请求所针对的网络协议. 对于IPv4, 它的值是0x0800.
        analysis_text += f"  Hardware size: {arp_packet[ARP].hwlen}\n"  # 硬件地址的长度(以字节为单位). 以太网地址长度为6.
        analysis_text += f"  Protocol size: {arp_packet[ARP].plen}\n"  # 网络地址的长度(以字节为单位). 网络协议在PTYPE中指定. 示例:IPv4地址长度为4.
        analysis_text += f"  Opcode: {'request (1)' if arp_packet[ARP].op == 1 else 'reply (2)'}\n"
        analysis_text += f"  Sender MAC address: {arp_packet[ARP].hwsrc}\n"  # 发送方硬件地址
        analysis_text += f"  Sender IP address: {arp_packet[ARP].psrc}\n"  # 发送方IP地址
        analysis_text += f"  Target MAC address: {arp_packet[ARP].hwdst}\n"  # 目标硬件地址
        analysis_text += f"  Target IP address: {arp_packet[ARP].pdst}\n"  # 目标IP

        self.PDUAnalysisText.insert(END, analysis_text)

    # 获取 TCP 的 Flag 每一位的值
    def tcpflag(self, tcpflag):
        result = {"bin": "", "hex": "", "Reserved": "", "NS": "",
                  "CWR": "", "ECE": "", "URG": "", "ACK": "",
                  "PSH": "", "RST": "", "SYN": "", "FIN": "",
                  "result": "", "letter": ""}
        # 保留字
        result["bin"] = "000"
        result["Reserved"] = "Not set"
        # NS
        if tcpflag & 0x100:
            result["bin"] += "1"
            result["NS"] = "Set"
            result["result"] += " NS"
            result["letter"] += "N"
        else:
            result["bin"] += "0"
            result["NS"] = "Not set"
            result["letter"] += "."
        # CWR
        if tcpflag & 0x80:
            result["bin"] += "1"
            result["CWR"] = "Set"
            result["result"] += " CWR"
            result["letter"] += "C"
        else:
            result["bin"] += "0"
            result["CWR"] = "Not set"
            result["letter"] += "."
        # ECE
        if tcpflag & 0x40:
            result["bin"] += "1"
            result["ECE"] = "Set"
            result["result"] += " ECE"
            result["letter"] += "E"
        else:
            result["bin"] += "0"
            result["ECE"] = "Not set"
            result["letter"] += "."
        # URG
        if tcpflag & 0x20:
            result["bin"] += "1"
            result["URG"] = "Set"
            result["result"] += " URG"
            result["letter"] += "U"
        else:
            result["bin"] += "0"
            result["URG"] = "Not set"
            result["letter"] += "."
        # ACK
        if tcpflag & 0x10:
            result["bin"] += "1"
            result["ACK"] = "Set"
            result["result"] += " ACK"
            result["letter"] += "A"
        else:
            result["bin"] += "0"
            result["ACK"] = "Not set"
            result["letter"] += "."
        # PSH
        if tcpflag & 0x08:
            result["bin"] += "1"
            result["PSH"] = "Set"
            result["result"] += " PSH"
            result["letter"] += "P"
        else:
            result["bin"] += "0"
            result["PSH"] = "Not set"
            result["letter"] += "."
        # RST
        if tcpflag & 0x04:
            result["bin"] += "1"
            result["RST"] = "Set"
            result["result"] += " RST"
            result["letter"] += "R"
        else:
            result["bin"] += "0"
            result["RST"] = "Not set"
            result["letter"] += "."
        # SYN
        if tcpflag & 0x02:
            result["bin"] += "1"
            result["SYN"] = "Set"
            result["result"] += " SYN"
            result["letter"] += "S"
        else:
            result["bin"] += "0"
            result["SYN"] = "Not set"
            result["letter"] += "."
        # FIN
        if tcpflag & 0x01:
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

    # 伪首部 部分数据
    def pseudo_head(self, tcp_or_udp):
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

    # tcp 长度
    def tcp_len(self, tcp_packet):
        length = 0
        if tcp_packet[TCP].haslayer('Padding'):
            length = len(tcp_packet[TCP].payload) - len(tcp_packet[Padding].load)
        else:
            length = len(tcp_packet[TCP].payload)
        return length

    # tcp校验和
    def TCP_headchecksum(self, tcp_packet):
        _f_tcp_packet = copy.deepcopy(tcp_packet)  # 使用深拷贝，以免影响原数据包
        checksum1 = _f_tcp_packet[TCP].chksum

        new_code = bytes()
        _f_tcp_packet[TCP].chksum = 0
        new_code += self.pseudo_head(_f_tcp_packet) + \
                    struct.pack('!H', 6) + \
                    struct.pack('!H', _f_tcp_packet[TCP].dataofs * 4 + self.tcp_len(_f_tcp_packet)) + \
                    bytes(_f_tcp_packet.getlayer(TCP))[0:_f_tcp_packet[TCP].dataofs * 4 + self.tcp_len(_f_tcp_packet)]

        checksum = 0
        code_len = len(new_code)
        if code_len % 2 == 1:
            # b:signed type
            new_code += b"\0"
        i = 0
        while i < code_len:
            temp = struct.unpack('!H', new_code[i:i + 2])[0]
            checksum = checksum + temp
            i = i + 2
        # 将高16bit与低16bit相加
        checksum = (checksum >> 16) + (checksum & 0xffff)
        # 将高16bit与低16bit再相加
        checksum = checksum + (checksum >> 16)
        checksum2 = ~checksum & 0xffff

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

    # TODO TCP 数据报分析
    def choosedTCPPDUAnalysis(self, tcp_packet):
        # 请在此处完成TCP协议的分析器(分析数据包功能)，并添加详细代码注释
        analysis_text = "\n"

        if tcp_packet.haslayer('IP'):
            self.choosedIPPDUAnalysis(tcp_packet)
        elif tcp_packet.haslayer('IPv6'):
            self.choosedIPv6PDUAnalysis(tcp_packet)

        analysis_text += f"Transmission Control Protocol, Src Port: {tcp_packet[TCP].sport}, Dst Port: {tcp_packet[TCP].dport}, Seq: {tcp_packet[TCP].seq}, Ack: {tcp_packet[TCP].ack}, Len: {self.tcp_len(tcp_packet)}\n"
        analysis_text += f"  Source Port: {tcp_packet[TCP].sport}\n"  # 发送连接端口
        analysis_text += f"  Destination Port: {tcp_packet[TCP].dport}\n"  # 接收连接端口

        # analysis_text += f"  [Stream index: ???]\n"  # 流索引
        # analysis_text += f"  [Conversation completeness: ??? Incomplete (12)]\n"

        analysis_text += f"  [TCP Segment Len: {self.tcp_len(tcp_packet)}\n"  # tcp长度

        # 如果SYN标志设置为1, 则这是初始序列号
        # 如果SYN标志设置为0, 则这是当前会话该段的第一个数据字节的累计序列号
        # analysis_text += f"  Sequence Number: ??? (relative sequence number)\n"
        analysis_text += f"  Sequence Number (raw): {tcp_packet[TCP].seq}\n"
        # analysis_text += f"  [Next Sequence Number: ???    (relative sequence number)]\n"

        # 如果设置了ACK标志, 那么这个字段的值就是ACK发送者期望的下一个序列号
        # analysis_text += f"  Acknowledgment Number: ???    (relative ack number)\n"
        analysis_text += f"  Acknowledgment Number (raw): {tcp_packet[TCP].ack}\n"

        # 首部长度
        analysis_text += f"  {intbin(tcp_packet[TCP].dataofs, 4)} .... = Header Length: {tcp_packet[TCP].dataofs * 4} bytes ({tcp_packet[TCP].dataofs})\n"

        # 标志位
        analysis_text += f"  Flags: {self.tcpflag(tcp_packet[TCP].flags)['hex']} ({self.tcpflag(tcp_packet[TCP].flags)['result']})\n"
        analysis_text += f"    000. .... .... = Reserved: Not set\n"
        analysis_text += f"    ...{self.tcpflag(tcp_packet[TCP].flags)['bin'][3]} .... .... = Accurate ECN: {self.tcpflag(tcp_packet[TCP].flags)['NS']}\n"
        analysis_text += f"    .... {self.tcpflag(tcp_packet[TCP].flags)['bin'][4]}... .... = Congestion Window Reduced: {self.tcpflag(tcp_packet[TCP].flags)['CWR']}\n"
        analysis_text += f"    .... .{self.tcpflag(tcp_packet[TCP].flags)['bin'][5]}.. .... = ECN-Echo: {self.tcpflag(tcp_packet[TCP].flags)['ECE']}\n"
        analysis_text += f"    .... ..{self.tcpflag(tcp_packet[TCP].flags)['bin'][6]}. .... = Urgent: {self.tcpflag(tcp_packet[TCP].flags)['URG']}\n"
        analysis_text += f"    .... ...{self.tcpflag(tcp_packet[TCP].flags)['bin'][7]} .... = Acknowledgment: {self.tcpflag(tcp_packet[TCP].flags)['ACK']}\n"
        analysis_text += f"    .... .... {self.tcpflag(tcp_packet[TCP].flags)['bin'][8]}.. .... = Push: {self.tcpflag(tcp_packet[TCP].flags)['PSH']}\n"
        analysis_text += f"    .... .... .{self.tcpflag(tcp_packet[TCP].flags)['bin'][9]} .... = Reset: {self.tcpflag(tcp_packet[TCP].flags)['RST']}\n"
        analysis_text += f"    .... .... ..{self.tcpflag(tcp_packet[TCP].flags)['bin'][10]} .... = Syn: {self.tcpflag(tcp_packet[TCP].flags)['SYN']}\n"
        analysis_text += f"    .... .... ...{self.tcpflag(tcp_packet[TCP].flags)['bin'][11]} .... = Fin: {self.tcpflag(tcp_packet[TCP].flags)['FIN']}\n"
        analysis_text += f"    [TCP Flags: {self.tcpflag(tcp_packet[TCP].flags)['letter']}]\n"

        # 接收窗口的大小, 它指定此段的发送方当前愿意接收的窗口大小单元的数量(默认情况下为字节)
        analysis_text += f"  Window: {tcp_packet[TCP].window}\n"
        # analysis_text += f"  [Calculated window size: ???]\n"
        # analysis_text += f"  [Window size scaling factor: ???]\n"

        # 校验和
        analysis_text += f"  Checksum: {self.TCP_headchecksum(tcp_packet)[0]} {self.TCP_headchecksum(tcp_packet)[2]}\n"
        analysis_text += f"  [Checksum Status: {self.TCP_headchecksum(tcp_packet)[3]}]\n"
        analysis_text += f"  [Calculated Checksum: {self.TCP_headchecksum(tcp_packet)[1]}]\n"

        # 如果设置了URG标志, 那么这个16位字段就是表示最后一个紧急数据字节的序列号的偏移量
        analysis_text += f"  Urgent Pointer: {tcp_packet[TCP].urgptr}\n"

        # TCP 数据包的选项字段（Options Field）。TCP 选项字段是 TCP 头部中的一部分，用于在 TCP 连接建立和维护过程中传输附加信息。
        analysis_text += f"  Options: {tcp_packet[TCP].options}\n"

        self.PDUAnalysisText.insert(END, analysis_text)

    # udp校验和
    def UDP_headchecksum(self, udp_packet):
        result_string = ""
        result = []
        checksum1 = udp_packet[UDP].chksum
        if checksum1 == 0:
            result_string = "  Checksum: 0x0000[zero - value ignored]\n"
        else:
            _f_udp_packet = copy.deepcopy(udp_packet)  # 使用深拷贝，以免影响原数据包

            new_code = bytes()
            _f_udp_packet[UDP].chksum = 0
            new_code += self.pseudo_head(_f_udp_packet) + \
                        struct.pack('!H', 17) + \
                        struct.pack('!H', _f_udp_packet[UDP].len) + \
                        bytes(_f_udp_packet.getlayer(UDP))[0:_f_udp_packet[UDP].len]

            checksum = 0
            code_len = len(new_code)
            if code_len % 2 == 1:
                # b:signed type
                new_code += b"\0"
            i = 0
            while i < code_len:
                temp = struct.unpack('!H', new_code[i:i + 2])[0]
                checksum = checksum + temp
                i = i + 2
            # 将高16bit与低16bit相加
            checksum = (checksum >> 16) + (checksum & 0xffff)
            # 将高16bit与低16bit再相加
            checksum = checksum + (checksum >> 16)
            checksum2 = ~checksum & 0xffff

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

    # TODO UDP 数据报分析
    def choosedUDPPDUAnalysis(self, udp_packet):
        # 请在此处完成UDP协议的分析器(分析数据包功能)，并添加详细代码注释
        analysis_text = "\n"

        if udp_packet.haslayer('IP'):
            self.choosedIPPDUAnalysis(udp_packet)
        elif udp_packet.haslayer('IPv6'):
            self.choosedIPv6PDUAnalysis(udp_packet)

        analysis_text += f"User Datagram Protocol, Src Port: {udp_packet[UDP].sport}, Dst Port: {udp_packet[UDP].dport}\n"
        analysis_text += f"  Source Port: {udp_packet[UDP].sport}\n"
        analysis_text += f"  Destination Port: {udp_packet[UDP].dport}\n"
        analysis_text += f"  Length: {udp_packet[UDP].len}\n"
        analysis_text += self.UDP_headchecksum(udp_packet)
        # analysis_text += f"  [Stream index: ???]\n"
        analysis_text += f"  UDP payload ({len(udp_packet[UDP].payload)} bytes)\n"

        self.PDUAnalysisText.insert(END, analysis_text)

    # icmp校验和
    def ICMP_headchecksum(self, icmp_packet):
        _f_icmp_packet = copy.deepcopy(icmp_packet)  # 使用深拷贝，以免影响原数据包
        # 计算检验和
        checksum1 = _f_icmp_packet[ICMP].chksum

        _f_icmp_packet[ICMP].chksum = 0
        ICMP_codes = bytes(_f_icmp_packet.getlayer(ICMP))[:]

        checksum = 0
        code_len = len(ICMP_codes)
        if code_len % 2 == 1:
            # b:signed type
            ICMP_codes += b"\0"
        i = 0
        while i < code_len:
            temp = struct.unpack('!H', ICMP_codes[i:i + 2])[0]
            checksum = checksum + temp
            i = i + 2
        # 将高16bit与低16bit相加
        checksum = (checksum >> 16) + (checksum & 0xffff)
        # 将高16bit与低16bit再相加
        checksum = checksum + (checksum >> 16)
        checksum2 = ~checksum & 0xffff
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

    # TODO ICMP
    def choosedICMPPDUAnalysis(self, icmp_packet):
        analysis_text = "\n"

        self.choosedIPPDUAnalysis(icmp_packet)

        analysis_text += f"Internet Control Message Protocol\n"
        analysis_text += f"  Type: {icmp_packet[ICMP].type} ({ICMP_TYPES[icmp_packet[ICMP].type]})\n"
        analysis_text += f"  Code: {icmp_packet[ICMP].code} {'(' + ICMP_CODES[icmp_packet[ICMP].type][icmp_packet[ICMP].code] + ')' if icmp_packet[ICMP].type in ICMP_CODES.keys() else ''}\n"
        analysis_text += f"  Checksum: {self.ICMP_headchecksum(icmp_packet)[0]} {self.ICMP_headchecksum(icmp_packet)[2]}\n"
        analysis_text += f"  [Checksum Status: {self.ICMP_headchecksum(icmp_packet)[3]}]\n"
        analysis_text += f"  [Calculated Checksum:  {self.ICMP_headchecksum(icmp_packet)[1]}]\n"
        analysis_text += f"  Identifier (BE): {icmp_packet[ICMP].id} (0x{icmp_packet[ICMP].id:04x})\n"  # linux 用于匹配 Request/Reply 的标识符 大端字节序
        analysis_text += f"  Identifier (LE): {swap_endianness(icmp_packet[ICMP].id)} (0x{swap_endianness(icmp_packet[ICMP].id):04x})\n"  # windows 小端字节序
        analysis_text += f"  Sequence Number (BE): {icmp_packet[ICMP].seq} (0x{icmp_packet[ICMP].seq:04x})\n"  # 用于匹配 Request/Reply 的序列号
        analysis_text += f"  Sequence Number (LE): {swap_endianness(icmp_packet[ICMP].seq)} (0x{swap_endianness(icmp_packet[ICMP].seq):04x})\n"

        self.PDUAnalysisText.insert(END, analysis_text)

    # dns flags
    def dns_flags(self, dns_packet):
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
        result_string += f"    .{str(intbin(dns_packet[DNS].opcode, 4))[0:3]} {str(intbin(dns_packet[DNS].opcode, 4))[3]}... .... .... = Opcode: {DNS_OPCODE_TYPES[dns_packet[DNS].opcode]} ({dns_packet[DNS].opcode})\n"
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

    # TODO DNS
    def choosedDNSPDUAnalysis(self, dns_packet):
        analysis_text = "\n"

        if dns_packet.haslayer('TCP'):
            self.choosedTCPPDUAnalysis(dns_packet)
        elif dns_packet.haslayer('UDP'):
            self.choosedUDPPDUAnalysis(dns_packet)

        # # 查看值
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
        analysis_text += self.dns_flags(dns_packet)
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

        self.PDUAnalysisText.insert(END, analysis_text)


app = Application()
app.mainloop()
