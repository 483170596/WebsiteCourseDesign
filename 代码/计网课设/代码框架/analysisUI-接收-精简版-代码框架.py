import datetime
from tkinter.ttk import Combobox

import scapy.utils
from scapy.all import *
from tkinter import *
import tkinter as tk
import time, threading
import tkinter.messagebox as messagebox
import datetime

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, TCP, in4_chksum, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP


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
        if self.conditionInput.get().find('IP') != -1:
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
        else:
            if self.count > self.countAct:
                self.countAct += 1
                self.sniffDataList.append(pkt)
                self.listbox.insert(END, pktSummaryInfo)
        self.sniff_times.append(datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))  # 捕获时间
        print(threading.current_thread().name + ' 2')
        # https://blog.csdn.net/briblue/article/details/85101144
        # time.sleep(1) # 最好不要延时，否则好多包抓不到

    # 检验和计算和验证
    def IP_headchecksum(self, IP_head):
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
        return ~checksum & 0xffff

    # 协议号代表的协议名称
    def proto_IPcol(self, ori_protocol):
        proString = ''
        if ori_protocol == 1:
            proString = 'ICMP'
        elif ori_protocol == 6:
            proString = 'TCP'
        elif ori_protocol == 17:
            proString = 'UDP'
        elif ori_protocol == 89:
            proString = 'OSPF'
        elif ori_protocol == 0:
            proString = 'IPv6 Hop-by-Hop Option'
        elif ori_protocol == 58:
            proString = 'ICMPv6'
        elif ori_protocol == 4:
            proString = 'IP'
        return proString

    # 对选择的报文，判断其协议调用不同的分析函数
    def choosedPDUAnalysis(self, event):
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        sniff_time = self.sniff_times[choosePDUNum]
        self.PDUAnalysisText.delete('1.0', 'end')
        self.PDUCodeText.delete('1.0', 'end')  # 清空PDUAnalysisText，PDUCodeText控件内容
        if self.conditionInput.get().find('IP') != -1:
            self.choosedIPPDUAnalysis(choosedPacket)
        elif self.conditionInput.get().find('ARP') != -1:
            self.choosedARPPDUAnalysis(choosedPacket, sniff_time)
        elif self.conditionInput.get().find('Ether') != -1:  # 以太网MAC协议
            self.choosedEtherPDUAnalysis(choosedPacket, sniff_time)
        elif self.conditionInput.get().find('TCP') != -1:
            self.choosedTCPPDUAnalysis(choosedPacket)
        elif self.conditionInput.get().find('UDP') != -1:
            self.choosedUDPPDUAnalysis(choosedPacket)
        elif self.conditionInput.get() == '':
            if choosedPacket.haslayer('IP'):
                self.choosedIPPDUAnalysis(choosedPacket)
            elif choosedPacket.haslayer('ARP'):
                self.choosedARPPDUAnalysis(choosedPacket, sniff_time)
            elif choosedPacket.haslayer('Ether'):  # 以太网MAC协议
                self.choosedEtherPDUAnalysis(choosedPacket, sniff_time)
            elif choosedPacket.haslayer('TCP'):
                self.choosedTCPPDUAnalysis(choosedPacket)
            elif choosedPacket.haslayer('UDP'):
                self.choosedUDPPDUAnalysis(choosedPacket)

    # TODO MAC 数据报分析
    def choosedEtherPDUAnalysis(self, mac_packet, sniff_time):
        # 请在此处完成MAC协议的分析器(分析数据包功能)，并添加详细代码注释
        analysis_text = ""
        analysis_text += f"Ethernet II, Src: {mac_packet[Ether].src}, Dst: {mac_packet[Ether].dst}\n"
        analysis_text += f"  Destination: {mac_packet[Ether].dst}\n"  # Destination MAC
        analysis_text += f"  Source: {mac_packet[Ether].src}\n"  # Source MAC(48 bits)
        analysis_text += f"  Type: {str(mac_packet[Ether].type) + ' ' + ETHER_TYPES[mac_packet[Ether].type]}\n"  # 以太类型
        analysis_text += f"  payload: {bytes(mac_packet.payload)}"

        self.PDUAnalysisText.insert(END, analysis_text)
        self.PDUCodeText.insert(END, scapy.utils.hexdump(mac_packet, True))
        pass

    # TODO IP 数据报分析
    def choosedIPPDUAnalysis(self, ip_packet):
        # 请在此处完成IP协议的分析器(分析数据包功能)，并添加详细代码注释
        print("尝试输出")
        analysis_text = ""
        analysis_text += f"Ethernet II, Src: {ip_packet[IP]}, Dst: {ip_packet[IP]}\n"
        self.PDUAnalysisText.insert(END, analysis_text)
        self.PDUCodeText.insert(END, scapy.utils.hexdump(ip_packet, True))

        # TODO TCP 数据报分析
        pass

    # TODO ARP 数据报分析
    def choosedARPPDUAnalysis(self, arp_packet, sniff_time):
        # 请在此处完成ARP协议的分析器(分析数据包功能)，并添加详细代码注释

        analysis_text = ""
        analysis_text += f"捕获时间: {sniff_time}\n"
        analysis_text += f"Ethernet II, Src: {arp_packet[Ether].src}, Dst: {arp_packet[Ether].dst}\n"
        analysis_text += f"  Destination: {arp_packet[Ether].dst}\n"  # Destination MAC
        analysis_text += f"  Source: {arp_packet[Ether].src}\n"  # Source MAC(48 bits)
        analysis_text += f"  Type: {str(arp_packet[Ether].type) + ' ' + ETHER_TYPES[arp_packet[Ether].type]}\n"  # 以太类型
        analysis_text += f"Address Resolution Protocol ({'Response' if arp_packet[ARP].op == 1 else 'Reply'})\n"  # 指定发送方执行的操作:1表示请求, 2表示应答.
        analysis_text += f"  Hardware type: {scapy.layers.l2.HARDWARE_TYPES[arp_packet[ARP].hwtype]}\n"  # 网络链接协议类型
        analysis_text += f"  Protocol type: {arp_packet[ARP].ptype}\n"  # 此字段指定ARP请求所针对的网络协议. 对于IPv4, 它的值是0x0800.
        analysis_text += f"  Hardware size: {arp_packet[ARP].hwlen}\n"  # 硬件地址的长度(以字节为单位). 以太网地址长度为6.
        analysis_text += f"  Protocol size: {arp_packet[ARP].plen}\n"  # 网络地址的长度(以字节为单位). 网络协议在PTYPE中指定. 示例:IPv4地址长度为4.
        analysis_text += f"  Opcode: {'Response (1)' if arp_packet[ARP].op == 1 else 'Reply (2)'}\n"
        analysis_text += f"  Sender MAC address: {arp_packet[ARP].hwsrc}\n"  # 发送方硬件地址
        analysis_text += f"  Sender IP address: {arp_packet[ARP].psrc}\n"  # 发送方IP地址
        analysis_text += f"  Target MAC address: {arp_packet[ARP].hwdst}\n"  # 目标硬件地址
        analysis_text += f"  Target IP address: {arp_packet[ARP].pdst}\n"  # 目标IP

        self.PDUAnalysisText.insert(END, analysis_text)
        self.PDUCodeText.insert(END, scapy.utils.hexdump(arp_packet, True))
        pass

    # 获取 TCP 的 Flag 每一位的值
    def tcpflag(self, tcpflag):  # 将标志位是1的拼接
        flagString = ' '
        flag = 0
        if tcpflag & 0x80:
            if flag == 0:
                flagString += 'CWR'
                flag = 1
            else:
                flagString += ',CWR'
        if tcpflag & 0x40:
            if flag == 0:
                flagString += 'ECE'
                flag = 1
            else:
                flagString += ',ECE'
        if tcpflag & 0x20:
            if flag == 0:
                flagString += 'URG'
                flag = 1
            else:
                flagString += ',URG'
        if tcpflag & 0x10:
            if flag == 0:
                flagString += 'ACK'
                flag = 1
            else:
                flagString += ',ACK'
        if tcpflag & 0x08:
            if flag == 0:
                flagString += 'PSH'
                flag = 1
            else:
                flagString += ',PSH'
        if tcpflag & 0x04:
            if flag == 0:
                flagString += 'RST'
                flag = 1
            else:
                flagString += ',RST'
        if tcpflag & 0x02:
            if flag == 0:
                flagString += 'SYN'
                flag = 1
            else:
                flagString += ',SYN'
        if tcpflag & 0x01:
            if flag == 0:
                flagString += 'FIN'
                flag = 1
            else:
                flagString += ',FIN'
        return flagString

    # TODO TCP 数据报分析
    def choosedTCPPDUAnalysis(self, tcp_packet):
        # 请在此处完成TCP协议的分析器(分析数据包功能)，并添加详细代码注释
        pass

    # TODO UDP 数据报分析
    def choosedUDPPDUAnalysis(self, udp_packet):
        # 请在此处完成UDP协议的分析器(分析数据包功能)，并添加详细代码注释
        pass


app = Application()
app.mainloop()
