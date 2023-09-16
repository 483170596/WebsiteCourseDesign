from tkinter.ttk import Combobox

from scapy.all import *
from tkinter import *
import tkinter as tk
import time, threading
import tkinter.messagebox as messagebox

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, TCP, in4_chksum, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

class Application(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.sniffDataList = []
        self.createWidgets()
        self.sniffFlag = True  # 设置控制捕获线程运行的标志变量

    def createWidgets(self):
        self.geometry('1200x800')
        self.title('协议分析器')
        self.count = 0  # 记录待捕获数据帧的个数
        self.countAct = 0 # 实际捕获数据帧的个数
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
        # 创建一个纵向滚动的滚动条，铺满Y方向
        s1 = Scrollbar(PDUCodeFrame, orient=VERTICAL)
        s1.pack(side=RIGHT, fill=Y)
        s1.config(command=self.PDUCodeText.yview)
        self.PDUCodeText['yscrollcommand'] = s1.set
        self.PDUCodeText.pack(fill=BOTH)
        PDUCodeFrame.pack(side=BOTTOM, fill=BOTH)
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
                    print(threading.current_thread().name+' 1') # https://blog.csdn.net/briblue/article/details/85101144

    def PDU_sniff(self):
        self.count=int(self.countInput.get())
        if self.count==0:
            self.count=float('inf') #无穷
        # sniff(filter='arp or ip or ip6 or tcp or udp', prn=(lambda x: self.ip_monitor_callback(x)), stop_filter=(lambda x: self.sniffFlag), store=0, iface='WLAN') # 指定无线网卡 一定要加filter='arp or ip or ip6 or tcp or udp'参数，协议名称一定要小写，否则无法顺利抓包 (filter BPF过滤规则 BPF：柏克莱封包过滤器（Berkeley Packet Filter，缩写BPF），是类Unix系统上数据链路层的一种原始接口，提供原始链路层封包的收发。) 回调函数：一个高层调用底层，底层再回过头来调用高层的过程。Scapy Sniffer的filter语法：https://blog.csdn.net/qwertyupoiuytr/article/details/54670477 有时候TCP和UDP校验和会由网卡计算(https://blog.csdn.net/weixin_34308389/article/details/93114074)，因此wireshark抓到的本机发送的TCP/UDP数据包的校验和都是错误的，这样检验校验和根本没有意义。所以Wireshark不自动做TCP和UDP校验和的校验。如果要校验校验和：可以在edit->preference->protocols中选择相应的TCP或者UDP协议，在相应的地方打钩。Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html
        sniff(filter="arp or ip or ip6 or tcp or udp", prn=(lambda x: self.ip_monitor_callback(x)), stop_filter=(lambda x: self.sniffFlag), store=0) # iface=None 则代表所有网卡 filter="arp or ip or ip6 or tcp or udp" 可选值：ether, fddi, tr, wlan, ip, ip6, arp, rarp, decnet, tcp, udp, icmp (fddi, tr, wlan是ether的别名, 包结构很类似) https://www.cnblogs.com/cheuhxg/p/15043117.html
        # sniff(prn=self.ip_monitor_callback, stop_filter=self.sniffFlag, store=0) # Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html

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
            self.listbox.delete(0, END) # 清空协议摘要信息动态窗口，0表示开始位置索引，END表示结束位置索引
            self.sniffDataList = []
            self.PDUAnalysisText.delete(1.0, END) # 清空协议详细解析动态窗口，1.0表示开始位置索引，END表示结束位置索引
            self.PDUCodeText.delete(1.0, END) # 清空协议报文编码动态窗口，1.0表示开始位置索引，END表示结束位置索引
            self.count = 0 # 记录待捕获数据帧的个数
            self.countAct=0 # 记录实际捕获数据帧的个数
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

    def split_dulequal(self, dul):  # 按照等号划分后获得筛选的条件
        splitList = dul.split('==')
        return splitList[1]

    # 回调函数，根据筛选条件调用不同的分析函数，注意为了降低难度，这里只实现与条件and(&&)
    def ip_monitor_callback(self, pkt):
        print(pkt.show())
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
                        self.countAct+=1
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
            if self.countAct==self.count:
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
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                        'ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                        'ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                        'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP and pkt[
                        'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and pkt[
                        'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and \
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
            if self.countAct==self.count:
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
            if self.count>self.countAct:
                self.countAct += 1
                self.sniffDataList.append(pkt)
                self.listbox.insert(END, pktSummaryInfo)

        print(threading.current_thread().name+' 2') # https://blog.csdn.net/briblue/article/details/85101144
        # time.sleep(1) # 最好不要延时，否则好多包抓不到

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

    def proto_IPcol(self, ori_protocol):
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

    #对应进制转换
    def intbin(self, n, count):
        """returns the binary of integer n, using count number of digits"""
        return "".join([str((n >> y) & 1) for y in range(count - 1, -1, -1)])

    def choosedPDUAnalysis(self, event):
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        if self.conditionInput.get().find('IP') != -1:
            self.choosedIPPDUAnalysis()
        elif self.conditionInput.get().find('ARP') != -1:
            self.choosedARPPDUAnalysis()
        elif self.conditionInput.get().find('Ether') != -1: # 以太网MAC协议
            self.choosedEtherPDUAnalysis()
        elif self.conditionInput.get().find('TCP') != -1:
            self.choosedTCPPDUAnalysis()
        elif self.conditionInput.get().find('UDP') != -1:
            self.choosedUDPPDUAnalysis()
        elif self.conditionInput.get() == '':
            if choosedPacket.haslayer('IP'):
                self.choosedIPPDUAnalysis()
            elif choosedPacket.haslayer('ARP'):
                self.choosedARPPDUAnalysis()
            elif choosedPacket.haslayer('Ether'): # 以太网MAC协议
                self.choosedEtherPDUAnalysis()
            elif choosedPacket.haslayer('TCP'):
                self.choosedTCPPDUAnalysis()
            elif choosedPacket.haslayer('UDP'):
                self.choosedUDPPDUAnalysis()

    def choosedEtherPDUAnalysis(self):
    # 请在此处完成MAC协议的分析器(分析数据包功能)，并添加详细代码注释
        # scapy.layers.l2.Ether：参考群文件Scapy 状元笔记，或https://github.com/twfb/Scapy-Note
        choosePDUNum = self.listbox.curselection()[0] # 参考代码框架560行代码获取双击鼠标左键所选中的数据报的索引，https://blog.csdn.net/m0_46489757/article/details/131054701
        choosedPacket = self.sniffDataList[choosePDUNum] # 参考代码框架561行代码根据双击鼠标左键所选中的数据报的索引提取捕获队列里的相应数据报

        self.PDUAnalysisText.delete(1.0, END) # 参考代码框架150行代码清空协议详细解析动态窗口，1.0表示开始位置索引，END表示结束位置索引，https://blog.csdn.net/weixin_43097301/article/details/84206539
        self.PDUAnalysisText.insert(END, 'Line 1, Src: ' + 'b0:73:5d:83:84:31' + ', Dst: ' + '12:67:15:09:fa:52' + '\n') # 在协议详细解析动态窗口输出第1行字符串，END表示结束位置索引，https://it.cha138.com/mysql/show-5911416.html
        self.PDUAnalysisText.insert(END, '   Line 2: ' + '12:67:15:09:fa:52' + '\n') # 在协议详细解析动态窗口输出第2行字符串，END表示结束位置索引，https://it.cha138.com/mysql/show-5911416.html

        self.PDUAnalysisText.insert(END, 'str(dir(choosedPacket[Ether])): ' + str(dir(choosedPacket[Ether])) + '\n') # 打印Ether数据报的所有可用字段，Ether可以为IP、ARP、TCP以及UDP

        self.PDUAnalysisText.insert(END, 'str(choosedPacket[Ether].src): ' + str(choosedPacket[Ether].src) + '\n') # 调用Ether数据报的src字段，Ether可以为IP、ARP、TCP以及UDP
        self.PDUAnalysisText.insert(END, '请自己补充其余代码！' + '\n')
        
        self.PDUCodeText.delete(1.0, END) # 参考代码框架151行协议报文编码动态窗口，1.0表示开始位置索引，END表示结束位置索引，https://blog.csdn.net/weixin_43097301/article/details/84206539
        self.PDUCodeText.insert(END, 'scapy 内 hexdump 详细使用：https://blog.csdn.net/qq_20237489/article/details/81632857') # 在协议报文编码动态窗口输出第1行字符串

    def choosedIPPDUAnalysis(self):
    # 请在此处完成IP协议的分析器(分析数据包功能)，并添加详细代码注释
        # scapy.layers.inet.IP：参考群文件Scapy 状元笔记，或https://github.com/twfb/Scapy-Note
        # 十进制转十六进制函数hex()
        # 数值转字符串函数str()
        # 字符串转整数函数int()
        # 打印16进制格式字符串'0x%04x'
        # 整数转二进制函数self.intbin()
        # 协议类型字符串获取函数self.proto_IPcol()
        # IP校验和checksum计算参考课件3-IP+TCP+UDP协议-2.pptx中的40-45页self.IP_headchecksum()
        # Differentiated Service Field计算参考：https://blog.nowcoder.net/n/483c8c3e8d1149b69ad9ad026698d1cdn/483c8c3e8d1149b69ad9ad026698d1cd
        choosePDUNum = self.listbox.curselection()[0] # 参考代码框架560行代码获取双击鼠标左键所选中的数据报的索引，https://blog.csdn.net/m0_46489757/article/details/131054701
        choosedPacket = self.sniffDataList[choosePDUNum] # 参考代码框架561行代码根据双击鼠标左键所选中的数据报的索引提取捕获队列里的相应数据报

        self.PDUAnalysisText.delete(1.0, END) # 参考代码框架150行代码清空协议详细解析动态窗口，1.0表示开始位置索引，END表示结束位置索引，https://blog.csdn.net/weixin_43097301/article/details/84206539

        # 计算IP Flags
        # '''
        flagAct = int(choosedPacket[IP].flags) * 8192
        fragmentAct = int(choosedPacket[IP].frag)
        flagsAct = fragmentAct + flagAct
        flagsActString = self.intbin(flagsAct, 16)
        if flagsActString[1] == '1':
            self.PDUAnalysisText.insert(END, '    Flags:0x%04x' % flagsAct + ", Don't fragment" + '\n')
            self.PDUAnalysisText.insert(END, '          0... .... .... .... = Reserved bit: Not set ' + '\n')
            self.PDUAnalysisText.insert(END, "          .1.. .... .... .... = Don't fragment : Set" + '\n')
        else:
            self.PDUAnalysisText.insert(END, '请自己补充其余代码！' + '\n')
        self.PDUAnalysisText.insert(END, '请自己补充其余代码！' + '\n')
        fraString = self.intbin(fragmentAct, 13)
        self.PDUAnalysisText.insert(END,
                                    "          ..." + str(fraString[0]) + ' ' + str(fraString[1:5]) + ' ' + str(
                                        fraString[5:9]) + ' ' + str(
                                        fraString[9:14]) + ' = Fragment offset : ' + str(fragmentAct) + '\n')
        # '''

    def choosedARPPDUAnalysis(self):
    # 请在此处完成ARP协议的分析器(分析数据包功能)，并添加详细代码注释
        # scapy.layers.l2.ARP：参考群文件Scapy 状元笔记，或https://github.com/twfb/Scapy-Note
        self.PDUAnalysisText.delete(1.0, END) # 参考代码框架150行代码清空协议详细解析动态窗口，1.0表示开始位置索引，END表示结束位置索引，https://blog.csdn.net/weixin_43097301/article/details/84206539
        self.PDUAnalysisText.insert(END, 'Python中的时间格式的读取与转换（time模块）：' + 'https://blog.csdn.net/sinat_41482627/article/details/127643708' + '\n') # 在协议详细解析动态窗口输出第1行字符串
        self.PDUAnalysisText.delete(1.0, END) # 参考代码框架150行代码清空协议详细解析动态窗口，1.0表示开始位置索引，END表示结束位置索引，https://blog.csdn.net/weixin_43097301/article/details/84206539        
        self.PDUAnalysisText.insert(END, '请自己补充其余代码！' + '\n')

    def tcpflag(self, tcpflag):  # 将标志位是1的拼接
        flagString = ''
        flag = 0
        if tcpflag & 0x80:
            if flag == 0:
                flagString += 'CWR'
                flag = 1
            else:
                flagString += ', CWR'
        if tcpflag & 0x40:
            if flag == 0:
                flagString += 'ECE'
                flag = 1
            else:
                flagString += ', ECE'
        if tcpflag & 0x20:
            if flag == 0:
                flagString += 'URG'
                flag = 1
            else:
                flagString += ', URG'
        if tcpflag & 0x10:
            if flag == 0:
                flagString += 'ACK'
                flag = 1
            else:
                flagString += ', ACK'
        if tcpflag & 0x08:
            if flag == 0:
                flagString += 'PSH'
                flag = 1
            else:
                flagString += ', PSH'
        if tcpflag & 0x04:
            if flag == 0:
                flagString += 'RST'
                flag = 1
            else:
                flagString += ', RST'
        if tcpflag & 0x02:
            if flag == 0:
                flagString += 'SYN'
                flag = 1
            else:
                flagString += ', SYN'
        if tcpflag & 0x01:
            if flag == 0:
                flagString += 'FIN'
                flag = 1
            else:
                flagString += ', FIN'
        return flagString

    def choosedTCPPDUAnalysis(self):
    # 请在此处完成TCP协议的分析器(分析数据包功能)，并添加详细代码注释
        # scapy.layers.inet.TCP：参考群文件Scapy 状元笔记，或https://github.com/twfb/Scapy-Note
        # 十进制转十六进制函数hex()
        # 数值转字符串函数str()
        # 字符串转整数函数int()
        # 打印16进制格式字符串'0x%04x'
        # 整数转二进制函数self.intbin()
        # 协议类型字符串获取函数self.proto_IPcol()
        # IP校验和checksum计算参考课件3-IP+TCP+UDP协议-2.pptx中的40-45页self.IP_headchecksum()
        # TCP校验和checksum计算参考课件3-IP+TCP+UDP协议-2.pptx中的47页in4_chksum()
        
        choosePDUNum = self.listbox.curselection()[0] # 参考代码框架560行代码获取双击鼠标左键所选中的数据报的索引，https://blog.csdn.net/m0_46489757/article/details/131054701
        choosedPacket = self.sniffDataList[choosePDUNum] # 参考代码框架561行代码根据双击鼠标左键所选中的数据报的索引提取捕获队列里的相应数据报

        self.PDUAnalysisText.delete(1.0, END) # 参考代码框架150行代码清空协议详细解析动态窗口，1.0表示开始位置索引，END表示结束位置索引，https://blog.csdn.net/weixin_43097301/article/details/84206539

        # 计算TCP Flags
        # '''
        tcp_Flag = choosedPacket[TCP].flags
        flagTrans = self.tcpflag(tcp_Flag)
        self.PDUAnalysisText.insert(END,
                                    '    Flags: 0x%03x ' % int(choosedPacket[TCP].flags) + '(' + flagTrans + ')' + '\n')
        self.PDUAnalysisText.insert(END, '      000. .... .... = Reserved: Not set' + '\n')
        self.PDUAnalysisText.insert(END, '      ...0 .... .... = Nonce: Not set' + '\n')
        if tcp_Flag & 0x80:
            self.PDUAnalysisText.insert(END, '      .... 1... .... = Congestion Window Reduced(CWR): Set' + '\n')
        else:
            self.PDUAnalysisText.insert(END, '      .... 0... .... = Congestion Window Reduced(CWR): Not set' + '\n')
        self.PDUAnalysisText.insert(END, '请自己补充其余代码！' + '\n')
        # '''

    def choosedUDPPDUAnalysis(self):
    # 请在此处完成UDP协议的分析器(分析数据包功能)，并添加详细代码注释
        # scapy.layers.inet.UDP：参考群文件Scapy 状元笔记，或https://github.com/twfb/Scapy-Note
        # 十进制转十六进制函数hex()
        # 数值转字符串函数str()
        # 字符串转整数函数int()
        # 打印16进制格式字符串'0x%04x'
        # 整数转二进制函数self.intbin()
        # 协议类型字符串获取函数self.proto_IPcol()
        # IP校验和checksum计算参考课件3-IP+TCP+UDP协议-2.pptx中的40-45页self.IP_headchecksum()
        # UDP校验和checksum计算参考课件3-IP+TCP+UDP协议-2.pptx中的46页in4_chksum()

        choosePDUNum = self.listbox.curselection()[0] # 参考代码框架560行代码获取双击鼠标左键所选中的数据报的索引，https://blog.csdn.net/m0_46489757/article/details/131054701
        choosedPacket = self.sniffDataList[choosePDUNum] # 参考代码框架561行代码根据双击鼠标左键所选中的数据报的索引提取捕获队列里的相应数据报

        self.PDUAnalysisText.delete(1.0, END) # 参考代码框架150行代码清空协议详细解析动态窗口，1.0表示开始位置索引，END表示结束位置索引，https://blog.csdn.net/weixin_43097301/article/details/84206539

        self.PDUAnalysisText.insert(END, '请自己补充其余代码！' + '\n')                

app = Application()
app.mainloop()
