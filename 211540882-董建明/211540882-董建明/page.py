import tkinter as tk
from analysis import *
from control import *


class Application(tk.Tk):
    # 初始化
    def __init__(self):
        tk.Tk.__init__(self)

        self.count = None
        self.countAct = None
        self.mainPDUShowWindow = None
        self.countInput = None
        self.conditionInput = None
        self.startListenButton = None
        self.stopListenButton = None
        self.listbox = None
        self.PDUAnalysisText = None
        self.PDUCodeText = None

        self.sniffFlag = True  # 设置控制捕获线程运行的标志变量
        self.sniffDataList = []
        self.sniff_times = []  # 捕获时间

        self.createWidgets()

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
        """TODO pack()布局修改成grid()布局方便添加单选组件"""
        controlFrame = Frame()
        Label(controlFrame, text='请输入待捕获的数据帧数：').grid(row=0, column=1, columnspan=7)  # 请输入待捕获的数据帧数：
        countvar = StringVar(value='0')
        self.countInput = Entry(controlFrame, textvariable=countvar, width=6)
        self.countInput.grid(row=1, column=1, columnspan=7)  # [动态] 输入框
        Label(controlFrame, text='请输入捕获条件：').grid(row=2, column=1, columnspan=7)  # 请输入捕获条件
        self.conditionInput = Entry(controlFrame, width=60)
        self.conditionInput.grid(row=3, column=1, columnspan=7)  # [动态] 输入框
        
        # TODO 创建一组单选按钮
        self._quick_selection(controlFrame)
        
        # 在创建控制面板设置startListenButton按键
        self.startListenButton = Button(controlFrame, text='开始捕获', command=lambda: start_sniff(self))
        self.startListenButton.grid(row=5, column=1, columnspan=7)  # [动态] 开始捕获按钮
        # 在创建控制面板放置clearButton按钮
        Button(controlFrame, text='清空数据', command=lambda: clear_data(self)).grid(row=6, column=1, columnspan=7)
        # 在创建控制面板放置stopListenButton按钮
        self.stopListenButton = Button(controlFrame, text='停止捕获', command=lambda: stop_sniff(self))
        self.stopListenButton.grid(row=7, column=1, columnspan=7)  # [动态] 停止捕获按钮
        controlFrame.pack(side=TOP, fill=Y)

    def _sel(self, selected_option):
        """ TODO 单选调用函数 """
        self.conditionInput.delete(0, END)
        self.conditionInput.insert(0, str(selected_option.get()))

    def _quick_selection(self, control_frame):
        """TODO 创建单选按钮组，设置不同的值和文本标签  将单选按钮排列在一行中"""
        selected_option = tk.StringVar()
        tk.Radiobutton(control_frame, text="清空", variable=selected_option, value="",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=0)
        tk.Radiobutton(control_frame, text="Ether", variable=selected_option, value="Ether",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=1)
        tk.Radiobutton(control_frame, text="ARP", variable=selected_option, value="ARP",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=2)
        tk.Radiobutton(control_frame, text="IP", variable=selected_option, value="IP",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=3)
        tk.Radiobutton(control_frame, text="IPv6", variable=selected_option, value="IPv6",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=4)
        tk.Radiobutton(control_frame, text="TCP", variable=selected_option, value="TCP",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=5)
        tk.Radiobutton(control_frame, text="UDP", variable=selected_option, value="UDP",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=6)
        tk.Radiobutton(control_frame, text="ICMP", variable=selected_option, value="ICMP",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=7)
        tk.Radiobutton(control_frame, text="DNS", variable=selected_option, value="DNS",
                       command=lambda: self._sel(selected_option)).grid(row=4, column=8)
        # 设置默认选中的选项
        selected_option.set("")

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
        self.listbox.bind('<Double-ButtonPress>', self.chosen_pdu_analysis)
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
        PDUCodeFrame = Frame()
        # 创建显示捕获数据的文本框
        self.PDUCodeText = Text(PDUCodeFrame)
        # 创建一个纵向滚动的滚动条，铺满Y方向
        s1 = Scrollbar(PDUCodeFrame, orient=VERTICAL)
        s1.pack(side=RIGHT, fill=Y)
        s1.config(command=self.PDUCodeText.yview)
        self.PDUCodeText['yscrollcommand'] = s1.set
        self.PDUCodeText.pack(fill=BOTH)
        self.mainPDUShowWindow.add(PDUCodeFrame)

    # 对选择的报文，判断其协议调用不同的分析函数 报文双击调用函数
    def chosen_pdu_analysis(self, event):
        chosen_pdu_num = self.listbox.curselection()[0]
        chosen_packet = self.sniffDataList[chosen_pdu_num]

        # TODO 捕获时间
        sniff_time = self.sniff_times[chosen_pdu_num]
        # TODO清空PDUAnalysisText，PDUCodeText控件内容
        self.PDUAnalysisText.delete('1.0', 'end')
        self.PDUCodeText.delete('1.0', 'end')

        # TODO IPv6 对选择的报文，判断其协议调用不同的分析函数 注意IPv6要放在IP前面，否则会直接去判断IP
        if self.conditionInput.get().find('IPv6') != -1:
            ipv6_pdu_analysis(self, chosen_packet)

        # TODO DNS 对选择的报文，判断其协议调用不同的分析函数
        elif self.conditionInput.get().find('DNS') != -1:
            dns_pdu_analysis(self, chosen_packet)

        # TODO ICMP对选择的报文，判断其协议调用不同的分析函数
        elif self.conditionInput.get().find('ICMP') != -1:
            icmp_pdu_analysis(self, chosen_packet)

        elif self.conditionInput.get().find('ARP') != -1:
            arp_pdu_analysis(self, chosen_packet, sniff_time)  # TODO ARP需要捕获时间传入
        elif self.conditionInput.get().find('Ether') != -1:
            ether_pdu_analysis(self, chosen_packet)
        elif self.conditionInput.get().find('TCP') != -1:
            tcp_pdu_analysis(self, chosen_packet)
        elif self.conditionInput.get().find('UDP') != -1:
            udp_pdu_analysis(self, chosen_packet)
        elif self.conditionInput.get().find('IP') != -1:
            ip_pdu_analysis(self, chosen_packet)
        elif self.conditionInput.get() == '':
            if chosen_packet.haslayer('IPv6'):  # TODO IPv6
                ipv6_pdu_analysis(self, chosen_packet)
            elif chosen_packet.haslayer('DNS'):  # TODO DNS
                dns_pdu_analysis(self, chosen_packet)
            elif chosen_packet.haslayer('ICMP'):  # TODO ICMP
                icmp_pdu_analysis(self, chosen_packet)
            elif chosen_packet.haslayer('ARP'):
                arp_pdu_analysis(self, chosen_packet, sniff_time)  # TODO ARP需要捕获时间传入
            elif chosen_packet.haslayer('Ether'):
                ether_pdu_analysis(self, chosen_packet)
            elif chosen_packet.haslayer('TCP'):
                tcp_pdu_analysis(self, chosen_packet)
            elif chosen_packet.haslayer('UDP'):
                udp_pdu_analysis(self, chosen_packet)
            elif chosen_packet.haslayer('IP'):
                ip_pdu_analysis(self, chosen_packet)
