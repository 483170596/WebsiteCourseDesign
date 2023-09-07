from tkinter import *
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as messagebox
from tkinter import Tk, PanedWindow
from tkinter.ttk import Treeview, Style, Combobox, Checkbutton
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

# class Application(tk.Tk):

window = tk.Tk()  # 创建主窗体对象
window.title("协议编辑器")  # 设置窗口标题
window.geometry("1000x800")
# window.state("zoomed")
mainPanedWindow = PanedWindow(window, sashrelief=RAISED, sashwidth=5)
protocolsTree = Treeview()


# 协议导航树单击事件响应
def on_click_protocols_tree(event):
    select_item = event.widget.selection()
    for widget in protocolEditorFrame.winfo_children():
        widget.destroy()
    if select_item[0] == "Mac":
        print("MAC帧")
        create_mac_sender()
    elif select_item[0] == "ARP":
        print("ARP包")
        create_arp_sender()
    elif select_item[0] == "IP":
        print("IP包")
        create_ip_sender()
        pass
    elif select_item[0] == "TCP":
        print("TCP包")
        create_tcp_sender()
        pass
    elif select_item[0] == "UDP":
        print("UDP包")
        create_udp_sender()
        pass


def createProtocolsTree():
    # 创建协议导航树
    # return: 协议导航树
    protocolsTree.heading("#0", text="选择网络协议", anchor="w")

    # 传输层
    transfer_layer_tree_entry = protocolsTree.insert("", 1, "传输层", text="传输层")
    tcp_packet_tree_entry = protocolsTree.insert(transfer_layer_tree_entry, 0, "TCP", text="TCP")
    udp_packet_tree_entry = protocolsTree.insert(transfer_layer_tree_entry, 1, "UDP", text="UDP")
    # 网络层
    ip_layer_tree_entry = protocolsTree.insert("", 2, "网络层", text="网络层")
    ip_packet_tree_entry = protocolsTree.insert(ip_layer_tree_entry, 0, "IP", text="IP")
    arp_packet_tree_entry = protocolsTree.insert(ip_layer_tree_entry, 2, "ARP", text="ARP")

    # 网络接入层
    ether_layer_tree_entry = protocolsTree.insert("", 3, "网络接入层", text="网络接入层")
    mac_frame_tree_entry = protocolsTree.insert(ether_layer_tree_entry, 1, "Mac", text="Mac")
    protocolsTree.bind("<<TreeviewSelect>>", on_click_protocols_tree)
    style = Style(window)
    # get disabled entry colors
    disabled_bg = style.lookup("TEntry", "fieldbackground", ("disabled",))
    style.map("Treeview",
              fieldbackground=[("disabled", disabled_bg)],
              foreground=[("disabled", "gray")],
              background=[("disabled", disabled_bg)])
    protocolsTree.pack()
    return protocolsTree


dstMacEntry = Entry()
payloadEntry = Entry()
countEntry = Entry()
resultText = Text()
dstIpEntry = Entry()
srcIpEntry = Entry()
ARPnetworkcombo = Combobox()
ARPprotocombo = Combobox()
ARPopcombo = Combobox()


def create_mac_sender():
    global dstMacEntry, payloadEntry, countEntry, resultText
    etherFrame = Frame(protocolEditorFrame)
    dstMacLabel = Label(etherFrame, text="请输入目的Mac", font=("Time New Roman", 10))
    dstMacLabel.pack()
    # dstMacLabel.place(x=70,y=80)#调整标签位置
    # 设置目的Mac地址输入文本框，将文本框放置于窗体
    dstMac = StringVar(value="FF:FF:FF:FF:FF:FF")  # 定义目的Mac地址的默认值
    dstMacEntry = Entry(etherFrame, show=None, textvariable=dstMac, font=("Time New Roman", 10))
    dstMacEntry.pack()
    # dstMacEntry.place(x=200,y=80)#调整文本框的位置

    # srcMac=StringVar(value="aa:aa:aa:aa:aa:aa")

    # 关于负载数据
    payloadLabel = Label(etherFrame, text="请输入负载数据", font=("Time New Roman", 10))  # 在窗体中创建一个提示负载数据输入的标签
    payloadLabel.pack()  # 显示标签，pack方法用于将标签放在窗体的默认位置，自动调节尺寸
    # dstMac.place(x=70,y=80)#调整标签位置
    # 设置目的Mac地址输入文本框，将文本框放置于窗体
    payload = StringVar(value="660341124张三丰")  # 定义负载数据的默认值
    payloadEntry = Entry(etherFrame, show=None, textvariable=payload, font=("Time New Roman", 10))
    payloadEntry.pack()
    # payloadEntry.place(x=200,y=120)

    # 关于数据帧发送
    intLabel = Label(etherFrame, text="请输入发送次数", font=("Time New Roman", 10))  # 在窗体中创建一个提示发送次数输入的标签
    intLabel.pack()
    # intLabel.place(x=70,y=160)
    # 设置数据帧发送次数的输入文本框，将文本框放置于窗体
    count = StringVar(value="5")  # 定义数据帧发送次数的默认值，字符类型
    countEntry = Entry(etherFrame, show=None, textvariable=count, font=("Time New Roman", 10))
    countEntry.pack()
    # countEntry.place(x=200,y=160)

    # 定义结果显示框和滚动条
    resultTextFrame = Frame(etherFrame)  # Frame就是屏幕上的一块区域，用来作为容器布局窗体
    resultText = Text(resultTextFrame, height=25)  # 创建多行文本框，以显示发送数据帧的信息
    s = Scrollbar(resultTextFrame, orient=VERTICAL)  # 设置垂直滚动条，Scrollbar(滚动条)组件用于滚动一些组建的可见范围，
    # 根据方向可分为垂直滚动条和水平滚动条
    # Scrollbar组件常常被用于实现文本，画布和列表框的滚动
    s.pack(side=RIGHT, fill=Y)  # 显示滚动条，并将它充满Y轴
    # 在resultText组件上安装垂直滚动条,需要做的两件事
    s.config(command=resultText.yview)  # 滚动条关联文本框，设置Scrollbar组件的command选项为该组件的yview(方法)
    resultText["yscrollcommand"] = s.set  # 文本框关联滚动条，设置组件的属性值可以像引用数组的元素一样引用，s.set后面不加()
    # 设置resultText组件的yscrollbarcommand选项为Scrollbar组件的set()方法
    resultText.pack(side=LEFT, fill=BOTH)
    resultTextFrame.pack()  # 在window窗体中的位置，设置为低部对齐

    sendButton = Button(etherFrame, text=("发送"), command=sendEtherFrame)
    sendButton.pack()
    etherFrame.pack()


def sendEtherFrame():
    # 请在此处完成MAC协议的编辑器(发送数据包功能)，并添加详细代码注释
    pass


def create_arp_sender():
    global dstMacEntry, payloadEntry, countEntry, resultText, dstIpEntry
    etherFrame = Frame(protocolEditorFrame)

    dstMacLabel = Label(etherFrame, text="请输入目的Mac", font=("Time New Roman", 10))
    dstMacLabel.pack()
    # dstMacLabel.place(x=70,y=80)#调整标签位置
    # 设置目的Mac地址输入文本框，将文本框放置于窗体
    dstMac = StringVar(value="FF:FF:FF:FF:FF:FF")  # 定义目的Mac地址的默认值
    dstMacEntry = Entry(etherFrame, show=None, textvariable=dstMac, font=("Time New Roman", 10))
    dstMacEntry.pack()
    # dstMacEntry.place(x=200,y=80)#调整文本框的位置

    # srcMac=StringVar(value="aa:aa:aa:aa:aa:aa")
    # 设置目的ip地址的输入文本框，将文本框放置于窗体
    dstIpLabel = Label(etherFrame, text="请输入目的Ip", font=("Time New Roman", 10))
    dstIpLabel.pack()
    dstIp = StringVar(value="255.255.255.255")
    dstIpEntry = Entry(etherFrame, show=None, textvariable=dstIp, font=("Time New Roman", 10))
    dstIpEntry.pack()

    # 关于负载数据
    payloadLabel = Label(etherFrame, text="请输入负载数据", font=("Time New Roman", 10))  # 在窗体中创建一个提示负载数据输入的标签
    payloadLabel.pack()  # 显示标签，pack方法用于将标签放在窗体的默认位置，自动调节尺寸
    # dstMac.place(x=70,y=80)#调整标签位置
    # 设置目的Mac地址输入文本框，将文本框放置于窗体
    payload = StringVar(value="660341124张三丰")  # 定义负载数据的默认值
    payloadEntry = Entry(etherFrame, show=None, textvariable=payload, font=("Time New Roman", 10))
    payloadEntry.pack()
    # payloadEntry.place(x=200,y=120)

    # 关于数据帧发送
    intLabel = Label(etherFrame, text="请输入发送次数", font=("Time New Roman", 10))  # 在窗体中创建一个提示发送次数输入的标签
    intLabel.pack()
    # intLabel.place(x=70,y=160)
    # 设置数据帧发送次数的输入文本框，将文本框放置于窗体
    count = StringVar(value="5")  # 定义数据帧发送次数的默认值，字符类型
    countEntry = Entry(etherFrame, show=None, textvariable=count, font=("Time New Roman", 10))
    countEntry.pack()
    # countEntry.place(x=200,y=160)

    # 运行ARP的网络类型
    networktypeLabel = Label(etherFrame, text="运行arp的网络类型", font=("Time New Roman", 10))
    networktypeLabel.pack()
    ARPnetworkcombo = Combobox(etherFrame, font=("Time New Roman", 10), show=None)
    ARPnetworkcombo["value"] = ("以太网", "FDDI", "令牌环网")
    ARPnetworkcombo.current(0)
    ARPnetworkcombo.pack()

    # 关于协议类型
    prototypeLabel = Label(etherFrame, text="运行arp的协议类型", font=("Time New Roman", 10))
    prototypeLabel.pack()
    ARPprotocombo = Combobox(etherFrame, font=("Time New Roman", 10), show=None)
    ARPprotocombo["value"] = ("IPV4")
    ARPprotocombo.current(0)
    ARPprotocombo.pack()

    # 关于arp操作码
    optypeLabel = Label(etherFrame, text="ARP操作类型", font=("Time New Roman", 10))
    optypeLabel.pack()
    ARPopcombo = Combobox(etherFrame, font=("Time New Roman", 10), show=None)
    ARPopcombo["value"] = ("请求", "应答")
    ARPopcombo.current(0)
    ARPopcombo.pack()

    # 定义结果显示框和滚动条
    resultTextFrame = Frame(etherFrame)  # Frame就是屏幕上的一块区域，用来作为容器布局窗体
    resultText = Text(resultTextFrame, height=25)  # 创建多行文本框，以显示发送数据帧的信息
    s = Scrollbar(resultTextFrame, orient=VERTICAL)  # 设置垂直滚动条，Scrollbar(滚动条)组件用于滚动一些组建的可见范围，
    # 根据方向可分为垂直滚动条和水平滚动条
    # Scrollbar组件常常被用于实现文本，画布和列表框的滚动
    s.pack(side=RIGHT, fill=Y)  # 显示滚动条，并将它充满Y轴
    # 在resultText组件上安装垂直滚动条,需要做的两件事
    s.config(command=resultText.yview)  # 滚动条关联文本框，设置Scrollbar组件的command选项为该组件的yview(方法)
    resultText["yscrollcommand"] = s.set  # 文本框关联滚动条，设置组件的属性值可以像引用数组的元素一样引用，s.set后面不加()
    # 设置resultText组件的yscrollbarcommand选项为Scrollbar组件的set()方法
    resultText.pack(side=LEFT, fill=BOTH)
    resultTextFrame.pack()  # 在window窗体中的位置，设置为低部对齐

    sendButton = Button(etherFrame, text=("发送"), command=sendArp)
    sendButton.pack()
    etherFrame.pack()


def sendArp():
    # 请在此处完成ARP协议的编辑器(发送数据包功能)，并添加详细代码注释
    pass


def headchecksum(head):
    checksum = 0
    headlen = len(head)
    if headlen % 2 == 1:
        head += b"\0"
    i = 0
    while i < headlen:
        temp = struct.unpack("!H", head[i:i + 2])[0]
        # print("%04x"%temp)
        checksum = checksum + temp
        i += 2
    # 将高16bit与低16bit相加
    checksum = (checksum >> 16) + (checksum & 0xffff)
    # 将进位到高位的16bit与低16bit再相加
    checksum = checksum + (checksum >> 16)
    return ~checksum & 0xffff


IPversioncombo = Combobox()


def create_ip_sender():
    global payloadEntry, countEntry, resultText, dstIpEntry, IPversioncombo
    etherFrame = Frame(protocolEditorFrame)
    # srcMac=StringVar(value="aa:aa:aa:aa:aa:aa")
    # 设置目的ip地址的输入文本框，将文本框放置于窗体
    dstIpLabel = Label(etherFrame, text="请输入目的Ip", font=("Time New Roman", 10))
    dstIpLabel.pack()
    dstIp = StringVar(value="255.255.255.255")
    dstIpEntry = Entry(etherFrame, show=None, textvariable=dstIp, font=("Time New Roman", 10))
    dstIpEntry.pack()

    # 设置源IP地址的输入模块
    srcIpLabel = Label(etherFrame, text="请输入源Ip", font=("Time New Roman", 10))
    srcIpLabel.pack()
    srcIpEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="255.255.255.255"),
                       font=("Time New Roman", 10))
    srcIpEntry.pack()

    # 设置IP数据包的版本，有IPV4和IPV6两个版本
    IPversionLabel = Label(etherFrame, text="IP版本选择", font=("Time New Roman", 10))
    IPversionLabel.pack()
    IPversioncombo = Combobox(etherFrame, font=("Time New Roman", 10), show=None)
    IPversioncombo["value"] = ("IPV4", "IPV6")
    IPversioncombo.current(0)
    IPversioncombo.pack()

    # 设置负载数据部分
    payloadLabel = Label(etherFrame, text="负载数据部分", font=("Time New Roman", 10))
    payloadLabel.pack()
    payloadEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="660341124"), font=("Time New Roman", 10))
    payloadEntry.pack()

    # 关于数据帧发送
    intLabel = Label(etherFrame, text="请输入发送次数", font=("Time New Roman", 10))  # 在窗体中创建一个提示发送次数输入的标签
    intLabel.pack()
    # intLabel.place(x=70,y=160)
    # 设置数据帧发送次数的输入文本框，将文本框放置于窗体
    count = StringVar(value="5")  # 定义数据帧发送次数的默认值，字符类型
    countEntry = Entry(etherFrame, show=None, textvariable=count, font=("Time New Roman", 10))
    countEntry.pack()

    # 定义结果显示框和滚动条
    resultTextFrame = Frame(etherFrame)  # Frame就是屏幕上的一块区域，用来作为容器布局窗体
    resultText = Text(resultTextFrame, height=25)  # 创建多行文本框，以显示发送数据帧的信息
    s = Scrollbar(resultTextFrame, orient=VERTICAL)  # 设置垂直滚动条，Scrollbar(滚动条)组件用于滚动一些组建的可见范围，
    # 根据方向可分为垂直滚动条和水平滚动条
    # Scrollbar组件常常被用于实现文本，画布和列表框的滚动
    s.pack(side=RIGHT, fill=Y)  # 显示滚动条，并将它充满Y轴
    # 在resultText组件上安装垂直滚动条,需要做的两件事
    s.config(command=resultText.yview)  # 滚动条关联文本框，设置Scrollbar组件的command选项为该组件的yview(方法)
    resultText["yscrollcommand"] = s.set  # 文本框关联滚动条，设置组件的属性值可以像引用数组的元素一样引用，s.set后面不加()
    # 设置resultText组件的yscrollbarcommand选项为Scrollbar组件的set()方法
    resultText.pack(side=LEFT, fill=BOTH)
    resultTextFrame.pack()  # 在window窗体中的位置，设置为低部对齐

    sendButton = Button(etherFrame, text=("发送"), command=sendIp)
    sendButton.pack()
    etherFrame.pack()


def sendIp():
    # 请在此处完成IP协议的编辑器(发送数据包功能)，并添加详细代码注释
    pass


srcPortEntry = Entry()
dstPortEntry = Entry()


def create_udp_sender():
    global payloadEntry, countEntry, resultText, dstIpEntry, IPversioncombo, srcIpEntry, srcPortEntry, dstPortEntry
    etherFrame = Frame(protocolEditorFrame)
    # 设置目的ip地址的输入文本框，将文本框放置于窗体
    dstIpLabel = Label(etherFrame, text="请输入目的Ip", font=("Time New Roman", 10))
    dstIpLabel.pack()
    dstIp = StringVar(value="255.255.255.255")
    dstIpEntry = Entry(etherFrame, show=None, textvariable=dstIp, font=("Time New Roman", 10))
    dstIpEntry.pack()

    # 设置源IP地址的输入模块
    srcIpLabel = Label(etherFrame, text="请输入源Ip", font=("Time New Roman", 10))
    srcIpLabel.pack()
    srcIpEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="255.255.255.255"),
                       font=("Time New Roman", 10))
    srcIpEntry.pack()

    # 设置IP数据包的版本，有IPV4和IPV6两个版本
    IPversionLabel = Label(etherFrame, text="IP版本选择", font=("Time New Roman", 10))
    IPversionLabel.pack()
    IPversioncombo = Combobox(etherFrame, font=("Time New Roman", 10), show=None)
    IPversioncombo["value"] = ("IPV4", "IPV6")
    IPversioncombo.current(0)
    IPversioncombo.pack()

    # 设置upd源端口
    srcPortLabel = Label(etherFrame, text="请输入源端口", font=("Time New Roman", 10))
    srcPortLabel.pack()
    srcPortEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="0000"), font=("Time New Roman", 10))
    srcPortEntry.pack()

    # 设置udp目的端口
    dstPortLabel = Label(etherFrame, text="请输入源端口", font=("Time New Roman", 10))
    dstPortLabel.pack()
    dstPortEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="0000"), font=("Time New Roman", 10))
    dstPortEntry.pack()
    # 设置负载数据部分
    payloadLabel = Label(etherFrame, text="负载数据部分", font=("Time New Roman", 10))
    payloadLabel.pack()
    payloadEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="660341124"), font=("Time New Roman", 10))
    payloadEntry.pack()

    # 关于数据帧发送
    intLabel = Label(etherFrame, text="请输入发送次数", font=("Time New Roman", 10))  # 在窗体中创建一个提示发送次数输入的标签
    intLabel.pack()
    # intLabel.place(x=70,y=160)
    # 设置数据帧发送次数的输入文本框，将文本框放置于窗体
    count = StringVar(value="5")  # 定义数据帧发送次数的默认值，字符类型
    countEntry = Entry(etherFrame, show=None, textvariable=count, font=("Time New Roman", 10))
    countEntry.pack()

    # 定义结果显示框和滚动条
    resultTextFrame = Frame(etherFrame)  # Frame就是屏幕上的一块区域，用来作为容器布局窗体
    resultText = Text(resultTextFrame, height=25)  # 创建多行文本框，以显示发送数据帧的信息
    s = Scrollbar(resultTextFrame, orient=VERTICAL)  # 设置垂直滚动条，Scrollbar(滚动条)组件用于滚动一些组建的可见范围，
    # 根据方向可分为垂直滚动条和水平滚动条
    # Scrollbar组件常常被用于实现文本，画布和列表框的滚动
    s.pack(side=RIGHT, fill=Y)  # 显示滚动条，并将它充满Y轴
    # 在resultText组件上安装垂直滚动条,需要做的两件事
    s.config(command=resultText.yview)  # 滚动条关联文本框，设置Scrollbar组件的command选项为该组件的yview(方法)
    resultText["yscrollcommand"] = s.set  # 文本框关联滚动条，设置组件的属性值可以像引用数组的元素一样引用，s.set后面不加()
    # 设置resultText组件的yscrollbarcommand选项为Scrollbar组件的set()方法
    resultText.pack(side=LEFT, fill=BOTH)
    resultTextFrame.pack()  # 在window窗体中的位置，设置为低部对齐

    sendButton = Button(etherFrame, text=("发送"), command=sendUdp)
    sendButton.pack()
    etherFrame.pack()


def sendUdp():
    # 请在此处完成UDP协议的编辑器(发送数据包功能)，并添加详细代码注释
    pass


windowEntry = Entry()
tcpctrl1 = Checkbutton()
ctrl1 = StringVar(value="0")
tcpctrl2 = Checkbutton()
ctrl2 = StringVar(value="0")
tcpctrl3 = Checkbutton()
ctrl3 = StringVar(value="0")
tcpctrl4 = Checkbutton()
ctrl4 = StringVar(value="0")
tcpctrl5 = Checkbutton()
ctrl5 = StringVar(value="0")
tcpctrl6 = Checkbutton()
ctrl6 = StringVar(value="0")

tcpseqEntry = Entry()
tcpackEntry = Entry()


def create_tcp_sender():
    global payloadEntry, countEntry, resultText, dstIpEntry, IPversioncombo, srcIpEntry, srcPortEntry, dstPortEntry, windowEntry, tcpseqEntry, tcpackEntry
    etherFrame = Frame(protocolEditorFrame)
    # 设置目的ip地址的输入文本框，将文本框放置于窗体
    dstIpLabel = Label(etherFrame, text="请输入目的Ip", font=("Time New Roman", 10))
    dstIpLabel.pack()
    dstIp = StringVar(value="255.255.255.255")
    dstIpEntry = Entry(etherFrame, show=None, textvariable=dstIp, font=("Time New Roman", 10))
    dstIpEntry.pack()

    # 设置源IP地址的输入模块
    srcIpLabel = Label(etherFrame, text="请输入源Ip", font=("Time New Roman", 10))
    srcIpLabel.pack()
    srcIpEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="255.255.255.255"),
                       font=("Time New Roman", 10))
    srcIpEntry.pack()

    # 设置tcp源端口
    srcPortLabel = Label(etherFrame, text="请输入源端口", font=("Time New Roman", 10))
    srcPortLabel.pack()
    srcPortEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="0000"), font=("Time New Roman", 10))
    srcPortEntry.pack()

    # 设置tcp目的端口
    dstPortLabel = Label(etherFrame, text="请输入目的端口", font=("Time New Roman", 10))
    dstPortLabel.pack()
    dstPortEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="0000"), font=("Time New Roman", 10))
    dstPortEntry.pack()

    # 设置我方窗口值的大小
    windowLabel = Label(etherFrame, text="请输入当前我们的窗口值大小", font=("Time New Roman", 10))
    windowLabel.pack()
    windowEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="1000"), font=("Time New Roman", 10))
    windowEntry.pack()

    # 设置6个控制位
    tcpctrl1 = Checkbutton(etherFrame, text="紧急位", onvalue=1, offvalue=0, variable=ctrl1)
    tcpctrl2 = Checkbutton(etherFrame, text="确认位", onvalue=1, offvalue=0, variable=ctrl2)
    tcpctrl3 = Checkbutton(etherFrame, text="推送位", onvalue=1, offvalue=0, variable=ctrl3)
    tcpctrl4 = Checkbutton(etherFrame, text="复位", onvalue=1, offvalue=0, variable=ctrl4)
    tcpctrl5 = Checkbutton(etherFrame, text="同步位", onvalue=1, offvalue=0, variable=ctrl5)
    tcpctrl6 = Checkbutton(etherFrame, text="终止位", onvalue=1, offvalue=0, variable=ctrl6)
    tcpctrl1.pack()
    tcpctrl2.pack()
    tcpctrl3.pack()
    tcpctrl4.pack()
    tcpctrl5.pack()
    tcpctrl6.pack()

    # 设置序号
    tcpseqLabel = Label(etherFrame, text="序列号", font=("Time New Roman", 10))
    tcpseqLabel.pack()
    tcpseqLabel.place(x=30, y=300)
    tcpseqEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="100000"), font=("Time New Roman", 10))
    tcpseqEntry.pack()
    tcpseqEntry.place(x=30, y=320)

    # 设置确认号
    tcpackLabel = Label(etherFrame, text="确认号", font=("Time New Roman", 10))
    tcpackLabel.pack()
    tcpackLabel.place(x=350, y=300)
    tcpackEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="100000"), font=("Time New Roman", 10))
    tcpackEntry.pack()
    tcpackEntry.place(x=350, y=320)

    # 设置负载数据部分
    payloadLabel = Label(etherFrame, text="负载数据部分", font=("Time New Roman", 10))
    payloadLabel.pack()
    payloadEntry = Entry(etherFrame, show=None, textvariable=StringVar(value="660341124"), font=("Time New Roman", 10))
    payloadEntry.pack()

    # 关于数据帧发送
    intLabel = Label(etherFrame, text="请输入发送次数", font=("Time New Roman", 10))  # 在窗体中创建一个提示发送次数输入的标签
    intLabel.pack()
    # intLabel.place(x=70,y=160)
    # 设置数据帧发送次数的输入文本框，将文本框放置于窗体
    count = StringVar(value="5")  # 定义数据帧发送次数的默认值，字符类型
    countEntry = Entry(etherFrame, show=None, textvariable=count, font=("Time New Roman", 10))
    countEntry.pack()

    # 定义结果显示框和滚动条
    resultTextFrame = Frame(etherFrame)  # Frame就是屏幕上的一块区域，用来作为容器布局窗体
    resultText = Text(resultTextFrame, height=25)  # 创建多行文本框，以显示发送数据帧的信息
    s = Scrollbar(resultTextFrame, orient=VERTICAL)  # 设置垂直滚动条，Scrollbar(滚动条)组件用于滚动一些组建的可见范围，
    # 根据方向可分为垂直滚动条和水平滚动条
    # Scrollbar组件常常被用于实现文本，画布和列表框的滚动
    s.pack(side=RIGHT, fill=Y)  # 显示滚动条，并将它充满Y轴
    # 在resultText组件上安装垂直滚动条,需要做的两件事
    s.config(command=resultText.yview)  # 滚动条关联文本框，设置Scrollbar组件的command选项为该组件的yview(方法)
    resultText["yscrollcommand"] = s.set  # 文本框关联滚动条，设置组件的属性值可以像引用数组的元素一样引用，s.set后面不加()
    # 设置resultText组件的yscrollbarcommand选项为Scrollbar组件的set()方法
    resultText.pack(side=LEFT, fill=BOTH)
    resultTextFrame.pack()  # 在window窗体中的位置，设置为低部对齐

    sendButton = Button(etherFrame, text=("发送"), command=sendTcp)
    sendButton.pack()
    etherFrame.pack()


def sendTcp():
    # 请在此处完成TCP协议的编辑器(发送数据包功能)，并添加详细代码注释
    pass


mainPanedWindow.add(createProtocolsTree())
protocolEditorFrame = Frame()
mainPanedWindow.add(protocolEditorFrame)
mainPanedWindow.pack(fill=BOTH, expand=1)

window.mainloop()
