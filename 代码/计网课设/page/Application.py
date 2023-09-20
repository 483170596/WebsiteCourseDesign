import tkinter as tk
from tkinter import *


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
        self.geometry('1000x800')  # 设置宽高
        self.title('协议分析器')
        self.count = 0  # 记录捕获数据帧的个数
        self.countAct = 0  # 实际捕获数据帧的个数
        # 创建并添加协议分析器控制组件及面板
        self.createControlWidgets()
        # 创建并添加协议分析主面板
        self.mainPDUShowWindow = PanedWindow(self, orient=tk.VERTICAL, sashrelief=RAISED, sashwidth=5)

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
        self.stopListenButton = Button(controlFrame, text='停止捕获', command=self.stop_sniff)
        self.stopListenButton.pack()
        controlFrame.pack(side=TOP, fill=Y)
