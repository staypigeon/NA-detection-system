import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QVBoxLayout, 
                           QWidget, QLabel, QPushButton, QTextEdit, QLineEdit, QProgressBar, QInputDialog) 
import subprocess
from PyQt6.QtCharts import QChart, QChartView, QPieSeries, QLineSeries
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPainter, QFont
import subprocess
import json
import os
import time
import locale
import io


class FlowCollectorThread(QThread):
    #用于在后台运行流量捕获的线程类
    result_signal = pyqtSignal(str)
    adapter_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)

    def __init__(self, interface_index=None, capture_count=1, param_value=1):
        super().__init__()
        self.interface_index = interface_index
        self.capture_count = capture_count
        self.param_value = param_value

    def run(self):
        try:
            if self.interface_index is None:
                # 搜索网卡
                self.result_signal.emit("加载中，请稍候...")
                process = subprocess.Popen(
                    ['python', './flow_collector/flow_collector.py'],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                stdout, stderr = process.communicate()
                # 先解码为GBK再转为UTF-8
                output = stdout.decode('gbk', errors='replace').encode('utf-8').decode('utf-8')
                self.adapter_signal.emit(output)

            else:
                # 流量捕获 
                self.result_signal.emit(f"使用捕获时间: {self.param_value} 分钟进行捕获")
                for capture_num in range(1, self.capture_count + 1):
                    self.result_signal.emit(f"正在进行第 {capture_num}/{self.capture_count} 次捕获...")
                    process = subprocess.Popen(
                        ['python', './flow_collector/flow_collector.py'],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    process.stdin.write(f'{self.interface_index}\n'.encode('gbk'))  # 编码发送
                    process.stdin.flush()

                    total_seconds = self.param_value * 60
                    for i in range(1, total_seconds + 1):
                        progress = int((i / total_seconds) * 100)
                        self.progress_signal.emit(progress)
                        self.result_signal.emit(f"第 {capture_num}/{self.capture_count} 次捕获进度: {i}/{total_seconds} 秒")
                        self.msleep(1000)

                    process.stdin.close()
                    stdout, stderr = process.communicate()

                # 保持原有文件处理逻辑
                output_dir = './flow_collector/output'
                flow_result = ''
                if os.path.exists(output_dir):
                    files = os.listdir(output_dir)
                    file_count = len(files)
                    flow_result = f"已捕获 {file_count} 个文件\n"
                    if files:
                        files = sorted(files, key=lambda x: os.path.getmtime(os.path.join(output_dir, x)), reverse=True)
                        for idx, file in enumerate(files[:self.capture_count]):
                            with open(os.path.join(output_dir, file), 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                flow_result += f"第 {idx + 1} 个文件捕获到 {len(data)} 个流量流\n"
                                for flow in data[:3]:
                                    flow_result += f"流信息: {flow['flow_key']}\n"

                if flow_result:
                    self.result_signal.emit(flow_result)

                if stderr:
                    error_output = stderr.decode('gbk', errors='replace').encode('utf-8').decode('utf-8')
                    self.result_signal.emit(f"错误信息: {error_output}")

        except Exception as e:
            self.result_signal.emit(f"流量捕获出错: {str(e)}")

class NetworkAttackMonitor(QMainWindow):
    """
    网络攻击检测系统的可视化主窗口类，用于展示实时监控、历史分析和管理界面。
    warning：此处为测试输出，非实例。
    """
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('网络攻击检测系统')
        self.setGeometry(100, 100, 1200, 800)

        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        real_time_tab = self.create_real_time_tab()
        tab_widget.addTab(real_time_tab, '实时监控')

        history_tab = self.create_history_tab()
        tab_widget.addTab(history_tab, '历史分析')

        management_tab = self.create_management_tab()
        tab_widget.addTab(management_tab, '管理界面')

        flow_tab = self.create_flow_tab()
        tab_widget.addTab(flow_tab, '流量捕获')

    def create_flow_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # 添加搜索网卡按钮
        self.search_adapter_button = QPushButton('搜索网卡')
        self.search_adapter_button.clicked.connect(self.search_adapters)
        layout.addWidget(self.search_adapter_button)

        # 初始化网卡显示区域
        self.adapter_text = QTextEdit()
        self.adapter_text.setReadOnly(True)
        layout.addWidget(self.adapter_text)

        # 初始隐藏输入框和开始按钮
        self.interface_input = QLineEdit()
        self.interface_input.setPlaceholderText('请输入要监听的网卡编号')
        self.interface_input.hide()
        layout.addWidget(self.interface_input)

        self.start_button = QPushButton('开始捕获流量')
        self.start_button.clicked.connect(self.start_flow_collection)
        self.start_button.hide()
        layout.addWidget(self.start_button)

        # 新增进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        tab.setLayout(layout)
        return tab

    def search_adapters(self):
        self.adapter_text.clear()
        self.adapter_thread = FlowCollectorThread()
        self.adapter_thread.adapter_signal.connect(self.show_adapters)
        self.adapter_thread.result_signal.connect(self.update_result_text)
        self.adapter_thread.start()

    def show_adapters(self, output):
        self.adapter_text.setPlainText(output)
        self.interface_input.show()
        self.start_button.show()

    def start_flow_collection(self):
        interface_index = self.interface_input.text()
        if not interface_index.isdigit():
            self.result_text.setPlainText("请输入有效的网卡编号")
            return
        
        # 弹出输入对话框，提示输入捕获流量的时间（整数分钟），默认值为 1
        capture_time, ok = QInputDialog.getInt(self, '输入捕获时间', '请输入捕获流量的时间（不超过30分钟）:', 1,1,30)
        if ok and capture_time > 30:
            pass
        elif not ok:
            capture_time = 1
        
        self.flow_thread = FlowCollectorThread(interface_index, capture_count=capture_time, param_value=capture_time)
        self.flow_thread.result_signal.connect(self.update_result_text)
        self.flow_thread.progress_signal.connect(self.update_progress_bar)  # 连接进度信号
        self.progress_bar.show()
        self.progress_bar.setValue(0)
        self.flow_thread.start()

    def update_result_text(self, result):
        self.result_text.setPlainText(result)

    def update_progress_bar(self, value):
        self.progress_bar.setValue(value)

    def create_real_time_tab(self):
        tab = QWidget()
        layout = QVBoxLayout() 

        heatmap_chart = self.create_heatmap_chart()
        heatmap_view = QChartView(heatmap_chart)
        heatmap_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        layout.addWidget(heatmap_view)

        attack_distribution_chart = self.create_attack_distribution_chart()
        attack_distribution_view = QChartView(attack_distribution_chart)
        attack_distribution_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        layout.addWidget(attack_distribution_view)

        tab.setLayout(layout)
        return tab

    def create_heatmap_chart(self):
        chart = QChart()
        chart.setTitle("实时流量热力图")
        # 示例：创建一个简单的饼图作为热力图的替代实现
        series = QPieSeries()
        series.append('流量类型 1', 30)
        series.append('流量类型 2', 20)
        series.append('流量类型 3', 50)
        chart.addSeries(series)
        return chart

    def create_attack_distribution_chart(self):
        series = QPieSeries()
        series.append('SQL注入', 20)
        series.append('XSS攻击', 15)
        series.append('DDoS攻击', 30)
        series.append('其他攻击', 35)

        chart = QChart()
        chart.addSeries(series)
        chart.setTitle('攻击类型分布')
        chart.setAnimationOptions(QChart.AnimationOption.AllAnimations)
        return chart

    def create_history_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        history_chart = self.create_history_chart()
        history_view = QChartView(history_chart)
        history_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        layout.addWidget(history_view)

        tab.setLayout(layout)
        return tab

    def create_history_chart(self):
        series = QLineSeries()
        series.append(0, 10)
        series.append(1, 20)
        series.append(2, 15)
        series.append(3, 25)

        chart = QChart()
        chart.addSeries(series)
        chart.setTitle('历史攻击趋势')
        chart.createDefaultAxes()
        chart.setAnimationOptions(QChart.AnimationOption.AllAnimations)
        return chart

    def create_management_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)
        return tab

if __name__ == '__main__':
    app = QApplication(sys.argv)
    monitor = NetworkAttackMonitor()
    monitor.show()
    sys.exit(app.exec())