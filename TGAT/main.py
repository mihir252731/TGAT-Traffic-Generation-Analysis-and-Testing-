import sys
import threading
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout,
    QComboBox, QSlider, QTextEdit, QTabWidget, QMainWindow, QGroupBox, QSizePolicy,
    QStatusBar, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QBrush, QPixmap
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

from traffic_generator import generate_traffic, log_action
from performance_analyzer import analyze_network
from attack_simulator import syn_flood, ddos_attack

class TGATTabs(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Tool")
        self.setGeometry(100, 100, 1200, 900)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.status = QStatusBar()
        self.setStatusBar(self.status)

        self.apply_theme()
        self.init_traffic_tab()
        self.init_analysis_tab()
        self.init_attack_tab()
        self.init_log_tab()

    def apply_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #001f3f;
                color: #FFFFFF;
                font-family: Segoe UI;
                font-size: 16px;
                font-weight: bold;
            }
            QGroupBox {
                border: 2px solid #00cc66;
                border-radius: 8px;
                margin-top: 10px;
                padding: 10px;
            }
            QLabel {
                color: #00ff99;
            }
            QPushButton {
                background-color: #009966;
                color: white;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #00cc66;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #ffffff;
                color: #000000;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QSlider::groove:horizontal {
                height: 10px;
                background: #888;
                border-radius: 5px;
            }
            QSlider::handle:horizontal {
                background: #00cc66;
                border: 1px solid #00aa55;
                width: 20px;
                margin: -5px 0;
                border-radius: 10px;
            }
        """)
        self.setAutoFillBackground(True)
        palette = QPalette()
        pixmap = QPixmap("abstract_bg.jpg")
        if not pixmap.isNull():
            palette.setBrush(QPalette.ColorRole.Window, QBrush(pixmap.scaled(
                self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding)))
            self.setPalette(palette)

    def add_labeled_slider(self, layout, label_text, slider, min_val, max_val, default_val):
        label = QLabel(f"{label_text}: {default_val}")
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(default_val)
        slider.setOrientation(Qt.Orientation.Horizontal)

        def update_label():
            value = slider.value()
            label.setText(f"{label_text}: {value}")

        slider.valueChanged.connect(update_label)
        layout.addWidget(label)
        layout.addWidget(slider)

    def timestamp(self):
        return datetime.now().strftime("%H:%M:%S")
    
    def init_traffic_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        group = QGroupBox("Traffic Generation")
        g_layout = QVBoxLayout()

        self.ip_input = QLineEdit("127.0.0.1")
        g_layout.addWidget(QLabel("Target IP Address"))
        g_layout.addWidget(self.ip_input)

        self.protocol_select = QComboBox()
        self.protocol_select.addItems(["TCP", "UDP", "ICMP"])
        g_layout.addWidget(QLabel("Protocol"))
        g_layout.addWidget(self.protocol_select)

        self.packet_size = QSlider()
        self.add_labeled_slider(g_layout, "Packet Size (bytes)", self.packet_size, 32, 1500, 100)

        self.packet_count = QSlider()
        self.add_labeled_slider(g_layout, "Number of Packets", self.packet_count, 1, 100, 10)

        self.delay_slider = QSlider()
        self.add_labeled_slider(g_layout, "Delay (x0.1s)", self.delay_slider, 0, 20, 1)

        start_button = QPushButton("Start Traffic")
        start_button.clicked.connect(self.start_traffic)
        g_layout.addWidget(start_button)

        group.setLayout(g_layout)
        layout.addWidget(group)
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Traffic")

    def start_traffic(self):
        dst = self.ip_input.text()
        protocol = self.protocol_select.currentText()
        size = self.packet_size.value()
        count = self.packet_count.value()
        delay = self.delay_slider.value() / 10.0

        threading.Thread(target=generate_traffic, args=(dst, protocol, size, count, delay)).start()
        log_action(f"Sent {count} {protocol} packets to {dst}")
        self.status.showMessage(f"[{self.timestamp()}] Traffic sent to {dst}", 5000)

    def init_analysis_tab(self):
        tab = QWidget()
        self.analysis_layout = QVBoxLayout()

        group = QGroupBox("Network Performance")
        layout = QHBoxLayout()

        left_panel = QVBoxLayout()
        self.analysis_ip = QLineEdit("8.8.8.8")
        left_panel.addWidget(QLabel("Target IP"))
        left_panel.addWidget(self.analysis_ip)

        self.ping_slider = QSlider()
        self.add_labeled_slider(left_panel, "Ping Count", self.ping_slider, 1, 20, 5)

        analyze_button = QPushButton("Analyze")
        analyze_button.clicked.connect(self.run_analysis)
        left_panel.addWidget(analyze_button)

        self.analyze_table = QTableWidget()
        self.analyze_table.setColumnCount(4)
        self.analyze_table.setHorizontalHeaderLabels(["Latency", "Jitter", "Loss", "Throughput"])
        self.analyze_table.setMinimumWidth(400)
        left_panel.addWidget(self.analyze_table)

        right_panel = QVBoxLayout()
        self.chart_canvas = FigureCanvas(plt.figure())
        self.chart_canvas.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        right_panel.addWidget(self.chart_canvas)

        self.next_graph_btn = QPushButton("Next Graph")
        self.next_graph_btn.clicked.connect(self.show_next_chart)
        self.next_graph_btn.setVisible(False)
        right_panel.addWidget(self.next_graph_btn)

        layout.addLayout(left_panel)
        layout.addLayout(right_panel)
        group.setLayout(layout)
        self.analysis_layout.addWidget(group)
        tab.setLayout(self.analysis_layout)
        self.tabs.addTab(tab, "Analyzer")

    def run_analysis(self):
        ip = self.analysis_ip.text()
        count = self.ping_slider.value()
        results = analyze_network(ip, count)
        self.status.showMessage(f"[{self.timestamp()}] Analyzing {ip}", 3000)

        self.chart_data = {"Latency": [], "Jitter": [], "Loss": [], "Throughput": []}
        self.analyze_table.setRowCount(len(results))

        for i, r in enumerate(results):
            self.chart_data["Latency"].append(r["latency"])
            self.chart_data["Jitter"].append(r["jitter (ms)"])
            self.chart_data["Loss"].append(r["packet loss"])
            self.chart_data["Throughput"].append(r["throughput (bps)"])
            self.analyze_table.setItem(i, 0, QTableWidgetItem(str(r["latency"])))
            self.analyze_table.setItem(i, 1, QTableWidgetItem(str(r["jitter (ms)"])))
            self.analyze_table.setItem(i, 2, QTableWidgetItem(str(r["packet loss"])))
            self.analyze_table.setItem(i, 3, QTableWidgetItem(str(r["throughput (bps)"])))

        self.chart_index = 0
        self.next_graph_btn.setVisible(True)
        self.show_next_chart()

    def show_next_chart(self):
        keys = list(self.chart_data.keys())
        label = keys[self.chart_index]
        data = self.chart_data[label]

        self.chart_canvas.figure.clf()
        ax = self.chart_canvas.figure.add_subplot(111)
        ax.plot(data, marker='o')
        ax.set_title(label)
        ax.set_xlabel("Ping #")
        ax.set_ylabel(label)
        ax.grid(True)
        self.chart_canvas.draw()

        self.chart_index = (self.chart_index + 1) % len(keys)

    def init_attack_tab(self):
        tab = QWidget()
        main_layout = QVBoxLayout()
        group = QGroupBox("Simulated Attacks")
        grid_layout = QVBoxLayout()
        input_layout = QVBoxLayout()

        self.attack_ip_input = QLineEdit("127.0.0.1")
        input_layout.addWidget(QLabel("Target IP"))
        input_layout.addWidget(self.attack_ip_input)

        self.attack_count_slider = QSlider()
        self.add_labeled_slider(input_layout, "Packets to Send", self.attack_count_slider, 10, 1000, 100)

        syn_button = QPushButton("SYN Flood")
        syn_button.clicked.connect(lambda: self.confirm_attack("syn"))
        ddos_button = QPushButton("DDoS Attack")
        ddos_button.clicked.connect(lambda: self.confirm_attack("ddos"))
        input_layout.addWidget(syn_button)
        input_layout.addWidget(ddos_button)

        grid_layout.addLayout(input_layout)
        group.setLayout(grid_layout)
        main_layout.addWidget(group)

        self.attack_status = QLabel("")
        self.attack_status.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(self.attack_status)

        tab.setLayout(main_layout)
        self.tabs.addTab(tab, "Attacks")

    def confirm_attack(self, attack_type):
        ip = self.attack_ip_input.text()
        count = self.attack_count_slider.value()
        msg = QMessageBox()
        msg.setWindowTitle("Confirm Attack")
        msg.setText(f"Are you sure you want to start a {attack_type.upper()} attack on {ip} with {count} packets?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        result = msg.exec()
        if result == QMessageBox.StandardButton.Yes:
            self.launch_attack(attack_type)

    def launch_attack(self, attack_type):
        ip = self.attack_ip_input.text()
        count = self.attack_count_slider.value()
        if attack_type == "syn":
            threading.Thread(target=syn_flood, args=(ip, count)).start()
            log_action(f"SYN flood to {ip} with {count} packets")
        else:
            threading.Thread(target=ddos_attack, args=(ip, count)).start()
            log_action(f"DDoS to {ip} with {count} packets")
        self.status.showMessage(f"[{self.timestamp()}] {attack_type.upper()} attack sent", 5000)
        self.attack_status.setText(f"{attack_type.upper()} attack sent to {ip}")

    def init_log_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(QLabel("Log Output"))
        layout.addWidget(self.log_display)

        load_button = QPushButton("Load Log")
        load_button.clicked.connect(self.load_log)
        clear_button = QPushButton("Clear Log")
        clear_button.clicked.connect(self.clear_log)
        export_button = QPushButton("Export Log")
        export_button.clicked.connect(self.export_log)

        button_layout = QHBoxLayout()
        button_layout.addWidget(load_button)
        button_layout.addWidget(clear_button)
        button_layout.addWidget(export_button)
        layout.addLayout(button_layout)

        tab.setLayout(layout)
        self.tabs.addTab(tab, "Logs")

    def load_log(self):
        try:
            with open("log.txt", "r") as f:
                self.log_display.setText(f.read())
        except FileNotFoundError:
            self.log_display.setText("No log file found.")

    def clear_log(self):
        open("log.txt", "w").close()
        self.log_display.setText("Log cleared.")

    def export_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Log", "log.txt", "Text Files (*.txt)")
        if path:
            with open("log.txt", "r") as src, open(path, "w") as dst:
                dst.write(src.read())
            self.status.showMessage(f"Log exported to {path}", 5000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TGATTabs()
    window.show()
    sys.exit(app.exec())
