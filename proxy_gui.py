import sys
import logging
import os
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QWidget, QLineEdit, QLabel, QListWidget
)
from PyQt5.QtCore import QThread, Qt
from PyQt5.QtGui import QFont, QCursor
from urllib import request, error
import socketserver
from datetime import datetime
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

BLOCKED = []

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        url = self.request.recv(1024).decode().strip()
        if any(blocked["url"] in url for blocked in BLOCKED):
            self.request.sendall(b"Access Denied: Blocked URL")
            if hasattr(self.server, 'gui'):  
                self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Access Denied: {url}")
            return

        cache_key = hashlib.md5(url.encode()).hexdigest()
        cache_file = os.path.join("proxy_cache", cache_key)

        if os.path.exists(cache_file):
            with open(cache_file, "rb") as f:
                logging.info(f"Serving from cache: {url}")
                self.request.sendall(f.read())
                if hasattr(self.server, 'gui'): 
                    self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Served from cache: {url}")
                return

        try:
            req = request.Request(url)
            with request.urlopen(req) as response:
                content = response.read()
                with open(cache_file, "wb") as f:
                    f.write(content)
                self.request.sendall(content)
                if hasattr(self.server, 'gui'):  
                    self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Fetched and cached: {url}")
        except error.URLError as e:
            logging.error(f"Error fetching {url}: {e}")
            self.request.sendall(b"Internal Proxy Error")
            if hasattr(self.server, 'gui'):
                self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error fetching {url}: {e}")

class ProxyServer:
    def __init__(self, port=8080, gui=None):
        self.port = port
        self.httpd = None
        self.gui = gui

    def run(self):
        with socketserver.TCPServer(("", self.port), ProxyHandler) as httpd:
            httpd.RequestHandlerClass.gui = self.gui
            self.httpd = httpd
            logging.info(f"Proxy server running on port {self.port}")
            httpd.serve_forever()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            logging.info("Proxy server stopped")

class ProxyThread(QThread):
    def __init__(self, port=8080, gui=None):
        super().__init__()
        self.server = ProxyServer(port, gui)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.stop()

class ProxyGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Proxy Server")
        self.setGeometry(100, 100, 900, 700)
        self.setStyleSheet("background-color: #eeeeee;")

        # Central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()

        # Header
        self.header_label = QLabel("Python Proxy Server ")
        self.header_label.setAlignment(Qt.AlignCenter)
        self.header_label.setFont(QFont("Glacial Indifference", 14, QFont.Bold))
        self.header_label.setStyleSheet("color: #333; padding: 10px;")
        self.layout.addWidget(self.header_label)

        # Sub Header
        self.sub_header_label = QLabel("A proxy server with a graphical user interface (GUI) built using PyQt5.")
        self.sub_header_label.setAlignment(Qt.AlignCenter)
        self.sub_header_label.setFont(QFont("Glacial Indifference", 10, QFont.Bold))
        self.sub_header_label.setStyleSheet("color: #333; padding: 5px;")
        self.layout.addWidget(self.sub_header_label)

        # Logs Area
        self.log_area_label = QLabel("Server Logs:")
        self.log_area_label.setFont(QFont("Arial", 10))
        self.layout.addWidget(self.log_area_label)

        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Courier", 10))
        self.log_area.setStyleSheet("background-color: #ffffff; border: 1px solid #ccc;")
        self.layout.addWidget(self.log_area, stretch=2)

        # Controls
        controls_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Proxy", self)
        self.start_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.start_button.setStyleSheet(self.button_style("#28a745"))
        self.start_button.setFixedWidth(180)
        self.start_button.clicked.connect(self.start_proxy)

        self.stop_button = QPushButton("Stop Proxy", self)
        self.stop_button.setEnabled(False)
        self.stop_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.stop_button.setStyleSheet(self.button_style("#dc3545"))
        self.stop_button.setFixedWidth(180)
        self.stop_button.clicked.connect(self.stop_proxy)

        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        self.layout.addLayout(controls_layout)

        # Blocked URLs
        self.blocked_urls_label = QLabel("Blocked URLs/IPs with Timestamps:")
        self.blocked_urls_label.setFont(QFont("Arial", 10))
        self.layout.addWidget(self.blocked_urls_label)

        self.blocked_list = QListWidget(self)
        self.blocked_list.setStyleSheet("background-color: #ffffff; border: 1px solid #ccc;")
        self.layout.addWidget(self.blocked_list, stretch=1)

        block_input_layout = QHBoxLayout()
        self.block_url_input = QLineEdit(self)
        self.block_url_input.setPlaceholderText("Enter URL to block")
        self.block_url_input.setStyleSheet("padding: 5px; font-size: 14px;")
        block_input_layout.addWidget(self.block_url_input)

        self.add_block_button = QPushButton("Block URL", self)
        self.add_block_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.add_block_button.setStyleSheet(self.button_style("#007bff"))
        self.add_block_button.clicked.connect(self.add_to_blocked)
        block_input_layout.addWidget(self.add_block_button)

        self.layout.addLayout(block_input_layout)

        # Visualization
        self.graph_canvas = FigureCanvas(Figure(figsize=(6, 3)))
        self.layout.addWidget(self.graph_canvas)
        self.graph_ax = self.graph_canvas.figure.add_subplot(111)

        self.central_widget.setLayout(self.layout)
        self.proxy_thread = None
            # Footer
        self.footer_label = QLabel("Submitted by: Burhan Ahmad and Ifra Fazal ")
        self.footer_label.setAlignment(Qt.AlignCenter)
        self.footer_label.setFont(QFont("Glacial Indifference", 10, QFont.Normal))
        self.footer_label.setStyleSheet("color: #666; padding: 5px;")
        self.layout.addWidget(self.footer_label)

    def button_style(self, color):
        return f"""
        QPushButton {{
            background-color: {color};
            color: white;
            border: none;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
        }}
        QPushButton:hover {{
            background-color: {self.lighten_color(color, 20)};
        }}
        """

    def lighten_color(self, color, amount):
        color = color.lstrip("#")
        rgb = tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))
        return f"#{''.join(f'{min(255, int(c + amount)):#02x}'[2:] for c in rgb)}"

    def log_message(self, message):
        self.log_area.append(message)
        self.update_graph()

    def start_proxy(self):
        self.proxy_thread = ProxyThread(port=8080, gui=self)
        self.proxy_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_message("Proxy server started on port 8080")

    def stop_proxy(self):
        if self.proxy_thread:
            self.proxy_thread.stop()
            self.proxy_thread.wait()
            self.proxy_thread = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_message("Proxy server stopped")

    def add_to_blocked(self):
        new_url = self.block_url_input.text().strip()
        if new_url:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            BLOCKED.append({"url": new_url, "timestamp": timestamp})
            self.blocked_list.addItem(f"{new_url} - {timestamp}")
            self.log_message(f"Blocked URL/IP added: {new_url} at {timestamp}")
            self.block_url_input.clear()

    def update_graph(self):
        self.graph_ax.clear()
        self.graph_ax.bar(["Blocked", "Allowed"], [len(BLOCKED), 100 - len(BLOCKED)], color=["#ff6f61", "#6f9fff"])
        self.graph_ax.set_ylabel("Count")
        self.graph_ax.set_title("Blocked vs. Allowed URLs")
        self.graph_canvas.draw()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = ProxyGUI()
    gui.show()
    sys.exit(app.exec_())
