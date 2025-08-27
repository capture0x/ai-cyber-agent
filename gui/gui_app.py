# gui/gui_app.py
import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel, QProgressBar,
    QListWidget, QTabWidget, QGroupBox, QFormLayout,
    QMessageBox, QFileDialog, QCheckBox, QDoubleSpinBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont

# Add core to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from core.agent import AICyberAgent
from core.config import Config

class ScanThread(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    progress_signal = pyqtSignal(int)
    
    def __init__(self, targets, config):
        super().__init__()
        self.targets = targets
        self.config = config
        
    def run(self):
        try:
            agent = AICyberAgent(self.targets, self.config)
            # Override the agent's logger to emit signals
            # This is a simplification; a full implementation would be more robust
            agent.run()
            self.output_signal.emit("[+] Scan completed and report generated.")
            self.progress_signal.emit(100)
        except Exception as e:
            self.output_signal.emit(f"[!] Error during scan: {e}")
        finally:
            self.finished_signal.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ AI Cyber Agent - Red Team Edition")
        self.setGeometry(100, 100, 1200, 800)
        
        self.setStyleSheet("""
            QMainWindow { background-color: #2b2b2b; }
            QWidget { background-color: #2b2b2b; color: #ffffff; font-family: 'Segoe UI', Arial, sans-serif; }
            QGroupBox { background-color: #363636; border: 2px solid #555555; border-radius: 8px; margin-top: 1ex; font-weight: bold; color: #4fc3f7; }
            QPushButton { background-color: #4fc3f7; border: none; color: #000000; padding: 8px 16px; border-radius: 4px; font-weight: bold; min-height: 30px; }
            QPushButton:hover { background-color: #29b6f6; }
            QPushButton:disabled { background-color: #757575; color: #bdbdbd; }
            QLineEdit, QDoubleSpinBox { background-color: #424242; border: 2px solid #555555; border-radius: 4px; padding: 6px; color: #ffffff; }
            QTextEdit, QListWidget { background-color: #1e1e1e; border: 2px solid #555555; border-radius: 4px; color: #ffffff; }
            QProgressBar { border: 2px solid #555555; border-radius: 4px; text-align: center; color: #ffffff; }
            QProgressBar::chunk { background-color: #4caf50; border-radius: 2px; }
            QTabWidget::pane { border: 2px solid #555555; border-radius: 4px; }
            QTabBar::tab { background-color: #424242; border: 1px solid #555555; padding: 8px 16px; color: #ffffff; font-weight: bold; }
            QTabBar::tab:selected { background-color: #4fc3f7; color: #000000; }
        """)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title_label = QLabel("🛡️ AI CYBER AGENT - RED TEAM EDITION")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #4fc3f7; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Settings
        settings_group = QGroupBox("⚙️ Scan Settings")
        settings_layout = QFormLayout()
        
        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("http://example.com/page?id=")
        self.add_target_btn = QPushButton("➕ Add Target")
        self.add_target_btn.clicked.connect(self.add_target)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(self.target_input)
        target_layout.addWidget(self.add_target_btn)
        settings_layout.addRow("🌐 Target URL:", target_layout)
        
        # Target list
        self.target_list = QListWidget()
        self.load_targets_btn = QPushButton("📁 Load from File")
        self.load_targets_btn.clicked.connect(self.load_targets_from_file)
        self.clear_targets_btn = QPushButton("🗑️ Clear List")
        self.clear_targets_btn.clicked.connect(self.clear_targets)
        
        list_layout = QVBoxLayout()
        list_layout.addWidget(self.target_list)
        list_btn_layout = QHBoxLayout()
        list_btn_layout.addWidget(self.load_targets_btn)
        list_btn_layout.addWidget(self.clear_targets_btn)
        list_layout.addLayout(list_btn_layout)
        settings_layout.addRow("📋 Target List:", list_layout)
        
        # Proxy
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        settings_layout.addRow("🔗 Proxy:", self.proxy_input)
        
        # Stealth mode
        self.stealth_checkbox = QCheckBox("Enable Stealth Mode (slower, less detectable)")
        settings_layout.addRow("", self.stealth_checkbox)
        
        # Delay
        self.delay_spinbox = QDoubleSpinBox()
        self.delay_spinbox.setRange(0.1, 10.0)
        self.delay_spinbox.setSingleStep(0.5)
        self.delay_spinbox.setValue(1.0)
        settings_layout.addRow("⏱️ Delay (seconds):", self.delay_spinbox)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Controls
        controls_layout = QHBoxLayout()
        self.start_button = QPushButton("🚀 Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("⏹️ Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        layout.addLayout(controls_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        
        # Output
        output_group = QGroupBox("📋 Scan Output")
        output_layout = QVBoxLayout()
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumHeight(200)
        output_layout.addWidget(self.output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Report
        report_group = QGroupBox("🔍 Vulnerability Report")
        report_layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.tabs.addTab(self.report_text, "📄 Report")
        report_layout.addWidget(self.tabs)
        report_group.setLayout(report_layout)
        layout.addWidget(report_group)
        
        self.targets = []
        
    def add_target(self):
        target = self.target_input.text().strip()
        if target:
            from core.utils import sanitize_url
            sanitized_target = sanitize_url(target)
            self.targets.append(sanitized_target)
            self.target_list.addItem(sanitized_target)
            self.target_input.clear()
            self.output.append(f"[+] Target added: {sanitized_target}")
            
    def load_targets_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Targets File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        target = line.strip()
                        if target:
                            from core.utils import sanitize_url
                            sanitized_target = sanitize_url(target)
                            self.targets.append(sanitized_target)
                            self.target_list.addItem(sanitized_target)
                self.output.append(f"[+] Loaded {len(self.targets)} targets from file.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {e}")
                
    def clear_targets(self):
        self.targets.clear()
        self.target_list.clear()
        self.output.append("[-] Target list cleared")
        
    def start_scan(self):
        if not self.targets:
            QMessageBox.warning(self, "Warning", "Please add at least one target URL!")
            return
            
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.output.clear()
        self.report_text.clear()
        self.progress.setValue(0)
        
        # Configure scan
        config = type('Config', (object,), dict(vars(Config))) # Copy default config
        if self.proxy_input.text().strip():
            config.USE_PROXY = True
            config.PROXY_URL = self.proxy_input.text().strip()
        if self.stealth_checkbox.isChecked():
            config.STEALTH_MODE = True
        config.DEFAULT_DELAY = self.delay_spinbox.value()
        
        self.output.append("[*] 🚀 Starting scan...")
        self.scan_thread = ScanThread(self.targets, config)
        self.scan_thread.output_signal.connect(self.update_output)
        self.scan_thread.finished_signal.connect(self.scan_finished)
        self.scan_thread.progress_signal.connect(self.update_progress)
        self.scan_thread.start()
        
    def stop_scan(self):
        if hasattr(self, 'scan_thread'):
            self.scan_thread.terminate()
            self.scan_finished()
            
    def update_output(self, text):
        self.output.append(text)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())
        
    def update_progress(self, value):
        self.progress.setValue(value)
        
    def scan_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.output.append("[+] ✅ Scan completed!")
        # In a full implementation, the report would be loaded here
        self.report_text.setPlainText("Scan completed. Please check the 'reports' directory for generated files.")

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
