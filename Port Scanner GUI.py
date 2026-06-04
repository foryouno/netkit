#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描工具 - GUI版本（支持批量扫描）
用途：图形化界面的端口扫描工具，支持批量IP扫描
"""

import socket
import threading
import time
import ipaddress
import re
import os
import platform
import subprocess
from queue import Queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog


class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, 
                 progress_callback=None, result_callback=None, custom_ports=None,
                 speed_mode='fast'):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.custom_ports = custom_ports  # 自定义端口列表
        self.threads = threads
        self.queue = Queue()
        self.open_ports = []
        self.lock = threading.Lock()
        self.running = False
        self.total_ports = 0
        self.scanned_ports = 0
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        
        # 速度模式配置
        self.speed_mode = speed_mode
        if speed_mode == 'fast':
            self.socket_timeout = 0.3  # 快速模式：0.3秒超时
            self.queue_timeout = 0.1   # 快速模式：0.1秒队列超时
        elif speed_mode == 'normal':
            self.socket_timeout = 1.0  # 普通模式：1秒超时
            self.queue_timeout = 0.5   # 普通模式：0.5秒队列超时
        else:  # slow
            self.socket_timeout = 2.0  # 慢速模式：2秒超时
            self.queue_timeout = 1.0   # 慢速模式：1秒队列超时
        
        # 常见服务端口对照表
        self.common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy',
            1433: 'MSSQL', 1521: 'Oracle', 27017: 'MongoDB',
            9200: 'Elasticsearch', 11211: 'Memcached'
        }
    
    def scan_port(self, port):
        """扫描单个端口"""
        if not self.running:
            return
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.socket_timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                with self.lock:
                    service = self.common_services.get(port, 'Unknown')
                    self.open_ports.append((port, service))
                    if self.result_callback:
                        self.result_callback(self.target, port, service)
            sock.close()
        except Exception:
            pass
        finally:
            with self.lock:
                self.scanned_ports += 1
                if self.progress_callback and self.total_ports > 0:
                    progress = (self.scanned_ports / self.total_ports) * 100
                    self.progress_callback(progress, self.scanned_ports, self.total_ports)
    
    def ping_host(self):
        """Ping检测主机是否在线"""
        try:
            param = '-n' if platform.system() == 'Windows' else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-w' if platform.system() == 'Windows' else '-W', '1000', self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def worker(self):
        """工作线程"""
        while self.running and not self.queue.empty():
            try:
                port = self.queue.get(timeout=self.queue_timeout)
                self.scan_port(port)
                self.queue.task_done()
            except Exception:
                break
    
    def stop(self):
        """停止扫描"""
        self.running = False
    
    def run(self):
        """运行扫描"""
        self.running = True
        
        # 确定要扫描的端口列表
        if self.custom_ports:
            ports_to_scan = self.custom_ports
        else:
            ports_to_scan = list(range(self.start_port, self.end_port + 1))
        
        self.total_ports = len(ports_to_scan)
        self.scanned_ports = 0
        
        # 填充队列
        for port in ports_to_scan:
            self.queue.put(port)
        
        # 创建线程
        thread_list = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread_list.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in thread_list:
            thread.join()
        
        return self.open_ports


def parse_ip_input(ip_input):
    """解析IP输入，支持多种格式"""
    ip_list = []
    
    # 检查是否是文件
    if os.path.isfile(ip_input):
        try:
            with open(ip_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ip_list.extend(parse_ip_input(line))
            return ip_list
        except Exception:
            pass
    
    # 检查CIDR格式
    try:
        network = ipaddress.ip_network(ip_input, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass
    
    # 检查IP范围格式
    range_match = re.match(r'(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)', ip_input)
    if range_match:
        start_ip = ipaddress.ip_address(range_match.group(1))
        end_ip = ipaddress.ip_address(range_match.group(2))
        current_ip = start_ip
        while current_ip <= end_ip:
            ip_list.append(str(current_ip))
            current_ip += 1
        return ip_list
    
    # 多个IP用逗号分隔
    if ',' in ip_input:
        for ip in ip_input.split(','):
            ip = ip.strip()
            if ip:
                ip_list.extend(parse_ip_input(ip))
        return ip_list
    
    # 单个IP
    try:
        ipaddress.ip_address(ip_input)
        return [ip_input]
    except ValueError:
        pass
    
    return ip_list


class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("端口扫描工具 - 批量扫描版")
        self.root.geometry("800x650")
        self.root.minsize(700, 500)
        
        # 设置样式
        self.style = ttk.Style()
        self.style.configure('TButton', font=('微软雅黑', 10))
        self.style.configure('TLabel', font=('微软雅黑', 10))
        self.style.configure('TEntry', font=('微软雅黑', 10))
        self.style.configure('Header.TLabel', font=('微软雅黑', 12, 'bold'))
        
        self.scanner = None
        self.batch_thread = None
        self.scanning = False
        self.results = {}
        self.ping_results = {}  # 存储ping结果
        
        self.create_widgets()
        self.center_window()
    
    def center_window(self):
        """窗口居中"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置grid权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(7, weight=1)
        
        # 标题
        title_label = ttk.Label(
            main_frame, 
            text="🔍 端口扫描工具 (批量扫描版)", 
            style='Header.TLabel'
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        # 目标输入框架
        target_frame = ttk.LabelFrame(main_frame, text="目标设置", padding="10")
        target_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        target_frame.columnconfigure(1, weight=1)
        
        # IP输入
        ttk.Label(target_frame, text="目标IP:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.target_entry.insert(0, "127.0.0.1")
        
        # 文件选择按钮
        ttk.Button(target_frame, text="📁 选择文件", command=self.load_ip_file).grid(row=0, column=2, padx=5)
        
        # IP格式说明
        ip_hint = "支持格式: 单个IP | CIDR(192.168.1.0/24) | 范围(1.1.1.1-1.1.1.100) | 逗号分隔多个IP | 从文件导入"
        hint_label = ttk.Label(target_frame, text=ip_hint, foreground="gray", font=('微软雅黑', 8))
        hint_label.grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=(5, 0))
        
        # 端口范围框架
        port_frame = ttk.LabelFrame(main_frame, text="端口设置", padding="10")
        port_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # 端口设置模式选择
        self.port_mode_var = tk.StringVar(value="range")
        ttk.Radiobutton(port_frame, text="端口范围", variable=self.port_mode_var, 
                        value="range", command=self.update_port_ui).grid(row=0, column=0, padx=5)
        ttk.Radiobutton(port_frame, text="自定义端口", variable=self.port_mode_var, 
                        value="custom", command=self.update_port_ui).grid(row=0, column=1, padx=5)
        
        # 端口范围输入框
        self.range_frame = ttk.Frame(port_frame)
        self.range_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(self.range_frame, text="起始端口:").pack(side=tk.LEFT, padx=5)
        self.start_port_entry = ttk.Entry(self.range_frame, width=10)
        self.start_port_entry.pack(side=tk.LEFT, padx=5)
        self.start_port_entry.insert(0, "1")
        
        ttk.Label(self.range_frame, text="结束端口:").pack(side=tk.LEFT, padx=5)
        self.end_port_entry = ttk.Entry(self.range_frame, width=10)
        self.end_port_entry.pack(side=tk.LEFT, padx=5)
        self.end_port_entry.insert(0, "1024")
        
        # 快速选择按钮
        quick_btn_frame = ttk.Frame(self.range_frame)
        quick_btn_frame.pack(side=tk.LEFT, padx=10)
        
        ttk.Button(quick_btn_frame, text="常用端口", 
                   command=lambda: self.set_port_range(1, 1024), width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_btn_frame, text="Web端口", 
                   command=lambda: self.set_port_range(80, 8080), width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_btn_frame, text="全部端口", 
                   command=lambda: self.set_port_range(1, 65535), width=10).pack(side=tk.LEFT, padx=2)
        
        # 自定义端口输入框
        self.custom_frame = ttk.Frame(port_frame)
        self.custom_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(self.custom_frame, text="端口列表 (用逗号分隔):").pack(side=tk.LEFT, padx=5)
        self.custom_ports_entry = ttk.Entry(self.custom_frame, width=50)
        self.custom_ports_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.custom_ports_entry.insert(0, "22,80,443,3306,5432,6379,8080")
        
        # 默认隐藏自定义框
        self.custom_frame.grid_remove()
        
        # 设置框架
        settings_frame = ttk.LabelFrame(main_frame, text="扫描设置", padding="10")
        settings_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(settings_frame, text="速度模式:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.speed_mode_var = tk.StringVar(value="fast")
        speed_frame = ttk.Frame(settings_frame)
        speed_frame.grid(row=0, column=1, padx=5, sticky=tk.W, columnspan=2)
        ttk.Radiobutton(speed_frame, text="⚡ 快速", variable=self.speed_mode_var, value="fast").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(speed_frame, text="🔄 普通", variable=self.speed_mode_var, value="normal").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(speed_frame, text="🐢 慢速", variable=self.speed_mode_var, value="slow").pack(side=tk.LEFT, padx=2)
        
        ttk.Label(settings_frame, text="线程数:").grid(row=0, column=3, padx=5)
        self.threads_entry = ttk.Entry(settings_frame, width=10)
        self.threads_entry.grid(row=0, column=4, padx=5)
        self.threads_entry.insert(0, "100")
        
        # Ping扫描选项
        self.ping_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="✓ 先进行Ping扫描", 
                        variable=self.ping_var).grid(row=0, column=5, padx=10)
        
        # 按钮框架
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="▶ 开始扫描", 
                                    command=self.start_scan, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹ 停止扫描", 
                                   command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="🧹 清空结果", 
                   command=self.clear_results, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="💾 导出结果", 
                   command=self.export_results, width=15).pack(side=tk.LEFT, padx=5)
        
        # 进度框架
        progress_frame = ttk.LabelFrame(main_frame, text="扫描进度", padding="5")
        progress_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        progress_frame.columnconfigure(0, weight=1)
        
        # IP进度
        self.ip_progress_var = tk.DoubleVar()
        self.ip_progress_bar = ttk.Progressbar(progress_frame, variable=self.ip_progress_var, 
                                               maximum=100, length=400, mode='determinate')
        self.ip_progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=2, padx=5)
        self.ip_status_label = ttk.Label(progress_frame, text="IP: 0/0")
        self.ip_status_label.grid(row=0, column=1, padx=5)
        
        # 端口进度
        self.port_progress_var = tk.DoubleVar()
        self.port_progress_bar = ttk.Progressbar(progress_frame, variable=self.port_progress_var, 
                                                 maximum=100, length=400, mode='determinate')
        self.port_progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=2, padx=5)
        self.port_status_label = ttk.Label(progress_frame, text="端口: 0/0")
        self.port_status_label.grid(row=1, column=1, padx=5)
        
        # 当前IP标签
        self.current_ip_label = ttk.Label(main_frame, text="当前扫描: -")
        self.current_ip_label.grid(row=6, column=0, columnspan=3, sticky=tk.W, pady=2, padx=5)
        
        # 结果显示区域
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="5")
        result_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        self.result_text = scrolledtext.ScrolledText(
            result_frame, wrap=tk.WORD, width=90, height=20, font=('Consolas', 10)
        )
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def load_ip_file(self):
        """加载IP文件"""
        filename = filedialog.askopenfilename(
            title="选择IP列表文件",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, filename)
    
    def set_port_range(self, start, end):
        """设置端口范围"""
        self.start_port_entry.delete(0, tk.END)
        self.start_port_entry.insert(0, str(start))
        self.end_port_entry.delete(0, tk.END)
        self.end_port_entry.insert(0, str(end))
    
    def update_port_ui(self):
        """更新端口UI显示"""
        if self.port_mode_var.get() == "range":
            self.range_frame.grid()
            self.custom_frame.grid_remove()
        else:
            self.range_frame.grid_remove()
            self.custom_frame.grid()
    
    def log(self, message, tag=None):
        """添加日志"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.result_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        if tag:
            self.result_text.tag_config(tag, foreground=tag)
        self.result_text.see(tk.END)
    
    def update_ip_progress(self, current, total, current_ip):
        """更新IP进度"""
        self.root.after(0, lambda: self._update_ip_progress_ui(current, total, current_ip))
    
    def _update_ip_progress_ui(self, current, total, current_ip):
        progress = (current / total) * 100 if total > 0 else 0
        self.ip_progress_var.set(progress)
        self.ip_status_label.config(text=f"IP: {current}/{total}")
        self.current_ip_label.config(text=f"当前扫描: {current_ip}")
    
    def update_port_progress(self, progress, scanned, total):
        """更新端口进度"""
        self.root.after(0, lambda: self._update_port_progress_ui(progress, scanned, total))
    
    def _update_port_progress_ui(self, progress, scanned, total):
        self.port_progress_var.set(progress)
        self.port_status_label.config(text=f"端口: {scanned}/{total}")
    
    def add_result(self, ip, port, service):
        """添加扫描结果"""
        self.root.after(0, lambda: self._add_result_ui(ip, port, service))
    
    def _add_result_ui(self, ip, port, service):
        self.result_text.insert(tk.END, f"[+] {ip}:{port} 开放 - {service}\n", 'green')
        self.result_text.tag_config('green', foreground='green')
        self.result_text.see(tk.END)
    
    def scan_complete(self, results, duration):
        """扫描完成回调"""
        self.root.after(0, lambda: self._scan_complete_ui(results, duration))
    
    def _scan_complete_ui(self, results, duration):
        self.scanning = False
        self.ip_progress_var.set(100)
        self.port_progress_var.set(100)
        
        total_open = sum(len(ports) for ports in results.values())
        
        self.log("=" * 60)
        self.log(f"扫描完成！总耗时: {duration:.2f} 秒")
        self.log(f"扫描IP数: {len(results)}")
        self.log(f"发现开放端口总数: {total_open}")
        
        if total_open > 0:
            self.log("\n[+] 详细结果汇总:")
            for ip, ports in results.items():
                if ports:
                    self.log(f"\n  {ip}:")
                    for port, service in sorted(ports):
                        self.log(f"    {port}/tcp - {service}")
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.current_ip_label.config(text="当前扫描: -")
        
        messagebox.showinfo("扫描完成", 
                           f"扫描完成！\n扫描IP数: {len(results)}\n发现开放端口: {total_open}\n耗时: {duration:.2f} 秒")
    
    def start_scan(self):
        """开始批量扫描"""
        ip_input = self.target_entry.get().strip()
        
        try:
            threads = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror("输入错误", "线程数必须是有效的数字！")
            return
        
        # 获取端口配置
        if self.port_mode_var.get() == "range":
            try:
                start_port = int(self.start_port_entry.get())
                end_port = int(self.end_port_entry.get())
                custom_ports = None
            except ValueError:
                messagebox.showerror("输入错误", "端口范围必须是有效的数字！")
                return
        else:
            start_port = 1
            end_port = 1024
            custom_ports_str = self.custom_ports_entry.get().strip()
            if not custom_ports_str:
                messagebox.showerror("输入错误", "自定义端口不能为空！")
                return
            try:
                custom_ports = [int(p.strip()) for p in custom_ports_str.split(',') if p.strip()]
                if not custom_ports:
                    raise ValueError()
            except ValueError:
                messagebox.showerror("输入错误", "端口格式错误！请用逗号分隔数字，如: 22,80,443")
                return
        
        if not ip_input:
            messagebox.showerror("输入错误", "请输入目标IP或选择文件！")
            return
        
        # 解析IP列表
        ip_list = parse_ip_input(ip_input)
        
        if not ip_list:
            messagebox.showerror("输入错误", "没有解析到有效的IP地址！")
            return
        
        if len(ip_list) > 10000:
            if not messagebox.askyesno("确认", f"将要扫描 {len(ip_list)} 个IP，数量较大，是否继续？"):
                return
        
        # 清空之前的结果
        self.result_text.delete(1.0, tk.END)
        self.results = {}
        self.ping_results = {}
        self.scanning = True
        
        # 获取ping选项
        enable_ping = self.ping_var.get()
        
        # 获取速度模式
        speed_mode = self.speed_mode_var.get()
        
        # 记录开始信息
        self.log(f"批量扫描开始")
        self.log(f"目标数量: {len(ip_list)} 个IP")
        if self.port_mode_var.get() == "range":
            self.log(f"端口范围: {start_port} - {end_port}")
        else:
            self.log(f"自定义端口: {', '.join(map(str, custom_ports))}")
        self.log(f"速度模式: {speed_mode}")
        self.log(f"线程数: {threads}")
        self.log(f"Ping扫描: {'启用' if enable_ping else '禁用'}")
        self.log(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("-" * 60)
        
        # 更新按钮状态
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # 在新线程中运行批量扫描
        self.batch_thread = threading.Thread(
            target=self._batch_scan,
            args=(ip_list, start_port, end_port, threads, custom_ports, enable_ping, speed_mode)
        )
        self.batch_thread.daemon = True
        self.batch_thread.start()
    
    def _batch_scan(self, ip_list, start_port, end_port, threads, custom_ports=None, enable_ping=False, speed_mode='fast'):
        """批量扫描主函数"""
        start_time = time.time()
        total_ips = len(ip_list)
        
        # 第一阶段：Ping扫描
        if enable_ping:
            self.log("\n[*] 开始Ping扫描...\n")
            alive_ips = []
            for idx, ip in enumerate(ip_list):
                if not self.scanning:
                    break
                
                current_idx = idx + 1
                self.update_ip_progress(current_idx, total_ips, ip)
                self.current_ip_label.config(text=f"当前扫描: {ip} (Ping检测中...)")
                
                scanner = PortScanner(ip, start_port, end_port, threads)
                if scanner.ping_host():
                    alive_ips.append(ip)
                    self.ping_results[ip] = True
                    self.log(f"  [{ip}] - ✓ 主机在线 (Ping成功)")
                else:
                    self.ping_results[ip] = False
                    self.log(f"  [{ip}] - ✗ 主机离线 (Ping失败)")
            
            if not alive_ips:
                self.log("\n[!] 没有主机响应Ping，扫描结束")
                self.scan_complete({}, time.time() - start_time)
                return
            
            ip_list = alive_ips
            total_ips = len(alive_ips)
            self.log(f"\n[*] 发现 {total_ips} 个在线主机，开始端口扫描\n")
        
        # 第二阶段：端口扫描
        for idx, ip in enumerate(ip_list):
            if not self.scanning:
                break
            
            current_idx = idx + 1
            self.update_ip_progress(current_idx, total_ips, ip)
            self.log(f"\n[{current_idx}/{total_ips}] 扫描: {ip}")
            
            scanner = PortScanner(
                ip, start_port, end_port, threads,
                progress_callback=self.update_port_progress,
                result_callback=self.add_result,
                custom_ports=custom_ports,
                speed_mode=speed_mode
            )
            
            open_ports = scanner.run()
            self.results[ip] = open_ports
            
            if open_ports:
                self.log(f"  发现 {len(open_ports)} 个开放端口")
            else:
                self.log(f"  无开放端口")
        
        duration = time.time() - start_time
        self.scan_complete(self.results, duration)
    
    def stop_scan(self):
        """停止扫描"""
        self.scanning = False
        self.log("扫描被用户停止", 'orange')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.current_ip_label.config(text="当前扫描: -")
    
    def clear_results(self):
        """清空结果"""
        self.result_text.delete(1.0, tk.END)
        self.results = {}
        self.ping_results = {}
        self.ip_progress_var.set(0)
        self.port_progress_var.set(0)
        self.ip_status_label.config(text="IP: 0/0")
        self.port_status_label.config(text="端口: 0/0")
    
    def export_results(self):
        """导出结果到文件"""
        if not self.results:
            messagebox.showwarning("警告", "没有可导出的扫描结果！")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"端口扫描报告\n")
                    f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"扫描IP数: {len(self.results)}\n")
                    
                    if self.ping_results:
                        alive_count = sum(1 for v in self.ping_results.values() if v)
                        f.write(f"在线主机数: {alive_count}\n")
                    
                    f.write("=" * 60 + "\n\n")
                    
                    # 导出Ping结果
                    if self.ping_results:
                        f.write("【Ping扫描结果】\n")
                        for ip, is_alive in sorted(self.ping_results.items()):
                            status = "✓ 在线" if is_alive else "✗ 离线"
                            f.write(f"  {ip}: {status}\n")
                        f.write("\n")
                    
                    # 导出端口扫描结果
                    f.write("【端口扫描结果】\n\n")
                    for ip, ports in sorted(self.results.items()):
                        f.write(f"[{ip}]\n")
                        if ports:
                            for port, service in sorted(ports):
                                f.write(f"  {port}/tcp - {service}\n")
                        else:
                            f.write("  无开放端口\n")
                        f.write("\n")
                
                self.log(f"结果已导出到: {filename}")
                messagebox.showinfo("导出成功", f"结果已保存到:\n{filename}")
            except Exception as e:
                messagebox.showerror("导出失败", f"导出时发生错误:\n{str(e)}")
    
    def on_closing(self):
        """关闭窗口"""
        if self.scanning:
            if messagebox.askokcancel("确认", "扫描正在进行中，确定要退出吗？"):
                self.scanning = False
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
