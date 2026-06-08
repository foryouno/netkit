#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
<<<<<<< HEAD
端口扫描工具 - GUI版本（支持批量扫描 + 子网掩码计算）
用途：图形化界面的端口扫描工具，支持批量IP扫描和子网掩码计算
=======
端口扫描工具 - GUI版本（支持批量扫描）
用途：图形化界面的端口扫描工具，支持批量IP扫描
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
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


<<<<<<< HEAD
class SubnetCalculator:
    """子网掩码计算器类"""
    
    @staticmethod
    def ip_to_int(ip):
        """将IP地址转换为整数"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    @staticmethod
    def int_to_ip(num):
        """将整数转换为IP地址"""
        return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"
    
    @staticmethod
    def cidr_to_netmask(prefix_len):
        """CIDR前缀长度转换为子网掩码"""
        if not 0 <= prefix_len <= 32:
            raise ValueError("前缀长度必须在0-32之间")
        return (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    
    @staticmethod
    def netmask_to_cidr(netmask):
        """子网掩码转换为CIDR前缀长度"""
        if isinstance(netmask, str):
            netmask = SubnetCalculator.ip_to_int(netmask)
        # 计算二进制中1的个数
        count = 0
        temp = netmask
        while temp:
            count += 1
            temp &= temp - 1
        return count
    
    @staticmethod
    def calculate_subnet(ip, prefix_len):
        """计算子网信息"""
        ip_int = SubnetCalculator.ip_to_int(ip)
        netmask_int = SubnetCalculator.cidr_to_netmask(prefix_len)
        
        # 网络地址
        network_int = ip_int & netmask_int
        
        # 广播地址
        wildcard_int = 0xFFFFFFFF - netmask_int
        broadcast_int = network_int | wildcard_int
        
        # 主机数
        host_count = 2 ** (32 - prefix_len)
        
        # 可用IP数
        if prefix_len >= 31:
            usable_hosts = host_count
        else:
            usable_hosts = host_count - 2
        
        # 第一个可用IP（排除网络地址）
        if prefix_len >= 31:
            first_ip = network_int
        else:
            first_ip = network_int + 1
        
        # 最后一个可用IP（排除广播地址）
        if prefix_len >= 31:
            last_ip = broadcast_int
        else:
            last_ip = broadcast_int - 1
        
        return {
            'ip': ip,
            'prefix_len': prefix_len,
            'netmask': SubnetCalculator.int_to_ip(netmask_int),
            'network': SubnetCalculator.int_to_ip(network_int),
            'broadcast': SubnetCalculator.int_to_ip(broadcast_int),
            'first_host': SubnetCalculator.int_to_ip(first_ip) if usable_hosts > 0 else '-',
            'last_host': SubnetCalculator.int_to_ip(last_ip) if usable_hosts > 0 else '-',
            'host_count': host_count,
            'usable_hosts': usable_hosts,
            'wildcard': SubnetCalculator.int_to_ip(wildcard_int),
            'ip_class': SubnetCalculator.get_ip_class(ip),
            'ip_type': SubnetCalculator.get_ip_type(ip)
        }
    
    @staticmethod
    def get_ip_class(ip):
        """获取IP地址分类"""
        first_octet = int(ip.split('.')[0])
        if first_octet < 128:
            return 'A'
        elif first_octet < 192:
            return 'B'
        elif first_octet < 224:
            return 'C'
        elif first_octet < 240:
            return 'D (多播)'
        else:
            return 'E (保留)'
    
    @staticmethod
    def get_ip_type(ip):
        """获取IP地址类型"""
        first_octet = int(ip.split('.')[0])
        first = int(ip.split('.')[0])
        second = int(ip.split('.')[1])
        
        # 私有地址
        if first == 10:
            return '私有 (10.0.0.0/8)'
        elif first == 172 and 16 <= second <= 31:
            return '私有 (172.16.0.0/12)'
        elif first == 192 and second == 168:
            return '私有 (192.168.0.0/16)'
        # 特殊地址
        elif ip == '127.0.0.1':
            return '本地回环'
        elif ip == '255.255.255.255':
            return '广播'
        elif ip.startswith('0.'):
            return '本网络'
        # C类私有
        elif first == 192 and second == 168:
            return '私有'
        # 公网
        else:
            return '公网'
    
    @staticmethod
    def expand_cidr(cidr):
        """展开CIDR范围内的所有IP"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network]
        except ValueError as e:
            raise ValueError(f"无效的CIDR格式: {e}")
    
    @staticmethod
    def subnet_of_subnet(cidr, new_prefix):
        """将一个子网划分为更小的子网"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            current_prefix = network.prefixlen
            
            if new_prefix <= current_prefix:
                raise ValueError(f"新前缀长度({new_prefix})必须大于原前缀长度({current_prefix})")
            
            subnets = list(network.subnets(new_prefix=new_prefix))
            return [str(subnet) for subnet in subnets]
        except ValueError as e:
            raise ValueError(f"无效的CIDR格式或前缀长度: {e}")


=======
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
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


<<<<<<< HEAD
class SubnetCalculatorGUI:
    """子网掩码计算器GUI"""
    
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建组件
        self.create_widgets()
    
    def create_widgets(self):
        """创建子网掩码计算器界面组件"""
        # 输入框架
        input_frame = ttk.LabelFrame(self.frame, text="子网信息输入", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # IP地址输入
        ip_row = ttk.Frame(input_frame)
        ip_row.pack(fill=tk.X, pady=5)
        ttk.Label(ip_row, text="IP地址:", width=15).pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_row, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "192.168.1.100")
        
        # 前缀长度输入
        prefix_row = ttk.Frame(input_frame)
        prefix_row.pack(fill=tk.X, pady=5)
        ttk.Label(prefix_row, text="CIDR前缀 (/):", width=15).pack(side=tk.LEFT)
        self.prefix_var = tk.StringVar(value="24")
        self.prefix_spinbox = ttk.Spinbox(prefix_row, from_=0, to=32, width=18, 
                                          textvariable=self.prefix_var)
        self.prefix_spinbox.pack(side=tk.LEFT, padx=5)
        
        # 常用前缀快捷按钮
        quick_frame = ttk.Frame(input_frame)
        quick_frame.pack(fill=tk.X, pady=5)
        ttk.Label(quick_frame, text="常用前缀:").pack(side=tk.LEFT)
        for prefix, label in [(8, '/8'), (16, '/16'), (24, '/24'), (25, '/25'), 
                              (26, '/26'), (27, '/27'), (28, '/28'), (29, '/29'), (30, '/30')]:
            ttk.Button(quick_frame, text=label, width=5,
                      command=lambda p=prefix: self.set_prefix(p)).pack(side=tk.LEFT, padx=2)
        
        # 计算按钮
        calc_row = ttk.Frame(input_frame)
        calc_row.pack(fill=tk.X, pady=10)
        ttk.Button(calc_row, text="🔢 计算子网", command=self.calculate).pack(side=tk.LEFT, padx=5)
        ttk.Button(calc_row, text="🧹 清空", command=self.clear).pack(side=tk.LEFT, padx=5)
        
        # 结果显示框架
        result_frame = ttk.LabelFrame(self.frame, text="计算结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建两个列的结果显示
        result_container = ttk.Frame(result_frame)
        result_container.pack(fill=tk.BOTH, expand=True)
        
        # 左列
        left_frame = ttk.Frame(result_container)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # 右列
        right_frame = ttk.Frame(result_container)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 左列结果
        self.result_labels = {}
        
        left_items = [
            ('netmask', '子网掩码'),
            ('network', '网络地址'),
            ('broadcast', '广播地址'),
            ('wildcard', '通配符掩码'),
        ]
        
        right_items = [
            ('ip_class', 'IP分类'),
            ('ip_type', 'IP类型'),
            ('host_count', '总主机数'),
            ('usable_hosts', '可用主机数'),
        ]
        
        for key, label_text in left_items:
            row = ttk.Frame(left_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=f"{label_text}:", width=15, anchor=tk.W).pack(side=tk.LEFT)
            value_label = ttk.Label(row, text="-", anchor=tk.W, font=('Consolas', 10))
            value_label.pack(side=tk.LEFT, padx=5)
            self.result_labels[key] = value_label
        
        for key, label_text in right_items:
            row = ttk.Frame(right_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=f"{label_text}:", width=15, anchor=tk.W).pack(side=tk.LEFT)
            value_label = ttk.Label(row, text="-", anchor=tk.W, font=('Consolas', 10))
            value_label.pack(side=tk.LEFT, padx=5)
            self.result_labels[key] = value_label
        
        # 可用IP范围
        range_frame = ttk.LabelFrame(result_frame, text="可用IP范围", padding="5")
        range_frame.pack(fill=tk.X, pady=5)
        
        self.first_host_label = ttk.Label(range_frame, text="首个可用IP: -", font=('Consolas', 10))
        self.first_host_label.pack(anchor=tk.W, pady=2)
        
        self.last_host_label = ttk.Label(range_frame, text="最后可用IP: -", font=('Consolas', 10))
        self.last_host_label.pack(anchor=tk.W, pady=2)
        
        # 二进制显示
        binary_frame = ttk.LabelFrame(result_frame, text="二进制表示", padding="5")
        binary_frame.pack(fill=tk.X, pady=5)
        
        self.binary_label = ttk.Label(binary_frame, text="-", font=('Consolas', 9), 
                                       wraplength=500, justify=tk.LEFT)
        self.binary_label.pack(anchor=tk.W)
        
        # CIDR展开功能
        expand_frame = ttk.LabelFrame(self.frame, text="CIDR展开 (慎用,大范围会卡)", padding="10")
        expand_frame.pack(fill=tk.X, pady=5)
        
        expand_row = ttk.Frame(expand_frame)
        expand_row.pack(fill=tk.X)
        ttk.Label(expand_row, text="CIDR:").pack(side=tk.LEFT)
        self.cidr_entry = ttk.Entry(expand_row, width=25)
        self.cidr_entry.pack(side=tk.LEFT, padx=5)
        self.cidr_entry.insert(0, "192.168.1.0/30")
        ttk.Button(expand_row, text="展开IP列表", command=self.expand_cidr).pack(side=tk.LEFT, padx=5)
        
        # 展开结果显示
        self.expand_result = scrolledtext.ScrolledText(expand_frame, height=6, 
                                                        font=('Consolas', 9), wrap=tk.WORD)
        self.expand_result.pack(fill=tk.X, pady=5)
    
    def set_prefix(self, prefix):
        """设置前缀长度"""
        self.prefix_var.set(str(prefix))
    
    def calculate(self):
        """执行子网计算"""
        try:
            ip = self.ip_entry.get().strip()
            prefix_len = int(self.prefix_var.get())
            
            # 验证IP格式
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                messagebox.showerror("输入错误", "无效的IP地址格式！")
                return
            
            if not 0 <= prefix_len <= 32:
                messagebox.showerror("输入错误", "前缀长度必须在0-32之间！")
                return
            
            # 计算子网信息
            result = SubnetCalculator.calculate_subnet(ip, prefix_len)
            
            # 更新结果显示
            self.result_labels['netmask'].config(text=result['netmask'])
            self.result_labels['network'].config(text=f"{result['network']}/{result['prefix_len']}")
            self.result_labels['broadcast'].config(text=result['broadcast'])
            self.result_labels['wildcard'].config(text=result['wildcard'])
            self.result_labels['ip_class'].config(text=result['ip_class'])
            self.result_labels['ip_type'].config(text=result['ip_type'])
            self.result_labels['host_count'].config(text=f"{result['host_count']:,}")
            self.result_labels['usable_hosts'].config(text=f"{result['usable_hosts']:,}")
            
            # 更新可用IP范围
            self.first_host_label.config(text=f"首个可用IP: {result['first_host']}")
            self.last_host_label.config(text=f"最后可用IP: {result['last_host']}")
            
            # 更新二进制显示
            ip_binary = '.'.join([bin(int(octet)).split('b')[1].zfill(8) for octet in ip.split('.')])
            netmask_binary = '.'.join([bin(int(octet)).split('b')[1].zfill(8) 
                                       for octet in result['netmask'].split('.')])
            self.binary_label.config(text=f"IP: {ip_binary}\n子网掩码: {netmask_binary}")
            
        except Exception as e:
            messagebox.showerror("计算错误", f"计算时发生错误:\n{str(e)}")
    
    def clear(self):
        """清空结果"""
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, "192.168.1.100")
        self.prefix_var.set("24")
        
        for key in self.result_labels:
            self.result_labels[key].config(text="-")
        
        self.first_host_label.config(text="首个可用IP: -")
        self.last_host_label.config(text="最后可用IP: -")
        self.binary_label.config(text="-")
        self.expand_result.delete(1.0, tk.END)
    
    def expand_cidr(self):
        """展开CIDR范围内的所有IP"""
        try:
            cidr = self.cidr_entry.get().strip()
            network = ipaddress.ip_network(cidr, strict=False)
            ip_list = list(network)
            
            self.expand_result.delete(1.0, tk.END)
            self.expand_result.insert(tk.END, f"共 {len(ip_list)} 个IP地址:\n\n")
            
            if len(ip_list) <= 256:
                for ip in ip_list:
                    self.expand_result.insert(tk.END, f"{ip}\n")
            else:
                # 如果IP太多，只显示前100个和后100个
                for ip in ip_list[:100]:
                    self.expand_result.insert(tk.END, f"{ip}\n")
                self.expand_result.insert(tk.END, f"\n... (省略 {len(ip_list) - 200} 个IP) ...\n\n")
                for ip in ip_list[-100:]:
                    self.expand_result.insert(tk.END, f"{ip}\n")
                
        except ValueError as e:
            messagebox.showerror("输入错误", f"无效的CIDR格式:\n{str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"展开时发生错误:\n{str(e)}")


class PortScannerGUI:
    def __init__(self, root, embedded=False):
        self.root = root
        self.embedded = embedded
        self.parent = root  # 保存父容器引用
        
        if not embedded:
            self.root.title("NetKit - 网络工具箱")
            self.root.geometry("900x700")
            self.root.minsize(800, 600)
=======
class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("端口扫描工具 - 批量扫描版")
        self.root.geometry("800x650")
        self.root.minsize(700, 500)
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
        
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
<<<<<<< HEAD
        
        if not embedded:
            self.center_window()
=======
        self.center_window()
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
    
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
        
<<<<<<< HEAD
        # 绑定关闭事件（仅在非嵌入模式下）
        if not self.embedded:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
=======
        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
    
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
        
<<<<<<< HEAD
        # 清空并显示简洁结果
        self.result_text.delete(1.0, tk.END)
        
        if total_open > 0:
            self.result_text.insert(tk.END, f"✅ 发现 {total_open} 个开放端口\n\n", 'bold')
            self.result_text.tag_config('bold', font=('Consolas', 11, 'bold'))
            
            for ip, ports in sorted(results.items()):
                if ports:
                    # 格式化端口列表为简洁格式
                    port_list = [f"{port}" for port, _ in sorted(ports)]
                    service_list = [f"{port}/{service}" for port, service in sorted(ports)]
                    self.result_text.insert(tk.END, f"📍 {ip}\n", 'ip')
                    self.result_text.insert(tk.END, f"   端口: {', '.join(port_list)}\n", 'ports')
                    self.result_text.insert(tk.END, f"   服务: {', '.join(service_list)}\n\n", 'services')
                    self.result_text.tag_config('ip', font=('Consolas', 10, 'bold'))
                    self.result_text.tag_config('ports', foreground='green')
                    self.result_text.tag_config('services', foreground='blue')
        else:
            self.result_text.insert(tk.END, "✅ 扫描完成，未发现开放端口\n", 'bold')
        
        self.result_text.insert(tk.END, f"\n{'─' * 40}\n")
        self.result_text.insert(tk.END, f"⏱ 耗时: {duration:.2f} 秒 | 🌐 IP数: {len(results)} | 🔌 端口: {total_open}")
=======
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
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.current_ip_label.config(text="当前扫描: -")
<<<<<<< HEAD
=======
        
        messagebox.showinfo("扫描完成", 
                           f"扫描完成！\n扫描IP数: {len(results)}\n发现开放端口: {total_open}\n耗时: {duration:.2f} 秒")
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
    
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
<<<<<<< HEAD
        if not self.embedded:
            if self.scanning:
                if messagebox.askokcancel("确认", "扫描正在进行中，确定要退出吗？"):
                    self.scanning = False
                    self.root.destroy()
            else:
                self.root.destroy()


def main():
    """主函数 - 创建带选项卡的主界面"""
    root = tk.Tk()
    root.title("NetKit - 网络工具箱")
    root.geometry("900x700")
    root.minsize(800, 600)
    
    # 创建Notebook（选项卡控件）
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # 创建端口扫描界面
    scanner_frame = ttk.Frame(notebook)
    notebook.add(scanner_frame, text="🔍 端口扫描")
    
    # 创建子网掩码计算器界面
    subnet_frame = ttk.Frame(notebook)
    notebook.add(subnet_frame, text="🧮 子网掩码计算")
    
    # 初始化端口扫描界面
    scanner_app = PortScannerGUI(scanner_frame, embedded=True)
    
    # 初始化子网掩码计算器界面
    subnet_app = SubnetCalculatorGUI(subnet_frame)
    
    # 居中显示窗口
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
=======
        if self.scanning:
            if messagebox.askokcancel("确认", "扫描正在进行中，确定要退出吗？"):
                self.scanning = False
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
    root.mainloop()


if __name__ == "__main__":
<<<<<<< HEAD
    try:
        main()
    except Exception as e:
        import traceback
        error_msg = f"程序运行错误:\n{str(e)}\n\n详细错误:\n{traceback.format_exc()}"
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()  # 隐藏主窗口
            messagebox.showerror("错误", error_msg)
            root.destroy()
        except:
            print(error_msg)
        input("\n按回车键退出...")
=======
    main()
>>>>>>> 39f10c98347995b7e19ae3bb86943b0b75dfcc66
