#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetKit - 网络工具箱
端口扫描工具 - GUI版本（支持批量扫描 + 子网掩码计算 + Nmap扫描 + IP归属地查询）
"""

import socket
import threading
import time
import ipaddress
import re
import os
import platform
import subprocess
import json
import urllib.request
import urllib.error
from queue import Queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog


class SubnetCalculator:
    """子网掩码计算器类"""
    
    @staticmethod
    def ip_to_int(ip):
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    @staticmethod
    def int_to_ip(num):
        return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"
    
    @staticmethod
    def cidr_to_netmask(prefix_len):
        if not 0 <= prefix_len <= 32:
            raise ValueError("前缀长度必须在0-32之间")
        return (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    
    @staticmethod
    def netmask_to_cidr(netmask):
        if isinstance(netmask, str):
            netmask = SubnetCalculator.ip_to_int(netmask)
        count = 0
        temp = netmask
        while temp:
            count += 1
            temp &= temp - 1
        return count
    
    @staticmethod
    def calculate_subnet(ip, prefix_len):
        ip_int = SubnetCalculator.ip_to_int(ip)
        netmask_int = SubnetCalculator.cidr_to_netmask(prefix_len)
        network_int = ip_int & netmask_int
        wildcard_int = 0xFFFFFFFF - netmask_int
        broadcast_int = network_int | wildcard_int
        host_count = 2 ** (32 - prefix_len)
        if prefix_len >= 31:
            usable_hosts = host_count
        else:
            usable_hosts = host_count - 2
        if prefix_len >= 31:
            first_ip = network_int
        else:
            first_ip = network_int + 1
        if prefix_len >= 31:
            last_ip = broadcast_int
        else:
            last_ip = broadcast_int - 1
        return {
            'ip': ip, 'prefix_len': prefix_len,
            'netmask': SubnetCalculator.int_to_ip(netmask_int),
            'network': SubnetCalculator.int_to_ip(network_int),
            'broadcast': SubnetCalculator.int_to_ip(broadcast_int),
            'first_host': SubnetCalculator.int_to_ip(first_ip) if usable_hosts > 0 else '-',
            'last_host': SubnetCalculator.int_to_ip(last_ip) if usable_hosts > 0 else '-',
            'host_count': host_count, 'usable_hosts': usable_hosts,
            'wildcard': SubnetCalculator.int_to_ip(wildcard_int),
            'ip_class': SubnetCalculator.get_ip_class(ip),
            'ip_type': SubnetCalculator.get_ip_type(ip)
        }
    
    @staticmethod
    def get_ip_class(ip):
        first_octet = int(ip.split('.')[0])
        if first_octet < 128: return 'A'
        elif first_octet < 192: return 'B'
        elif first_octet < 224: return 'C'
        elif first_octet < 240: return 'D (多播)'
        else: return 'E (保留)'
    
    @staticmethod
    def get_ip_type(ip):
        first = int(ip.split('.')[0])
        second = int(ip.split('.')[1])
        if first == 10: return '私有 (10.0.0.0/8)'
        elif first == 172 and 16 <= second <= 31: return '私有 (172.16.0.0/12)'
        elif first == 192 and second == 168: return '私有 (192.168.0.0/16)'
        elif ip == '127.0.0.1': return '本地回环'
        elif ip == '255.255.255.255': return '广播'
        elif ip.startswith('0.'): return '本网络'
        else: return '公网'
    
    @staticmethod
    def expand_cidr(cidr):
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network]
        except ValueError as e:
            raise ValueError(f"无效的CIDR格式: {e}")


class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, 
                 progress_callback=None, result_callback=None, custom_ports=None, speed_mode='fast'):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.custom_ports = custom_ports
        self.threads = threads
        self.queue = Queue()
        self.open_ports = []
        self.lock = threading.Lock()
        self.running = False
        self.total_ports = 0
        self.scanned_ports = 0
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        self.speed_mode = speed_mode
        if speed_mode == 'fast':
            self.socket_timeout = 0.3
            self.queue_timeout = 0.1
        elif speed_mode == 'normal':
            self.socket_timeout = 1.0
            self.queue_timeout = 0.5
        else:
            self.socket_timeout = 2.0
            self.queue_timeout = 1.0
        self.common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy',
            1433: 'MSSQL', 1521: 'Oracle', 27017: 'MongoDB', 9200: 'Elasticsearch'
        }
    
    def scan_port(self, port):
        if not self.running: return
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
        except: pass
        finally:
            with self.lock:
                self.scanned_ports += 1
                if self.progress_callback and self.total_ports > 0:
                    progress = (self.scanned_ports / self.total_ports) * 100
                    self.progress_callback(progress, self.scanned_ports, self.total_ports)
    
    def ping_host(self):
        try:
            param = '-n' if platform.system() == "Windows" else '-c'
            result = subprocess.run(['ping', param, '1', '-w', '1000', self.target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return result.returncode == 0
        except: return False
    
    def worker(self):
        while self.running and not self.queue.empty():
            try:
                port = self.queue.get(timeout=self.queue_timeout)
                self.scan_port(port)
                self.queue.task_done()
            except: break
    
    def stop(self): self.running = False
    
    def run(self):
        self.running = True
        ports_to_scan = self.custom_ports if self.custom_ports else list(range(self.start_port, self.end_port + 1))
        self.total_ports = len(ports_to_scan)
        self.scanned_ports = 0
        for port in ports_to_scan: self.queue.put(port)git commit -m "第一次上传：初始化项目"
        thread_list = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread_list.append(thread)
            thread.start()
        for thread in thread_list: thread.join()
        return self.open_ports


def parse_ip_input(ip_input):
    ip_list = []
    if os.path.isfile(ip_input):
        try:
            with open(ip_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ip_list.extend(parse_ip_input(line))
            return ip_list
        except: pass
    try:
        network = ipaddress.ip_network(ip_input, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError: pass
    range_match = re.match(r'(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)', ip_input)
    if range_match:
        start_ip = ipaddress.ip_address(range_match.group(1))
        end_ip = ipaddress.ip_address(range_match.group(2))
        current_ip = start_ip
        while current_ip <= end_ip:
            ip_list.append(str(current_ip))
            current_ip += 1
        return ip_list
    if ',' in ip_input:
        for ip in ip_input.split(','):
            ip = ip.strip()
            if ip: ip_list.extend(parse_ip_input(ip))
        return ip_list
    try:
        ipaddress.ip_address(ip_input)
        return [ip_input]
    except ValueError: pass
    return ip_list


class SubnetCalculatorGUI:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.create_widgets()
    
    def create_widgets(self):
        input_frame = ttk.LabelFrame(self.frame, text="子网信息输入", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        ip_row = ttk.Frame(input_frame)
        ip_row.pack(fill=tk.X, pady=5)
        ttk.Label(ip_row, text="IP地址:", width=15).pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_row, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "192.168.1.100")
        prefix_row = ttk.Frame(input_frame)
        prefix_row.pack(fill=tk.X, pady=5)
        ttk.Label(prefix_row, text="CIDR前缀 (/):", width=15).pack(side=tk.LEFT)
        self.prefix_var = tk.StringVar(value="24")
        self.prefix_spinbox = ttk.Spinbox(prefix_row, from_=0, to=32, width=18, textvariable=self.prefix_var)
        self.prefix_spinbox.pack(side=tk.LEFT, padx=5)
        quick_frame = ttk.Frame(input_frame)
        quick_frame.pack(fill=tk.X, pady=5)
        ttk.Label(quick_frame, text="常用前缀:").pack(side=tk.LEFT)
        for prefix, label in [(8, '/8'), (16, '/16'), (24, '/24'), (25, '/25'), (26, '/26'), (27, '/27'), (28, '/28'), (29, '/29'), (30, '/30')]:
            ttk.Button(quick_frame, text=label, width=5, command=lambda p=prefix: self.set_prefix(p)).pack(side=tk.LEFT, padx=2)
        calc_row = ttk.Frame(input_frame)
        calc_row.pack(fill=tk.X, pady=10)
        ttk.Button(calc_row, text="计算子网", command=self.calculate).pack(side=tk.LEFT, padx=5)
        ttk.Button(calc_row, text="清空", command=self.clear).pack(side=tk.LEFT, padx=5)
        result_frame = ttk.LabelFrame(self.frame, text="计算结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        result_container = ttk.Frame(result_frame)
        result_container.pack(fill=tk.BOTH, expand=True)
        left_frame = ttk.Frame(result_container)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        right_frame = ttk.Frame(result_container)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.result_labels = {}
        left_items = [('netmask', '子网掩码'), ('network', '网络地址'), ('broadcast', '广播地址'), ('wildcard', '通配符掩码')]
        right_items = [('ip_class', 'IP分类'), ('ip_type', 'IP类型'), ('host_count', '总主机数'), ('usable_hosts', '可用主机数')]
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
        range_frame = ttk.LabelFrame(result_frame, text="可用IP范围", padding="5")
        range_frame.pack(fill=tk.X, pady=5)
        self.first_host_label = ttk.Label(range_frame, text="首个可用IP: -", font=('Consolas', 10))
        self.first_host_label.pack(anchor=tk.W, pady=2)
        self.last_host_label = ttk.Label(range_frame, text="最后可用IP: -", font=('Consolas', 10))
        self.last_host_label.pack(anchor=tk.W, pady=2)
        binary_frame = ttk.LabelFrame(result_frame, text="二进制表示", padding="5")
        binary_frame.pack(fill=tk.X, pady=5)
        self.binary_label = ttk.Label(binary_frame, text="-", font=('Consolas', 9), wraplength=500, justify=tk.LEFT)
        self.binary_label.pack(anchor=tk.W)
        expand_frame = ttk.LabelFrame(self.frame, text="CIDR展开 (慎用,大范围会卡)", padding="10")
        expand_frame.pack(fill=tk.X, pady=5)
        expand_row = ttk.Frame(expand_frame)
        expand_row.pack(fill=tk.X)
        ttk.Label(expand_row, text="CIDR:").pack(side=tk.LEFT)
        self.cidr_entry = ttk.Entry(expand_row, width=25)
        self.cidr_entry.pack(side=tk.LEFT, padx=5)
        self.cidr_entry.insert(0, "192.168.1.0/30")
        ttk.Button(expand_row, text="展开IP列表", command=self.expand_cidr).pack(side=tk.LEFT, padx=5)
        self.expand_result = scrolledtext.ScrolledText(expand_frame, height=6, font=('Consolas', 9), wrap=tk.WORD)
        self.expand_result.pack(fill=tk.X, pady=5)
    
    def set_prefix(self, prefix): self.prefix_var.set(str(prefix))
    
    def calculate(self):
        try:
            ip = self.ip_entry.get().strip()
            prefix_len = int(self.prefix_var.get())
            try: ipaddress.ip_address(ip)
            except ValueError:
                messagebox.showerror("输入错误", "无效的IP地址格式！"); return
            if not 0 <= prefix_len <= 32:
                messagebox.showerror("输入错误", "前缀长度必须在0-32之间！"); return
            result = SubnetCalculator.calculate_subnet(ip, prefix_len)
            self.result_labels['netmask'].config(text=result['netmask'])
            self.result_labels['network'].config(text=f"{result['network']}/{result['prefix_len']}")
            self.result_labels['broadcast'].config(text=result['broadcast'])
            self.result_labels['wildcard'].config(text=result['wildcard'])
            self.result_labels['ip_class'].config(text=result['ip_class'])
            self.result_labels['ip_type'].config(text=result['ip_type'])
            self.result_labels['host_count'].config(text=f"{result['host_count']:,}")
            self.result_labels['usable_hosts'].config(text=f"{result['usable_hosts']:,}")
            self.first_host_label.config(text=f"首个可用IP: {result['first_host']}")
            self.last_host_label.config(text=f"最后可用IP: {result['last_host']}")
            ip_binary = '.'.join([bin(int(octet)).split('b')[1].zfill(8) for octet in ip.split('.')])
            netmask_binary = '.'.join([bin(int(octet)).split('b')[1].zfill(8) for octet in result['netmask'].split('.')])
            self.binary_label.config(text=f"IP: {ip_binary}\n子网掩码: {netmask_binary}")
        except Exception as e:
            messagebox.showerror("计算错误", f"计算时发生错误:\n{str(e)}")
    
    def clear(self):
        self.ip_entry.delete(0, tk.END); self.ip_entry.insert(0, "192.168.1.100")
        self.prefix_var.set("24")
        for key in self.result_labels: self.result_labels[key].config(text="-")
        self.first_host_label.config(text="首个可用IP: -")
        self.last_host_label.config(text="最后可用IP: -")
        self.binary_label.config(text="-")
        self.expand_result.delete(1.0, tk.END)
    
    def expand_cidr(self):
        try:
            cidr = self.cidr_entry.get().strip()
            network = ipaddress.ip_network(cidr, strict=False)
            ip_list = list(network)
            self.expand_result.delete(1.0, tk.END)
            self.expand_result.insert(tk.END, f"共 {len(ip_list)} 个IP地址:\n\n")
            if len(ip_list) <= 256:
                for ip in ip_list: self.expand_result.insert(tk.END, f"{ip}\n")
            else:
                for ip in ip_list[:100]: self.expand_result.insert(tk.END, f"{ip}\n")
                self.expand_result.insert(tk.END, f"\n... (省略 {len(ip_list) - 200} 个IP) ...\n\n")
                for ip in ip_list[-100:]: self.expand_result.insert(tk.END, f"{ip}\n")
        except ValueError as e: messagebox.showerror("输入错误", f"无效的CIDR格式:\n{str(e)}")
        except Exception as e: messagebox.showerror("错误", f"展开时发生错误:\n{str(e)}")


class NmapScanner:
    def __init__(self, nmap_path=None):
        self.nmap_path = nmap_path or self._find_nmap()
        self.use_native = self.nmap_path is not None
        self.results = {}
    
    def _find_nmap(self):
        try:
            result = subprocess.run(['where', 'nmap'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines: return lines[0].strip()
        except: pass
        return None
    
    def scan(self, hosts, ports='1-1024', arguments='-sS'):
        if self.use_native: return self._native_scan(hosts, ports, arguments)
        else: return self._socket_scan(hosts, ports, arguments)
    
    def _native_scan(self, hosts, ports, arguments):
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=hosts, ports=ports, arguments=arguments)
            results = {}
            for host in nm.all_hosts():
                results[host] = {'status': nm[host].state(), 'protocols': {}}
                for proto in nm[host].all_protocols():
                    results[host]['protocols'][proto] = {}
                    for port in nm[host][proto].keys():
                        port_info = nm[host][proto][port]
                        results[host]['protocols'][proto][port] = {
                            'state': port_info.get('state', ''), 'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''), 'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')}
            self.results = results
            return results
        except:
            return self._socket_scan(hosts, ports, arguments)
    
    def _socket_scan(self, hosts, ports, arguments):
        results = {}
        host_list = self._parse_hosts(hosts) if isinstance(hosts, str) else (hosts if isinstance(hosts, list) else [hosts])
        port_list = self._parse_ports(ports)
        for host in host_list:
            results[host] = {'status': 'unknown', 'protocols': {'tcp': {}, 'udp': {}}}
            if '-sP' in arguments or '-sn' in arguments:
                if self._ping_host(host): results[host]['status'] = 'up'
                else: results[host]['status'] = 'down'; continue
            else: results[host]['status'] = 'up'
            if '-sS' in arguments or '-sT' in arguments or ('-sS' not in arguments and '-sU' not in arguments):
                for port in port_list:
                    state = self._scan_tcp_port(host, port)
                    if state == 'open':
                        service = self._get_service_name(port)
                        results[host]['protocols']['tcp'][port] = {'state': 'open', 'service': service, 'version': '', 'product': '', 'extrainfo': ''}
            if '-sU' in arguments:
                for port in port_list:
                    state = self._scan_udp_port(host, port)
                    if state == 'open|filtered':
                        service = self._get_service_name(port)
                        results[host]['protocols']['udp'][port] = {'state': 'open|filtered', 'service': service, 'version': '', 'product': '', 'extrainfo': ''}
        self.results = results
        return results
    
    def _parse_hosts(self, hosts_str):
        host_list = []
        if '/' in hosts_str:
            try: network = ipaddress.ip_network(hosts_str, strict=False); host_list = [str(ip) for ip in network.hosts()]
            except: host_list = [hosts_str]
        elif '-' in hosts_str and ':' not in hosts_str:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)-(\d+)', hosts_str)
            if match:
                base_ip = '.'.join(match.group(1).split('.')[:-1])
                start, end = int(match.group(1).split('.')[-1]), int(match.group(2))
                for i in range(start, min(end + 1, 256)): host_list.append(f"{base_ip}.{i}")
            else: host_list = [hosts_str]
        else: host_list = [hosts_str]
        return host_list
    
    def _parse_ports(self, ports_str):
        port_list = []
        aliases = {'top100': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443],
                   'top1000': list(range(1, 1001)), 'all': list(range(1, 65536)),
                   'common': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080]}
        if ports_str in aliases: return aliases[ports_str]
        if '-' in ports_str:
            parts = ports_str.split('-')
            if len(parts) == 2:
                try: port_list = list(range(int(parts[0]), min(int(parts[1]) + 1, 65536)))
                except: port_list = [80]
            else: port_list = [int(ports_str)]
        elif ',' in ports_str:
            for p in ports_str.split(','):
                try: port_list.append(int(p.strip()))
                except: pass
        else:
            try: port_list = [int(ports_str)]
            except: port_list = [80]
        return port_list
    
    def _ping_host(self, host):
        try:
            param = '-n' if platform.system() == "Windows" else '-c'
            result = subprocess.run(['ping', param, '1', '-w', '1000', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return result.returncode == 0
        except: return False
    
    def _scan_tcp_port(self, host, port, timeout=1.0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return 'open' if result == 0 else 'filtered'
        except: return 'closed'
    
    def _scan_udp_port(self, host, port, timeout=1.0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (host, port))
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return 'open'
            except socket.timeout:
                sock.close()
                return 'open|filtered'
        except: return 'closed'
    
    def _get_service_name(self, port):
        services = {20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp',
                    69: 'tftp', 80: 'http', 110: 'pop3', 119: 'nntp', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm',
                    139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 162: 'snmptrap', 389: 'ldap', 443: 'https', 445: 'microsoft-ds',
                    465: 'smtps', 514: 'syslog', 515: 'printer', 587: 'submission', 636: 'ldaps', 993: 'imaps', 995: 'pop3s',
                    1080: 'socks', 1433: 'mssql', 1434: 'mssql-m', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs', 3306: 'mysql',
                    3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 5985: 'winrm', 5986: 'winrm-ssl', 6379: 'redis',
                    8080: 'http-proxy', 8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb'}
        return services.get(port, 'unknown')
    
    def get_nmap_output(self):
        output_lines = []
        for host, data in self.results.items():
            output_lines.append(f"Nmap scan report for {host}")
            output_lines.append(f"Host is {data['status']}.")
            output_lines.append("")
            for proto in ['tcp', 'udp']:
                if proto in data['protocols'] and data['protocols'][proto]:
                    output_lines.append(f"PORT      STATE    SERVICE")
                    for port, info in sorted(data['protocols'][proto].items()):
                        output_lines.append(f"{port}/{proto:3}  {info['state']:12} {info['service']}")
                    output_lines.append("")
        return "\n".join(output_lines)


class NmapScanGUI:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.scanner = NmapScanner()
        self.use_native = self.scanner.use_native
        self.scanning = False
        self.results = {}
        self.root = None
        self.create_widgets()
    
    def set_root(self, root): self.root = root
    
    def create_widgets(self):
        status_frame = ttk.Frame(self.frame)
        status_frame.pack(fill=tk.X, pady=5)
        if self.use_native:
            status_text = f"检测到原生nmap: {self.scanner.nmap_path}"
            status_color = 'green'
        else:
            status_text = "未检测到nmap，将使用模拟模式"
            status_color = 'orange'
        self.status_label = ttk.Label(status_frame, text=status_text, foreground=status_color)
        self.status_label.pack(side=tk.LEFT)
        target_frame = ttk.LabelFrame(self.frame, text="目标设置", padding="10")
        target_frame.pack(fill=tk.X, pady=5)
        target_frame.columnconfigure(1, weight=1)
        ttk.Label(target_frame, text="目标:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.target_entry.insert(0, "127.0.0.1")
        ttk.Label(target_frame, text="端口:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.ports_entry = ttk.Entry(target_frame, width=50)
        self.ports_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        self.ports_entry.insert(0, "22,80,443,3306,5432,8080")
        port_quick_frame = ttk.Frame(target_frame)
        port_quick_frame.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Button(port_quick_frame, text="常用端口", command=lambda: self._set_ports("21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080"), width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(port_quick_frame, text="Top100", command=lambda: self._set_ports("top100"), width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(port_quick_frame, text="Web端口", command=lambda: self._set_ports("80,443,8080,8443,8000,8888"), width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(port_quick_frame, text="数据库端口", command=lambda: self._set_ports("3306,5432,1433,1521,27017,6379,9200"), width=12).pack(side=tk.LEFT, padx=2)
        scan_type_frame = ttk.LabelFrame(self.frame, text="扫描类型", padding="10")
        scan_type_frame.pack(fill=tk.X, pady=5)
        self.scan_type_var = tk.StringVar(value="-sS")
        scan_types = [('-sS', 'TCP SYN扫描'), ('-sT', 'TCP Connect扫描'), ('-sU', 'UDP扫描'), ('-sP', 'Ping扫描'), ('-A', '综合扫描(A)')]
        for i, (value, text) in enumerate(scan_types):
            row, col = i // 3, i % 3
            ttk.Radiobutton(scan_type_frame, text=text, variable=self.scan_type_var, value=value).grid(row=row, column=col, sticky=tk.W, padx=10, pady=2)
        options_frame = ttk.LabelFrame(self.frame, text="扫描选项", padding="10")
        options_frame.pack(fill=tk.X, pady=5)
        self.version_detect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="版本检测 (-sV)", variable=self.version_detect_var).grid(row=0, column=0, sticky=tk.W, padx=10)
        self.os_detect_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="操作系统检测 (-O)", variable=self.os_detect_var).grid(row=0, column=1, sticky=tk.W, padx=10)
        self.aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="激进模式 (-T4)", variable=self.aggressive_var).grid(row=0, column=2, sticky=tk.W, padx=10)
        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="详细输出 (-v)", variable=self.verbose_var).grid(row=1, column=0, sticky=tk.W, padx=10)
        cmd_frame = ttk.Frame(options_frame)
        cmd_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=5)
        ttk.Label(cmd_frame, text="命令预览:").pack(side=tk.LEFT)
        self.cmd_preview = ttk.Label(cmd_frame, text="nmap -v -sS 127.0.0.1", font=('Consolas', 10), foreground='blue')
        self.cmd_preview.pack(side=tk.LEFT, padx=5)
        btn_frame = ttk.Frame(self.frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.start_btn = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="停止", command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空", command=self.clear_results, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出", command=self.export_results, width=15).pack(side=tk.LEFT, padx=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.frame, variable=self.progress_var, maximum=100, length=600, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        self.status_text = ttk.Label(self.frame, text="就绪")
        self.status_text.pack(anchor=tk.W)
        result_frame = ttk.LabelFrame(self.frame, text="扫描结果", padding="5")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=90, height=15, font=('Consolas', 10))
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        for var in [self.scan_type_var, self.version_detect_var, self.os_detect_var, self.aggressive_var, self.verbose_var]:
            var.trace_add('write', lambda *args: self.update_cmd_preview())
        self.update_cmd_preview()
    
    def _set_ports(self, ports):
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, ports)
    
    def update_cmd_preview(self):
        target = self.target_entry.get().strip() or "TARGET"
        ports = self.ports_entry.get().strip() or "PORTS"
        cmd_parts = []
        if self.verbose_var.get(): cmd_parts.append("-v")
        cmd_parts.append(self.scan_type_var.get())
        if self.version_detect_var.get(): cmd_parts.append("-sV")
        if self.os_detect_var.get(): cmd_parts.append("-O")
        if self.aggressive_var.get(): cmd_parts.append("-T4")
        cmd = f"nmap {' '.join(cmd_parts)} -p {ports} {target}"
        if not self.use_native: cmd = cmd.replace("nmap", "[模拟] nmap", 1)
        self.cmd_preview.config(text=cmd)
    
    def log(self, message, tag=None):
        self.result_text.insert(tk.END, f"{message}\n", tag)
        if tag: self.result_text.tag_config(tag, foreground=tag)
        self.result_text.see(tk.END)
    
    def start_scan(self):
        target = self.target_entry.get().strip()
        ports = self.ports_entry.get().strip()
        if not target:
            messagebox.showerror("输入错误", "请输入目标地址！"); return
        self.scanning = True
        self.results = {}
        self.result_text.delete(1.0, tk.END)
        self.log("=" * 60)
        self.log(f"Nmap扫描开始")
        self.log(f"目标: {target}")
        self.log(f"端口: {ports}")
        self.log(f"模式: {self.scan_type_var.get()}")
        self.log("-" * 60)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        arguments = self.scan_type_var.get()
        if self.version_detect_var.get(): arguments += " -sV"
        if self.os_detect_var.get(): arguments += " -O"
        if self.aggressive_var.get(): arguments += " -T4"
        if self.verbose_var.get(): arguments += " -v"
        self.status_text.config(text=f"正在扫描: {target}")
        self.progress_var.set(0)
        thread = threading.Thread(target=self._run_scan, args=(target, ports, arguments), daemon=True)
        thread.start()
    
    def _run_scan(self, target, ports, arguments):
        start_time = time.time()
        try:
            scanner = NmapScanner()
            host_list = scanner._parse_hosts(target)
            total_hosts = len(host_list)
            for idx, host in enumerate(host_list):
                if not self.scanning: break
                if self.root: self.root.after(0, lambda h=host: self.status_text.config(text=f"正在扫描: {h}"))
                results = scanner.scan(host, ports, arguments)
                self.results.update(results)
                progress = ((idx + 1) / total_hosts) * 100
                if self.root: self.root.after(0, lambda p=progress: self.progress_var.set(p))
            if self.root: self.root.after(0, self._display_results)
        except Exception as e:
            if self.root: self.root.after(0, lambda: self.log(f"\n错误: {str(e)}", 'red'))
        duration = time.time() - start_time
        if self.root: self.root.after(0, lambda: self._scan_complete(duration))
    
    def _display_results(self):
        self._show_results_window()
    
    def _show_results_window(self):
        results_window = tk.Toplevel(self.root)
        results_window.title("扫描结果 - NetKit")
        results_window.geometry("900x650")
        results_window.update_idletasks()
        x = (results_window.winfo_screenwidth() // 2) - (900 // 2)
        y = (results_window.winfo_screenheight() // 2) - (650 // 2)
        results_window.geometry(f"900x650+{x}+{y}")
        title_frame = ttk.Frame(results_window, padding="10")
        title_frame.pack(fill=tk.X)
        ttk.Label(title_frame, text="Nmap 扫描结果", font=('微软雅黑', 14, 'bold')).pack(side=tk.LEFT)
        ttk.Label(title_frame, text=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), font=('Consolas', 10), foreground='gray').pack(side=tk.RIGHT)
        result_frame = ttk.Frame(results_window, padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True)
        result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=100, height=30, font=('Consolas', 11))
        result_text.pack(fill=tk.BOTH, expand=True)
        lines = ["=" * 80, "                         Nmap 扫描结果汇总", "=" * 80]
        total_hosts = len(self.results)
        total_open = sum(len(proto) for data in self.results.values() for proto in data['protocols'].values() if proto)
        lines.append(f"\n扫描概览:")
        lines.append(f"   扫描主机数: {total_hosts}")
        lines.append(f"   发现开放端口: {total_open} 个")
        for host, data in self.results.items():
            lines.append(f"\n{'─' * 80}")
            lines.append(f"主机: {host}")
            lines.append(f"   状态: {data['status'].upper()}")
            host_open_ports = sum(len(proto) for proto in data['protocols'].values() if proto)
            if host_open_ports > 0:
                lines.append(f"   开放端口数: {host_open_ports}")
                if 'tcp' in data['protocols'] and data['protocols']['tcp']:
                    lines.append(f"\n   TCP 端口:")
                    lines.append(f"   {'端口':<8} {'状态':<12} {'服务':<18} {'版本信息'}")
                    lines.append(f"   {'─'*8} {'─'*12} {'─'*18} {'─'*25}")
                    for port, info in sorted(data['protocols']['tcp'].items()):
                        state = info['state']
                        service = info['service']
                        version_info = f"{info.get('product', '')} {info.get('version', '')}".strip() or "-"
                        lines.append(f"   {port:<8} {state:<12} {service:<18} {version_info}")
                if 'udp' in data['protocols'] and data['protocols']['udp']:
                    lines.append(f"\n   UDP 端口:")
                    lines.append(f"   {'端口':<8} {'状态':<15} {'服务':<15}")
                    lines.append(f"   {'─'*8} {'─'*15} {'─'*15}")
                    for port, info in sorted(data['protocols']['udp'].items()):
                        lines.append(f"   {port:<8} {info['state']:<15} {info['service']:<15}")
            else:
                lines.append(f"   无开放端口")
        lines.append(f"\n{'=' * 80}")
        lines.append(f"扫描完成 | 发现 {total_open} 个开放端口")
        for line in lines: result_text.insert(tk.END, line + "\n")
        btn_frame = ttk.Frame(results_window, padding="10")
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="导出结果", command=lambda: self._export_from_window(result_text.get('1.0', tk.END))).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制全部", command=lambda: self._copy_results(result_text.get('1.0', tk.END))).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="关闭", command=results_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def _export_from_window(self, content):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f: f.write(content)
                messagebox.showinfo("导出成功", f"结果已保存到:\n{filename}")
            except Exception as e: messagebox.showerror("导出失败", f"导出时发生错误:\n{str(e)}")
    
    def _copy_results(self, content):
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("复制成功", "结果已复制到剪贴板")
    
    def _scan_complete(self, duration):
        self.scanning = False
        self.progress_var.set(100)
        self.log(f"\n扫描完成，耗时: {duration:.2f} 秒")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_text.config(text="扫描完成")
        messagebox.showinfo("扫描完成", f"扫描完成！\n耗时: {duration:.2f} 秒")
    
    def stop_scan(self):
        self.scanning = False
        self.log("\n扫描被用户停止", 'orange')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_text.config(text="已停止")
    
    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.results = {}
        self.progress_var.set(0)
        self.status_text.config(text="就绪")
    
    def export_results(self):
        if not self.results:
            messagebox.showwarning("警告", "没有可导出的扫描结果！"); return
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Nmap扫描报告\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n" + "=" * 60 + "\n\n")
                    for host, data in self.results.items():
                        f.write(f"Nmap scan report for {host}\nHost is {data['status']}.\n\n")
                        for proto in ['tcp', 'udp']:
                            if proto in data['protocols'] and data['protocols'][proto]:
                                f.write(f"PORT      STATE    SERVICE\n")
                                for port, info in sorted(data['protocols'][proto].items()):
                                    f.write(f"{port}/{proto:3}  {info['state']:12} {info['service']}\n")
                        f.write("\n")
                self.log(f"\n结果已导出到: {filename}")
                messagebox.showinfo("导出成功", f"结果已保存到:\n{filename}")
            except Exception as e: messagebox.showerror("导出失败", f"导出时发生错误:\n{str(e)}")


class ScanResultsGUI:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.results_data = {}
        self.history = []
        self.create_widgets()
    
    def create_widgets(self):
        header_frame = ttk.Frame(self.frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header_frame, text="扫描结果", font=('微软雅黑', 14, 'bold')).pack(side=tk.LEFT)
        self.timestamp_label = ttk.Label(header_frame, text="", font=('Consolas', 10), foreground='gray')
        self.timestamp_label.pack(side=tk.RIGHT)
        stats_frame = ttk.LabelFrame(self.frame, text="扫描统计", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)
        self.stats_labels = {}
        stats_items = [('total_hosts', '扫描主机数'), ('online_hosts', '在线主机数'), ('total_ports', '开放端口数'), ('scan_time', '扫描耗时')]
        for idx, (key, label_text) in enumerate(stats_items):
            row, col = idx // 2, idx % 2
            container = ttk.Frame(stats_frame)
            container.grid(row=row, column=col, sticky=tk.W, padx=20, pady=5)
            ttk.Label(container, text=f"{label_text}:", width=12).pack(side=tk.LEFT)
            value_label = ttk.Label(container, text="-", font=('Consolas', 11, 'bold'), foreground='#2196F3')
            value_label.pack(side=tk.LEFT, padx=5)
            self.stats_labels[key] = value_label
        result_list_frame = ttk.LabelFrame(self.frame, text="扫描详情", padding="5")
        result_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        result_list_frame.columnconfigure(0, weight=1)
        result_list_frame.rowconfigure(0, weight=1)
        columns = ('主机', '端口', '服务', '状态', '版本')
        self.result_tree = ttk.Treeview(result_list_frame, columns=columns, show='headings', height=15)
        for col in columns: self.result_tree.heading(col, text=col)
        self.result_tree.column('主机', width=150, anchor=tk.W)
        self.result_tree.column('端口', width=80, anchor=tk.CENTER)
        self.result_tree.column('服务', width=120, anchor=tk.W)
        self.result_tree.column('状态', width=80, anchor=tk.CENTER)
        self.result_tree.column('版本', width=200, anchor=tk.W)
        tree_scroll_y = ttk.Scrollbar(result_list_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        tree_scroll_x = ttk.Scrollbar(result_list_frame, orient=tk.HORIZONTAL, command=self.result_tree.xview)
        self.result_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        self.result_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        tree_scroll_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        btn_frame = ttk.Frame(self.frame)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="导出结果", command=self.export_results, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制全部", command=self.copy_results, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空结果", command=self.clear_results, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="按主机分组", command=self.group_by_host, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="按服务分组", command=self.group_by_service, width=15).pack(side=tk.LEFT, padx=5)
    
    def display_results(self, results, scan_type='nmap', duration=0, ping_results=None):
        self.results_data = {'results': results, 'scan_type': scan_type, 'duration': duration, 'ping_results': ping_results or {}, 'timestamp': datetime.now()}
        total_hosts = len(results)
        total_ports = sum(len(proto) for data in results.values() for proto in data.get('protocols', {}).values() if proto) if scan_type == 'nmap' else sum(len(p) for p in results.values() if isinstance(p, list))
        self.stats_labels['total_hosts'].config(text=str(total_hosts))
        self.stats_labels['online_hosts'].config(text=str(total_hosts))
        self.stats_labels['total_ports'].config(text=str(total_ports))
        self.stats_labels['scan_time'].config(text=f"{duration:.2f} 秒")
        self.timestamp_label.config(text=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        for item in self.result_tree.get_children(): self.result_tree.delete(item)
        if scan_type == 'nmap': self._display_nmap_results(results)
        else: self._display_port_results(results)
        self.history.append({'timestamp': datetime.now(), 'results': results, 'scan_type': scan_type, 'duration': duration})
    
    def _display_nmap_results(self, results):
        for host, data in results.items():
            protocols = data.get('protocols', {})
            for proto in ['tcp', 'udp']:
                if proto in protocols and protocols[proto]:
                    for port, info in sorted(protocols[proto].items()):
                        version_info = f"{info.get('product', '')} {info.get('version', '')}".strip() or '-'
                        self.result_tree.insert('', tk.END, values=(host, f"{port}/{proto}", info.get('service', 'unknown'), info.get('state', 'unknown'), version_info))
    
    def _display_port_results(self, results):
        for host, ports in results.items():
            if ports:
                for port, service in sorted(ports):
                    self.result_tree.insert('', tk.END, values=(host, port, service, 'open', '-'))
    
    def group_by_host(self):
        if not self.results_data.get('results'): return
        for item in self.result_tree.get_children(): self.result_tree.delete(item)
        results = self.results_data['results']
        if self.results_data['scan_type'] == 'nmap':
            for host, data in sorted(results.items()):
                host_id = self.result_tree.insert('', tk.END, values=(f"{host}", '---', f"状态: {data.get('status', 'unknown')}", '---', '---'))
                protocols = data.get('protocols', {})
                for proto in ['tcp', 'udp']:
                    if proto in protocols and protocols[proto]:
                        for port, info in sorted(protocols[proto].items()):
                            self.result_tree.insert(host_id, tk.END, values=('', f"{port}/{proto}", info.get('service', 'unknown'), info.get('state', 'unknown'), (info.get('product', '') + ' ' + info.get('version', '')).strip() or '-'))
        else:
            for host, ports in sorted(results.items()):
                host_id = self.result_tree.insert('', tk.END, values=(f"{host}", '---', f"开放端口: {len(ports)}", '---', '---'))
                for port, service in sorted(ports): self.result_tree.insert(host_id, tk.END, values=('', port, service, 'open', '-'))
    
    def group_by_service(self):
        if not self.results_data.get('results'): return
        for item in self.result_tree.get_children(): self.result_tree.delete(item)
        services = {}
        results = self.results_data['results']
        if self.results_data['scan_type'] == 'nmap':
            for host, data in results.items():
                for proto, proto_data in data.get('protocols', {}).items():
                    if proto_data:
                        for port, info in proto_data.items():
                            service = info.get('service', 'unknown')
                            if service not in services: services[service] = []
                            services[service].append((host, f"{port}/{proto}", info.get('state', 'unknown')))
        else:
            for host, ports in results.items():
                for port, service in ports:
                    if service not in services: services[service] = []
                    services[service].append((host, str(port), 'open'))
        for service in sorted(services.keys()):
            service_id = self.result_tree.insert('', tk.END, values=(f"{service}", f"共 {len(services[service])} 个", '---', '---', '---'))
            for host, port, state in services[service]: self.result_tree.insert(service_id, tk.END, values=(host, port, service, state, '-'))
    
    def export_results(self):
        if not self.results_data.get('results'):
            messagebox.showwarning("警告", "没有可导出的扫描结果！"); return
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"{'=' * 60}\n扫描结果报告\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'=' * 60}\n\n")
                    f.write("【统计信息】\n")
                    f.write(f"扫描类型: {self.results_data.get('scan_type', 'unknown')}\n")
                    f.write(f"扫描耗时: {self.results_data.get('duration', 0):.2f} 秒\n")
                    results = self.results_data['results']
                    f.write(f"主机数: {len(results)}\n")
                    total_ports = sum(len(proto) for data in results.values() for proto in data.get('protocols', {}).values() if proto)
                    f.write(f"开放端口数: {total_ports}\n\n")
                    f.write("【详细结果】\n" + "-" * 60 + "\n")
                    for host, data in sorted(results.items()):
                        f.write(f"\n主机: {host}\n状态: {data.get('status', 'unknown')}\n")
                        protocols = data.get('protocols', {})
                        for proto in ['tcp', 'udp']:
                            if proto in protocols and protocols[proto]:
                                f.write(f"\n  {proto.upper()} 端口:\n")
                                f.write(f"  {'端口':<10} {'状态':<12} {'服务':<20} {'版本'}\n")
                                f.write(f"  {'-'*10} {'-'*12} {'-'*20} {'-'*20}\n")
                                for port, info in sorted(protocols[proto].items()):
                                    version = f"{info.get('product', '')} {info.get('version', '')}".strip()
                                    f.write(f"  {port:<10} {info.get('state', ''):<12} {info.get('service', ''):<20} {version}\n")
                messagebox.showinfo("导出成功", f"结果已保存到:\n{filename}")
            except Exception as e: messagebox.showerror("导出失败", f"导出时发生错误:\n{str(e)}")
    
    def copy_results(self):
        if not self.results_data.get('results'):
            messagebox.showwarning("警告", "没有可复制的扫描结果！"); return
        results = self.results_data['results']
        lines = ["=" * 60, "扫描结果", "=" * 60]
        if self.results_data['scan_type'] == 'nmap':
            for host, data in sorted(results.items()):
                lines.append(f"\n主机: {host}")
                lines.append(f"状态: {data.get('status', 'unknown')}")
                for proto in ['tcp', 'udp']:
                    if proto in data['protocols'] and data['protocols'][proto]:
                        lines.append(f"\n  {proto.upper()} 端口:")
                        for port, info in sorted(data['protocols'][proto].items()):
                            lines.append(f"    {port}/{proto}: {info.get('state', '')} - {info.get('service', '')}")
        content = '\n'.join(lines)
        try:
            self.frame.clipboard_clear()
            self.frame.clipboard_append(content)
            messagebox.showinfo("复制成功", "结果已复制到剪贴板")
        except Exception as e: messagebox.showerror("复制失败", f"复制时发生错误:\n{str(e)}")
    
    def clear_results(self):
        for item in self.result_tree.get_children(): self.result_tree.delete(item)
        for key in self.stats_labels: self.stats_labels[key].config(text="-")
        self.timestamp_label.config(text="")
        self.results_data = {}


class IPGeolocationGUI:
    """IP归属地查询 - 通过多个公开API查询IP的地理位置和ISP信息"""

    APIS = [
        {
            'name': 'ip-api.com',
            'url': 'http://ip-api.com/json/{ip}?lang=zh-CN',
            'parse': lambda data: {
                'ip': data.get('query', '-'),
                '国家': data.get('country', '-'),
                '地区/省': data.get('regionName', '-'),
                '城市': data.get('city', '-'),
                '区县': data.get('district', '-') or '-',
                'ISP/运营商': data.get('isp', '-'),
                '组织': data.get('org', '-'),
                'AS号': data.get('as', '-'),
                '时区': data.get('timezone', '-'),
                '纬度': str(data.get('lat', '-')),
                '经度': str(data.get('lon', '-')),
                '邮编': data.get('zip', '-'),
            }
        },
        {
            'name': 'ipapi.co',
            'url': 'https://ipapi.co/{ip}/json/',
            'parse': lambda data: {
                'ip': data.get('ip', '-'),
                '国家': data.get('country_name', '-'),
                '地区/省': data.get('region', '-'),
                '城市': data.get('city', '-'),
                '区县': data.get('district', '-') or '-',
                'ISP/运营商': data.get('org', '-'),
                '组织': data.get('org', '-'),
                'AS号': data.get('asn', '-'),
                '时区': data.get('timezone', '-'),
                '纬度': str(data.get('latitude', '-')),
                '经度': str(data.get('longitude', '-')),
                '邮编': data.get('postal', '-'),
            }
        },
        {
            'name': '淘宝IP库',
            'url': 'https://ip.taobao.com/service/getIpInfo.php?ip={ip}',
            'parse': lambda data: {
                'ip': (data.get('data') or {}).get('ip', '-'),
                '国家': (data.get('data') or {}).get('country', '-'),
                '地区/省': (data.get('data') or {}).get('region', '-'),
                '城市': (data.get('data') or {}).get('city', '-'),
                '区县': (data.get('data') or {}).get('area', '-'),
                'ISP/运营商': (data.get('data') or {}).get('isp', '-'),
                '组织': (data.get('data') or {}).get('isp', '-'),
                'AS号': '-',
                '时区': '-',
                '纬度': '-',
                '经度': '-',
                '邮编': '-',
            }
        }
    ]

    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.history = []
        self.cache = {}
        self.cache_ttl = 3600
        self.busy = False
        self.local_ip = self._get_local_ip()
        self.create_widgets()

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("223.5.5.5", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    def _resolve_domain(self, domain):
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            raise ValueError(f"域名解析失败: {e}")

    def _query_api(self, api, ip):
        url = api['url'].format(ip=ip)
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (NetKit IP Geolocation Tool)',
            'Accept': 'application/json',
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode('utf-8', errors='ignore')
        data = json.loads(raw)
        return api['parse'](data), api['name']

    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    def lookup(self, ip_input, use_cache=True):
        if not ip_input or not ip_input.strip():
            raise ValueError("请输入有效的IP或域名")
        ip_input = ip_input.strip()
        try:
            ipaddress.ip_address(ip_input)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip:
            resolved = self._resolve_domain(ip_input)
            ip = resolved
            display_target = f"{ip_input} -> {ip}"
        else:
            ip = ip_input
            display_target = ip
        if self._is_private_ip(ip):
            return {
                '_target': display_target, '_ip': ip, '_source': '本地',
                '国家': '本地网络', '地区/省': '-', '城市': '-', '区县': '-',
                'ISP/运营商': '局域网/私有地址', '组织': '-', 'AS号': '-',
                '时区': '-', '纬度': '-', '经度': '-', '邮编': '-',
            }
        if use_cache and ip in self.cache:
            cached, ts = self.cache[ip]
            if time.time() - ts < self.cache_ttl:
                result = dict(cached)
                result['_target'] = display_target
                result['_cached'] = True
                return result
        last_err = None
        for api in self.APIS:
            try:
                result, source = self._query_api(api, ip)
                result['_target'] = display_target
                result['_ip'] = ip
                result['_source'] = source
                self.cache[ip] = (dict(result), time.time())
                return result
            except Exception as e:
                last_err = e
                continue
        raise RuntimeError(f"所有API均查询失败: {last_err}")

    def get_my_public_ip(self):
        urls = [
            'https://api.ipify.org?format=json',
            'https://ifconfig.me/all.json',
            'https://ipinfo.io/json',
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode('utf-8', errors='ignore'))
                if 'ip' in data: return data['ip']
                if 'origin' in data: return data['origin']
                if 'ip_addr' in data: return data['ip_addr']
            except Exception:
                continue
        return None

    def create_widgets(self):
        input_frame = ttk.LabelFrame(self.frame, text="IP / 域名 查询", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        input_frame.columnconfigure(1, weight=1)
        ttk.Label(input_frame, text="目标:", width=10).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.ip_entry = ttk.Entry(input_frame, width=50, font=('Consolas', 10))
        self.ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.ip_entry.insert(0, "8.8.8.8")
        self.ip_entry.bind('<Return>', lambda e: self.single_lookup())
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=0, column=2, padx=5)
        self.query_btn = ttk.Button(btn_frame, text="查询", command=self.single_lookup, width=10)
        self.query_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="清空", command=self.clear_single, width=8).pack(side=tk.LEFT, padx=2)
        quick_frame = ttk.Frame(input_frame)
        quick_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(8, 0))
        ttk.Label(quick_frame, text="快捷:", foreground='gray').pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="我的公网IP", command=self.lookup_my_ip, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="本机内网IP", command=self.lookup_local_ip, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="百度", command=lambda: self._quick_set("baidu.com"), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="谷歌", command=lambda: self._quick_set("google.com"), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="GitHub", command=lambda: self._quick_set("github.com"), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="114DNS", command=lambda: self._quick_set("114.114.114.114"), width=8).pack(side=tk.LEFT, padx=2)
        hint_label = ttk.Label(input_frame, text="支持单个IP、域名 (如 8.8.8.8 / baidu.com)", foreground='gray', font=('微软雅黑', 8))
        hint_label.grid(row=2, column=0, columnspan=3, sticky=tk.W, padx=5, pady=(5, 0))
        self.status_label = ttk.Label(self.frame, text="就绪", foreground='gray', font=('Consolas', 9))
        self.status_label.pack(anchor=tk.W, padx=5, pady=2)
        self.inner_notebook = ttk.Notebook(self.frame)
        self.inner_notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        single_frame = ttk.Frame(self.inner_notebook, padding="5")
        self.inner_notebook.add(single_frame, text="详细信息")
        single_frame.columnconfigure(0, weight=1)
        single_frame.rowconfigure(0, weight=1)
        detail_tree_frame = ttk.Frame(single_frame)
        detail_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        detail_tree_frame.columnconfigure(0, weight=1)
        detail_tree_frame.rowconfigure(0, weight=1)
        self.detail_tree = ttk.Treeview(detail_tree_frame, columns=('field', 'value'), show='headings', height=14)
        self.detail_tree.heading('field', text='字段')
        self.detail_tree.heading('value', text='值')
        self.detail_tree.column('field', width=160, anchor=tk.W)
        self.detail_tree.column('value', width=500, anchor=tk.W)
        ds_y = ttk.Scrollbar(detail_tree_frame, orient=tk.VERTICAL, command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=ds_y.set)
        self.detail_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ds_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        map_frame = ttk.Frame(single_frame)
        map_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        ttk.Label(map_frame, text="地图查看:", font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=5)
        self.map_link_label = ttk.Label(map_frame, text="(查询后显示)", foreground='blue', cursor='hand2', font=('Consolas', 9))
        self.map_link_label.pack(side=tk.LEFT, padx=5)
        ttk.Button(map_frame, text="打开地图", command=self.open_map, width=10).pack(side=tk.LEFT, padx=5)
        batch_frame = ttk.Frame(self.inner_notebook, padding="5")
        self.inner_notebook.add(batch_frame, text="批量查询")
        batch_frame.columnconfigure(0, weight=1)
        batch_frame.rowconfigure(1, weight=1)
        batch_input_frame = ttk.Frame(batch_frame)
        batch_input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        batch_input_frame.columnconfigure(0, weight=1)
        ttk.Label(batch_input_frame, text="输入多个IP/域名（每行一个）:").grid(row=0, column=0, sticky=tk.W)
        self.batch_text = scrolledtext.ScrolledText(batch_input_frame, height=6, font=('Consolas', 10), wrap=tk.WORD)
        self.batch_text.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=3)
        self.batch_text.insert(tk.END, "8.8.8.8\n1.1.1.1\n114.114.114.114\nbaidu.com\ngithub.com")
        batch_btn_frame = ttk.Frame(batch_input_frame)
        batch_btn_frame.grid(row=2, column=0, sticky=tk.W, pady=3)
        self.batch_btn = ttk.Button(batch_btn_frame, text="开始批量查询", command=self.batch_lookup, width=18)
        self.batch_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(batch_btn_frame, text="清空", command=lambda: self.batch_text.delete('1.0', tk.END), width=8).pack(side=tk.LEFT, padx=2)
        self.batch_progress = ttk.Progressbar(batch_input_frame, mode='determinate', length=400)
        self.batch_progress.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=3)
        batch_result_frame = ttk.Frame(batch_frame)
        batch_result_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        batch_result_frame.columnconfigure(0, weight=1)
        batch_result_frame.rowconfigure(0, weight=1)
        cols = ('目标', 'IP', '国家', '地区/省', '城市', 'ISP/运营商', '数据源')
        self.batch_tree = ttk.Treeview(batch_result_frame, columns=cols, show='headings', height=10)
        for c in cols: self.batch_tree.heading(c, text=c)
        self.batch_tree.column('目标', width=180, anchor=tk.W)
        self.batch_tree.column('IP', width=130, anchor=tk.W)
        self.batch_tree.column('国家', width=90, anchor=tk.W)
        self.batch_tree.column('地区/省', width=110, anchor=tk.W)
        self.batch_tree.column('城市', width=100, anchor=tk.W)
        self.batch_tree.column('ISP/运营商', width=180, anchor=tk.W)
        self.batch_tree.column('数据源', width=110, anchor=tk.W)
        bs_y = ttk.Scrollbar(batch_result_frame, orient=tk.VERTICAL, command=self.batch_tree.yview)
        bs_x = ttk.Scrollbar(batch_result_frame, orient=tk.HORIZONTAL, command=self.batch_tree.xview)
        self.batch_tree.configure(yscrollcommand=bs_y.set, xscrollcommand=bs_x.set)
        self.batch_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        bs_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        bs_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        history_frame = ttk.Frame(self.inner_notebook, padding="5")
        self.inner_notebook.add(history_frame, text="查询历史")
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        hist_tree_frame = ttk.Frame(history_frame)
        hist_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        hist_tree_frame.columnconfigure(0, weight=1)
        hist_tree_frame.rowconfigure(0, weight=1)
        hist_cols = ('时间', '目标', 'IP', '国家', '城市', 'ISP')
        self.history_tree = ttk.Treeview(hist_tree_frame, columns=hist_cols, show='headings', height=12)
        for c in hist_cols: self.history_tree.heading(c, text=c)
        self.history_tree.column('时间', width=140, anchor=tk.W)
        self.history_tree.column('目标', width=160, anchor=tk.W)
        self.history_tree.column('IP', width=120, anchor=tk.W)
        self.history_tree.column('国家', width=80, anchor=tk.W)
        self.history_tree.column('城市', width=100, anchor=tk.W)
        self.history_tree.column('ISP', width=200, anchor=tk.W)
        hs_y = ttk.Scrollbar(hist_tree_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=hs_y.set)
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        hs_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.history_tree.bind('<Double-1>', lambda e: self.relookup_selected())
        hist_btn_frame = ttk.Frame(history_frame)
        hist_btn_frame.grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Button(hist_btn_frame, text="重新查询选中", command=self.relookup_selected, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(hist_btn_frame, text="清空历史", command=self.clear_history, width=12).pack(side=tk.LEFT, padx=2)
        bottom_frame = ttk.Frame(self.frame)
        bottom_frame.pack(fill=tk.X, pady=5)
        ttk.Button(bottom_frame, text="导出结果", command=self.export_results, width=12).pack(side=tk.LEFT, padx=3)
        ttk.Button(bottom_frame, text="复制详情", command=self.copy_detail, width=12).pack(side=tk.LEFT, padx=3)
        ttk.Button(bottom_frame, text="清空全部", command=self.clear_all, width=12).pack(side=tk.LEFT, padx=3)
        ttk.Label(bottom_frame, text=f"本机IP: {self.local_ip}", foreground='gray', font=('Consolas', 9)).pack(side=tk.RIGHT, padx=5)

    def _quick_set(self, value):
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, value)

    def single_lookup(self):
        target = self.ip_entry.get().strip()
        if not target:
            messagebox.showwarning("提示", "请输入IP或域名")
            return
        if self.busy:
            messagebox.showinfo("提示", "正在查询中，请稍候")
            return
        self.busy = True
        self.query_btn.config(state=tk.DISABLED)
        self.status_label.config(text=f"正在查询: {target} ...", foreground='blue')
        def _do():
            try:
                result = self.lookup(target)
                self.frame.after(0, lambda: self._display_single_result(result))
            except Exception as e:
                self.frame.after(0, lambda: self._on_query_error(str(e)))
            finally:
                self.frame.after(0, lambda: self._reset_busy())
        threading.Thread(target=_do, daemon=True).start()

    def _display_single_result(self, result):
        for item in self.detail_tree.get_children(): self.detail_tree.delete(item)
        field_order = ['_target', '国家', '地区/省', '城市', '区县', 'ISP/运营商',
                       '组织', 'AS号', '时区', '纬度', '经度', '邮编']
        for key in field_order:
            if key in result:
                k = '查询目标' if key == '_target' else key
                v = str(result[key])
                if key == '_target' and result.get('_cached'):
                    v = v + "  (来自缓存)"
                self.detail_tree.insert('', tk.END, values=(k, v))
        lat = result.get('纬度', '-')
        lon = result.get('经度', '-')
        if lat != '-' and lon != '-':
            self.map_link_label.config(text=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=10/{lat}/{lon}")
        else:
            self.map_link_label.config(text="(无经纬度信息)")
        self._add_history(result)
        source = result.get('_source', '-')
        self.status_label.config(text=f"查询成功 [数据源: {source}]", foreground='green')

    def _on_query_error(self, msg):
        self.status_label.config(text=f"查询失败: {msg}", foreground='red')
        messagebox.showerror("查询失败", msg)

    def _reset_busy(self):
        self.busy = False
        self.query_btn.config(state=tk.NORMAL)

    def batch_lookup(self):
        content = self.batch_text.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("提示", "请输入要查询的IP/域名列表")
            return
        targets = [t.strip() for t in content.split('\n') if t.strip()]
        if not targets: return
        if len(targets) > 50:
            if not messagebox.askyesno("确认", f"将要查询 {len(targets)} 个目标，可能需要较长时间，是否继续？"):
                return
        for item in self.batch_tree.get_children(): self.batch_tree.delete(item)
        self.batch_btn.config(state=tk.DISABLED)
        self.batch_progress['maximum'] = len(targets)
        self.batch_progress['value'] = 0
        self.status_label.config(text=f"批量查询中: 0/{len(targets)}", foreground='blue')
        def _worker():
            success = 0
            fail = 0
            for idx, t in enumerate(targets):
                try:
                    r = self.lookup(t)
                    self.frame.after(0, lambda r=r: self._add_batch_row(r))
                    self._add_history(r)
                    success += 1
                except Exception as e:
                    self.frame.after(0, lambda t=t, e=str(e): self._add_batch_row_error(t, e))
                    fail += 1
                self.frame.after(0, lambda i=idx+1, n=len(targets): self._update_batch_progress(i, n))
                time.sleep(0.2)
            self.frame.after(0, lambda: self._batch_done(success, fail))
        threading.Thread(target=_worker, daemon=True).start()

    def _add_batch_row(self, r):
        self.batch_tree.insert('', tk.END, values=(
            r.get('_target', '-'), r.get('_ip', '-'),
            r.get('国家', '-'), r.get('地区/省', '-'),
            r.get('城市', '-'), r.get('ISP/运营商', '-'),
            r.get('_source', '-'),
        ), tags=('ok',))
        self.batch_tree.tag_configure('ok', foreground='black')

    def _add_batch_row_error(self, target, err):
        self.batch_tree.insert('', tk.END, values=(
            target, '-', '失败', '-', '-', str(err)[:50], '-'
        ), tags=('err',))
        self.batch_tree.tag_configure('err', foreground='red')

    def _update_batch_progress(self, current, total):
        self.batch_progress['value'] = current
        self.status_label.config(text=f"批量查询中: {current}/{total}", foreground='blue')

    def _batch_done(self, success, fail):
        self.batch_btn.config(state=tk.NORMAL)
        self.status_label.config(text=f"批量完成: 成功 {success}, 失败 {fail}", foreground='green')
        messagebox.showinfo("批量完成", f"查询完成！\n成功: {success}\n失败: {fail}")

    def _add_history(self, result):
        entry = {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': result.get('_target', '-'),
            'ip': result.get('_ip', '-'),
            'country': result.get('国家', '-'),
            'city': result.get('城市', '-'),
            'isp': result.get('ISP/运营商', '-'),
        }
        self.history.insert(0, entry)
        if len(self.history) > 200: self.history = self.history[:200]
        self.history_tree.insert('', 0, values=(
            entry['time'], entry['target'], entry['ip'],
            entry['country'], entry['city'], entry['isp']
        ))

    def relookup_selected(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择一条历史记录")
            return
        item = self.history_tree.item(sel[0])
        target = str(item['values'][1])
        if '->' in target:
            target = target.split('->')[-1].strip()
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, target)
        self.inner_notebook.select(0)
        self.single_lookup()

    def clear_history(self):
        if messagebox.askyesno("确认", "确定要清空查询历史吗？"):
            for item in self.history_tree.get_children(): self.history_tree.delete(item)
            self.history = []

    def clear_single(self):
        self.ip_entry.delete(0, tk.END)
        for item in self.detail_tree.get_children(): self.detail_tree.delete(item)
        self.map_link_label.config(text="(查询后显示)")
        self.status_label.config(text="就绪", foreground='gray')

    def lookup_my_ip(self):
        if self.busy:
            messagebox.showinfo("提示", "正在查询中，请稍候")
            return
        self.busy = True
        self.status_label.config(text="正在获取公网IP...", foreground='blue')
        def _do():
            try:
                ip = self.get_my_public_ip()
                if not ip: raise RuntimeError("无法获取公网IP")
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, ip)
                self.frame.after(0, lambda: self.single_lookup())
            except Exception as e:
                self.frame.after(0, lambda: self._on_query_error(f"获取公网IP失败: {e}"))
            finally:
                self.frame.after(0, lambda: self._reset_busy())
        threading.Thread(target=_do, daemon=True).start()

    def lookup_local_ip(self):
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, self.local_ip)
        self.single_lookup()

    def open_map(self):
        url = self.map_link_label.cget('text')
        if url and url.startswith('http'):
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception as e:
                messagebox.showerror("错误", f"无法打开浏览器: {e}")
        else:
            messagebox.showinfo("提示", "当前查询结果无经纬度信息")

    def export_results(self):
        rows = []
        if self.inner_notebook.index('current') == 0:
            for item in self.detail_tree.get_children():
                vals = self.detail_tree.item(item)['values']
                rows.append(('单查详情', str(vals[0]), str(vals[1])))
        elif self.inner_notebook.index('current') == 1:
            for item in self.batch_tree.get_children():
                vals = self.batch_tree.item(item)['values']
                rows.append(('批量结果',) + tuple(str(v) for v in vals))
        else:
            for item in self.history_tree.get_children():
                vals = self.history_tree.item(item)['values']
                rows.append(('历史',) + tuple(str(v) for v in vals))
        if not rows:
            messagebox.showwarning("提示", "当前页面没有可导出的结果")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"ip_geolocation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not filename: return
        try:
            import csv
            with open(filename, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['来源', '时间/字段', '目标', 'IP', '国家', '地区', '城市', 'ISP'])
                for r in rows:
                    writer.writerow(list(r) + [''] * max(0, 8 - len(r)))
            messagebox.showinfo("导出成功", f"结果已保存到:\n{filename}")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出时发生错误:\n{e}")

    def copy_detail(self):
        if self.inner_notebook.index('current') == 0:
            lines = []
            for item in self.detail_tree.get_children():
                vals = self.detail_tree.item(item)['values']
                lines.append(f"{str(vals[0]):<15}: {vals[1]}")
            text = '\n'.join(lines)
        elif self.inner_notebook.index('current') == 1:
            lines = ['目标\tIP\t国家\t地区\t城市\tISP\t数据源']
            for item in self.batch_tree.get_children():
                vals = self.batch_tree.item(item)['values']
                lines.append('\t'.join(str(v) for v in vals))
            text = '\n'.join(lines)
        else:
            lines = ['时间\t目标\tIP\t国家\t城市\tISP']
            for item in self.history_tree.get_children():
                vals = self.history_tree.item(item)['values']
                lines.append('\t'.join(str(v) for v in vals))
            text = '\n'.join(lines)
        if not text:
            messagebox.showinfo("提示", "没有可复制的内容")
            return
        self.frame.clipboard_clear()
        self.frame.clipboard_append(text)
        messagebox.showinfo("复制成功", "内容已复制到剪贴板")

    def clear_all(self):
        if messagebox.askyesno("确认", "确定要清空所有结果吗？"):
            self.clear_single()
            for item in self.batch_tree.get_children(): self.batch_tree.delete(item)
            for item in self.history_tree.get_children(): self.history_tree.delete(item)
            self.history = []
            self.cache = {}
            self.status_label.config(text="已清空", foreground='gray')


class PortScannerGUI:
    def __init__(self, root, embedded=False, results_page=None):
        self.root = root
        self.embedded = embedded
        self.parent = root
        self.results_page = results_page
        if not embedded:
            self.root.title("NetKit - 网络工具箱")
            self.root.geometry("900x700")
            self.root.minsize(800, 600)
        self.style = ttk.Style()
        self.style.configure('TButton', font=('微软雅黑', 10))
        self.style.configure('TLabel', font=('微软雅黑', 10))
        self.style.configure('TEntry', font=('微软雅黑', 10))
        self.style.configure('Header.TLabel', font=('微软雅黑', 12, 'bold'))
        self.scanner = None
        self.batch_thread = None
        self.scanning = False
        self.results = {}
        self.ping_results = {}
        self.create_widgets()
        if not embedded: self.center_window()
    
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(7, weight=1)
        title_label = ttk.Label(main_frame, text="端口扫描工具 (批量扫描版)", style='Header.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        target_frame = ttk.LabelFrame(main_frame, text="目标设置", padding="10")
        target_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        target_frame.columnconfigure(1, weight=1)
        ttk.Label(target_frame, text="目标IP:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.target_entry.insert(0, "127.0.0.1")
        ttk.Button(target_frame, text="选择文件", command=self.load_ip_file).grid(row=0, column=2, padx=5)
        hint_label = ttk.Label(target_frame, text="支持格式: 单个IP | CIDR(192.168.1.0/24) | 范围(1.1.1.1-1.1.1.100) | 逗号分隔多个IP | 从文件导入", foreground="gray", font=('微软雅黑', 8))
        hint_label.grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=(5, 0))
        port_frame = ttk.LabelFrame(main_frame, text="端口设置", padding="10")
        port_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        self.port_mode_var = tk.StringVar(value="range")
        ttk.Radiobutton(port_frame, text="端口范围", variable=self.port_mode_var, value="range", command=self.update_port_ui).grid(row=0, column=0, padx=5)
        ttk.Radiobutton(port_frame, text="自定义端口", variable=self.port_mode_var, value="custom", command=self.update_port_ui).grid(row=0, column=1, padx=5)
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
        quick_btn_frame = ttk.Frame(self.range_frame)
        quick_btn_frame.pack(side=tk.LEFT, padx=10)
        ttk.Button(quick_btn_frame, text="常用端口", command=lambda: self.set_port_range(1, 1024), width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_btn_frame, text="Web端口", command=lambda: self.set_port_range(80, 8080), width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_btn_frame, text="全部端口", command=lambda: self.set_port_range(1, 65535), width=10).pack(side=tk.LEFT, padx=2)
        self.custom_frame = ttk.Frame(port_frame)
        self.custom_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        ttk.Label(self.custom_frame, text="端口列表 (用逗号分隔):").pack(side=tk.LEFT, padx=5)
        self.custom_ports_entry = ttk.Entry(self.custom_frame, width=50)
        self.custom_ports_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.custom_ports_entry.insert(0, "22,80,443,3306,5432,6379,8080")
        self.custom_frame.grid_remove()
        settings_frame = ttk.LabelFrame(main_frame, text="扫描设置", padding="10")
        settings_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        ttk.Label(settings_frame, text="速度模式:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.speed_mode_var = tk.StringVar(value="fast")
        speed_frame = ttk.Frame(settings_frame)
        speed_frame.grid(row=0, column=1, padx=5, sticky=tk.W, columnspan=2)
        ttk.Radiobutton(speed_frame, text="快速", variable=self.speed_mode_var, value="fast").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(speed_frame, text="普通", variable=self.speed_mode_var, value="normal").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(speed_frame, text="慢速", variable=self.speed_mode_var, value="slow").pack(side=tk.LEFT, padx=2)
        ttk.Label(settings_frame, text="线程数:").grid(row=0, column=3, padx=5)
        self.threads_entry = ttk.Entry(settings_frame, width=10)
        self.threads_entry.grid(row=0, column=4, padx=5)
        self.threads_entry.insert(0, "100")
        self.ping_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="先进行Ping扫描", variable=self.ping_var).grid(row=0, column=5, padx=10)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)
        self.start_btn = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="停止扫描", command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空结果", command=self.clear_results, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出结果", command=self.export_results, width=15).pack(side=tk.LEFT, padx=5)
        progress_frame = ttk.LabelFrame(main_frame, text="扫描进度", padding="5")
        progress_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        progress_frame.columnconfigure(0, weight=1)
        self.ip_progress_var = tk.DoubleVar()
        self.ip_progress_bar = ttk.Progressbar(progress_frame, variable=self.ip_progress_var, maximum=100, length=400, mode='determinate')
        self.ip_progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=2, padx=5)
        self.ip_status_label = ttk.Label(progress_frame, text="IP: 0/0")
        self.ip_status_label.grid(row=0, column=1, padx=5)
        self.port_progress_var = tk.DoubleVar()
        self.port_progress_bar = ttk.Progressbar(progress_frame, variable=self.port_progress_var, maximum=100, length=400, mode='determinate')
        self.port_progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=2, padx=5)
        self.port_status_label = ttk.Label(progress_frame, text="端口: 0/0")
        self.port_status_label.grid(row=1, column=1, padx=5)
        self.current_ip_label = ttk.Label(main_frame, text="当前扫描: -")
        self.current_ip_label.grid(row=6, column=0, columnspan=3, sticky=tk.W, pady=2, padx=5)
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="5")
        result_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=90, height=20, font=('Consolas', 10))
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        if not self.embedded: self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def load_ip_file(self):
        filename = filedialog.askopenfilename(title="选择IP列表文件", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, filename)
    
    def set_port_range(self, start, end):
        self.start_port_entry.delete(0, tk.END); self.start_port_entry.insert(0, str(start))
        self.end_port_entry.delete(0, tk.END); self.end_port_entry.insert(0, str(end))
    
    def update_port_ui(self):
        if self.port_mode_var.get() == "range":
            self.range_frame.grid()
            self.custom_frame.grid_remove()
        else:
            self.range_frame.grid_remove()
            self.custom_frame.grid()
    
    def log(self, message, tag=None):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.result_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        if tag: self.result_text.tag_config(tag, foreground=tag)
        self.result_text.see(tk.END)
    
    def update_ip_progress(self, current, total, current_ip): self.root.after(0, lambda: self._update_ip_progress_ui(current, total, current_ip))
    def _update_ip_progress_ui(self, current, total, current_ip):
        progress = (current / total) * 100 if total > 0 else 0
        self.ip_progress_var.set(progress)
        self.ip_status_label.config(text=f"IP: {current}/{total}")
        self.current_ip_label.config(text=f"当前扫描: {current_ip}")
    
    def update_port_progress(self, progress, scanned, total): self.root.after(0, lambda: self._update_port_progress_ui(progress, scanned, total))
    def _update_port_progress_ui(self, progress, scanned, total):
        self.port_progress_var.set(progress)
        self.port_status_label.config(text=f"端口: {scanned}/{total}")
    
    def add_result(self, ip, port, service): self.root.after(0, lambda: self._add_result_ui(ip, port, service))
    def _add_result_ui(self, ip, port, service):
        self.result_text.insert(tk.END, f"[+] {ip}:{port} 开放 - {service}\n", 'green')
        self.result_text.tag_config('green', foreground='green')
        self.result_text.see(tk.END)
    
    def scan_complete(self, results, duration): self.root.after(0, lambda: self._scan_complete_ui(results, duration))
    def _scan_complete_ui(self, results, duration):
        self.scanning = False
        self.ip_progress_var.set(100)
        self.port_progress_var.set(100)
        total_open = sum(len(ports) for ports in results.values())
        self.result_text.delete(1.0, tk.END)
        if total_open > 0:
            self.result_text.insert(tk.END, f"发现 {total_open} 个开放端口\n\n", 'bold')
            self.result_text.tag_config('bold', font=('Consolas', 11, 'bold'))
            for ip, ports in sorted(results.items()):
                if ports:
                    port_list = [str(port) for port, _ in sorted(ports)]
                    self.result_text.insert(tk.END, f"{ip}\n", 'ip')
                    self.result_text.insert(tk.END, f"   端口: {', '.join(port_list)}\n", 'ports')
                    self.result_text.tag_config('ip', font=('Consolas', 10, 'bold'))
                    self.result_text.tag_config('ports', foreground='green')
        else:
            self.result_text.insert(tk.END, "扫描完成，未发现开放端口\n", 'bold')
        self.result_text.insert(tk.END, f"\n{'=' * 40}\n")
        self.result_text.insert(tk.END, f"耗时: {duration:.2f} 秒 | IP数: {len(results)} | 端口: {total_open}")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.current_ip_label.config(text="当前扫描: -")
        if self.results_page: self.results_page.display_results(results, 'port', duration, self.ping_results)
        messagebox.showinfo("扫描完成", f"扫描完成！\n扫描IP数: {len(results)}\n发现开放端口: {total_open}\n耗时: {duration:.2f} 秒")
    
    def start_scan(self):
        ip_input = self.target_entry.get().strip()
        try: threads = int(self.threads_entry.get())
        except ValueError: messagebox.showerror("输入错误", "线程数必须是有效的数字！"); return
        if self.port_mode_var.get() == "range":
            try:
                start_port = int(self.start_port_entry.get())
                end_port = int(self.end_port_entry.get())
                custom_ports = None
            except ValueError: messagebox.showerror("输入错误", "端口范围必须是有效的数字！"); return
        else:
            start_port, end_port = 1, 1024
            custom_ports_str = self.custom_ports_entry.get().strip()
            if not custom_ports_str: messagebox.showerror("输入错误", "自定义端口不能为空！"); return
            try:
                custom_ports = [int(p.strip()) for p in custom_ports_str.split(',') if p.strip()]
                if not custom_ports: raise ValueError()
            except ValueError: messagebox.showerror("输入错误", "端口格式错误！请用逗号分隔数字，如: 22,80,443"); return
        if not ip_input: messagebox.showerror("输入错误", "请输入目标IP或选择文件！"); return
        ip_list = parse_ip_input(ip_input)
        if not ip_list: messagebox.showerror("输入错误", "没有解析到有效的IP地址！"); return
        if len(ip_list) > 10000:
            if not messagebox.askyesno("确认", f"将要扫描 {len(ip_list)} 个IP，数量较大，是否继续？"): return
        self.result_text.delete(1.0, tk.END)
        self.results = {}
        self.ping_results = {}
        self.scanning = True
        enable_ping = self.ping_var.get()
        speed_mode = self.speed_mode_var.get()
        self.log(f"批量扫描开始")
        self.log(f"目标数量: {len(ip_list)} 个IP")
        if self.port_mode_var.get() == "range": self.log(f"端口范围: {start_port} - {end_port}")
        else: self.log(f"自定义端口: {', '.join(map(str, custom_ports))}")
        self.log(f"速度模式: {speed_mode}")
        self.log(f"线程数: {threads}")
        self.log(f"Ping扫描: {'启用' if enable_ping else '禁用'}")
        self.log(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("-" * 60)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.batch_thread = threading.Thread(target=self._batch_scan, args=(ip_list, start_port, end_port, threads, custom_ports, enable_ping, speed_mode))
        self.batch_thread.daemon = True
        self.batch_thread.start()
    
    def _batch_scan(self, ip_list, start_port, end_port, threads, custom_ports=None, enable_ping=False, speed_mode='fast'):
        start_time = time.time()
        total_ips = len(ip_list)
        if enable_ping:
            self.log("\n[*] 开始Ping扫描...\n")
            alive_ips = []
            for idx, ip in enumerate(ip_list):
                if not self.scanning: break
                current_idx = idx + 1
                self.update_ip_progress(current_idx, total_ips, ip)
                self.current_ip_label.config(text=f"当前扫描: {ip} (Ping检测中...)")
                scanner = PortScanner(ip, start_port, end_port, threads)
                if scanner.ping_host():
                    alive_ips.append(ip)
                    self.ping_results[ip] = True
                    self.log(f"  [{ip}] - 主机在线 (Ping成功)")
                else:
                    self.ping_results[ip] = False
                    self.log(f"  [{ip}] - 主机离线 (Ping失败)")
            if not alive_ips:
                self.log("\n[!] 没有主机响应Ping，扫描结束")
                self.scan_complete({}, time.time() - start_time)
                return
            ip_list = alive_ips
            total_ips = len(alive_ips)
            self.log(f"\n[*] 发现 {total_ips} 个在线主机，开始端口扫描\n")
        for idx, ip in enumerate(ip_list):
            if not self.scanning: break
            current_idx = idx + 1
            self.update_ip_progress(current_idx, total_ips, ip)
            self.log(f"\n[{current_idx}/{total_ips}] 扫描: {ip}")
            scanner = PortScanner(ip, start_port, end_port, threads, progress_callback=self.update_port_progress, result_callback=self.add_result, custom_ports=custom_ports, speed_mode=speed_mode)
            open_ports = scanner.run()
            self.results[ip] = open_ports
            if open_ports: self.log(f"  发现 {len(open_ports)} 个开放端口")
            else: self.log(f"  无开放端口")
        duration = time.time() - start_time
        self.scan_complete(self.results, duration)
    
    def stop_scan(self):
        self.scanning = False
        self.log("扫描被用户停止", 'orange')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.current_ip_label.config(text="当前扫描: -")
    
    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.results = {}
        self.ping_results = {}
        self.ip_progress_var.set(0)
        self.port_progress_var.set(0)
        self.ip_status_label.config(text="IP: 0/0")
        self.port_status_label.config(text="端口: 0/0")
    
    def export_results(self):
        if not self.results: messagebox.showwarning("警告", "没有可导出的扫描结果！"); return
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"端口扫描报告\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n扫描IP数: {len(self.results)}\n")
                    if self.ping_results:
                        alive_count = sum(1 for v in self.ping_results.values() if v)
                        f.write(f"在线主机数: {alive_count}\n")
                    f.write("=" * 60 + "\n\n")
                    if self.ping_results:
                        f.write("【Ping扫描结果】\n")
                        for ip, is_alive in sorted(self.ping_results.items()):
                            f.write(f"  {ip}: {'在线' if is_alive else '离线'}\n")
                        f.write("\n")
                    f.write("【端口扫描结果】\n\n")
                    for ip, ports in sorted(self.results.items()):
                        f.write(f"[{ip}]\n")
                        if ports:
                            for port, service in sorted(ports): f.write(f"  {port}/tcp - {service}\n")
                        else: f.write("  无开放端口\n")
                        f.write("\n")
                self.log(f"结果已导出到: {filename}")
                messagebox.showinfo("导出成功", f"结果已保存到:\n{filename}")
            except Exception as e: messagebox.showerror("导出失败", f"导出时发生错误:\n{str(e)}")
    
    def on_closing(self):
        if not self.embedded:
            if self.scanning:
                if messagebox.askokcancel("确认", "扫描正在进行中，确定要退出吗？"):
                    self.scanning = False
                    self.root.destroy()
            else: self.root.destroy()


class MTRScanner:
    """MTR (My Traceroute) - 路由追踪与丢包率统计

    实现思路:
    1. 通过 tracert (Windows) / traceroute (Linux/Mac) 发现路径
    2. 对路径上每个节点使用 ping 命令进行多轮探测
    3. 使用 Welford 在线算法实时计算均值与标准差
    4. 如果系统安装了原生 mtr 命令 (Linux/Mac)，可使用原生模式
    """

    def __init__(self, target, max_hops=30, count=10, interval=1.0,
                 timeout=2.0, packet_size=64, probe_type='icmp', use_native=False,
                 progress_callback=None, hop_callback=None,
                 stats_callback=None, ping_callback=None,
                 status_callback=None, log_callback=None,
                 complete_callback=None):
        self.target = target
        self.max_hops = max_hops
        self.count = count
        self.interval = interval
        self.timeout = timeout
        self.packet_size = packet_size  # ICMP 包大小 (字节)
        self.probe_type = probe_type    # 'icmp' (默认) 或 'tcp' (TCP 探测)
        self.use_native = use_native
        self.progress_callback = progress_callback
        self.hop_callback = hop_callback
        self.stats_callback = stats_callback
        self.ping_callback = ping_callback  # 每包回调: (ttl, hop, rtt, is_lost)
        self.status_callback = status_callback
        self.log_callback = log_callback
        self.complete_callback = complete_callback
        self.running = False
        self.hops = {}
        self.target_ip = None
        self.system = platform.system()
        self.native_mtr = self._find_mtr() if self.system != 'Windows' else None
        self.traceroute_cmd = self._find_traceroute_cmd()
        self._asn_cache = {}  # AS 号查询缓存

    def _find_mtr(self):
        if self.system == 'Windows':
            return None
        try:
            result = subprocess.run(['which', 'mtr'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                path = result.stdout.strip().split('\n')[0].strip()
                if path:
                    return path
        except Exception:
            pass
        return None

    def _find_traceroute_cmd(self):
        if self.system == 'Windows':
            return 'tracert'
        for cmd in ['traceroute', 'tracepath']:
            try:
                result = subprocess.run(['which', cmd], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    path = result.stdout.strip().split('\n')[0].strip()
                    if path:
                        return cmd
            except Exception:
                continue
        return None

    def _log(self, msg, color=None):
        if self.log_callback:
            try:
                self.log_callback(msg, color)
            except Exception:
                pass

    def _status(self, msg):
        if self.status_callback:
            try:
                self.status_callback(msg)
            except Exception:
                pass

    def _resolve_target(self):
        try:
            self.target_ip = socket.gethostbyname(self.target)
            return True
        except Exception as e:
            self._log(f"无法解析目标 {self.target}: {e}", 'red')
            return False

    def _discover_path(self):
        """通过系统 tracert/traceroute 命令发现网络路径"""
        if not self.traceroute_cmd:
            self._log("未找到 tracert/traceroute 命令", 'red')
            return {}

        self._status("正在发现网络路径...")
        self._log(f"使用 {self.traceroute_cmd} 发现路径...", 'blue')

        try:
            if self.system == 'Windows':
                cmd = [self.traceroute_cmd, '-d', '-h', str(self.max_hops),
                       '-w', str(max(1, int(self.timeout * 1000))), self.target]
            else:
                cmd = [self.traceroute_cmd, '-n', '-m', str(self.max_hops),
                       '-w', str(max(1, int(self.timeout))), self.target]

            self._log(f"执行命令: {' '.join(cmd)}")

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding='utf-8', errors='ignore')
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                if not self.running:
                    process.terminate()
                    break
                line = line.rstrip()
                if line.strip():
                    self._log(f"  {line}", 'gray')
                    output_lines.append(line)
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.terminate()
            output = '\n'.join(output_lines)
            return self._parse_traceroute_output(output)
        except FileNotFoundError:
            self._log(f"未找到命令: {self.traceroute_cmd}", 'red')
            return {}
        except Exception as e:
            self._log(f"路径发现失败: {e}", 'red')
            return {}

    def _parse_traceroute_output(self, output):
        """解析 tracert/traceroute 输出，提取每一跳的 IP"""
        hops = {}
        for line in output.split('\n'):
            m = re.match(r'^\s*(\d+)\s+', line)
            if not m:
                continue
            ttl = int(m.group(1))
            if ttl <= 0 or ttl > self.max_hops:
                continue
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            # 校验 IP 合法性
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ttl in hops:
                continue
            hostname = ip
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            hops[ttl] = {
                'ip': ip, 'hostname': hostname,
                'times': [], 'sent': 0, 'lost': 0,
                'last': None, 'best': None, 'worst': None,
                'avg': None, 'stdev': None, 'm2': 0,
            }
        return hops

    def _ping_host(self, ip):
        """对单个主机执行一次 ping，返回延迟 (ms) 或 None"""
        try:
            # 按探测类型选择命令 (icmp: ping, tcp: TCP 连接 80/443)
            if self.probe_type == 'tcp':
                # TCP 探测: 用 socket.connect 模拟 (适合穿透 ICMP 封锁的网络)
                return self._tcp_probe(ip)
            # ICMP 探测 (默认)
            if self.system == 'Windows':
                cmd = ['ping', '-n', '1', '-l', str(max(8, min(65500, self.packet_size))),
                       '-w', str(max(1, int(self.timeout * 1000))), ip]
            else:
                cmd = ['ping', '-c', '1', '-s', str(max(8, min(65507, self.packet_size - 28))),
                       '-W', str(max(1, int(self.timeout))), ip]

            start = time.time()
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout + 2)
            elapsed_ms = (time.time() - start) * 1000

            if result.returncode == 0:
                output = result.stdout.decode('utf-8', errors='ignore')
                m = re.search(r'time[=<]([\d.]+)\s*ms', output)
                if m:
                    return float(m.group(1))
                return elapsed_ms
            return None
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    def _tcp_probe(self, ip):
        """TCP 探测 (像 mtr -T): 尝试连接常见端口, 用连接时间作为延迟"""
        # 尝试常用端口: 443 (HTTPS), 80 (HTTP), 22 (SSH)
        for tcp_port in (443, 80, 22):
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if sock.connect_ex((ip, tcp_port)) == 0:
                    elapsed = (time.time() - start) * 1000
                    sock.close()
                    return elapsed
                sock.close()
            except Exception:
                pass
        return None

    def _lookup_asn(self, ip):
        """使用 DNS 查询 (Team Cymru) 获取 IP 的 AS 号

        原理: 将 IP 倒序拼接 + .origin.asn.cymru.com 查询 TXT 记录
        范例: 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com -> "15169 | 8.8.8.0/24 | US | arin | ..."
        """
        if not ip or ip in self._asn_cache:
            return self._asn_cache.get(ip, '-')
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                self._asn_cache[ip] = '-'
                return '-'
            # 倒序: 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
            reversed_ip = '.'.join(reversed(parts))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            answers = socket.getaddrinfo(query, None, type=socket.SOCK_STREAM)
            # 实际上 Cymru 返回 TXT 记录, 尝试解析
            try:
                import subprocess as sp
                result = sp.run(['nslookup', '-type=txt', query, '8.8.8.8'],
                               capture_output=True, text=True, timeout=2)
                txt = result.stdout
                # 查找 "15169 | ..." 格式
                m = re.search(r'"(\d+)\s*\|', txt)
                if m:
                    asn = f"AS{m.group(1)}"
                    self._asn_cache[ip] = asn
                    return asn
            except Exception:
                pass
            # 回退: 使用 gethostbyname (有时会有提示)
            self._asn_cache[ip] = '-'
            return '-'
        except Exception:
            self._asn_cache[ip] = '-'
            return '-'

    def _run_native_mtr(self):
        """使用系统原生 mtr 命令 (Linux/Mac) 执行实时输出"""
        if not self.native_mtr:
            return False

        self._log(f"使用原生 mtr: {self.native_mtr}", 'blue')
        try:
            cmd = [self.native_mtr, '-n', '-r', '-c', str(self.count),
                   '-m', str(self.max_hops), '-i', str(self.interval), self.target]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding='utf-8', errors='ignore')
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                if not self.running:
                    process.terminate()
                    break
                line_s = line.rstrip()
                self._log(line_s, 'gray')
                output_lines.append(line_s)
            try:
                process.wait(timeout=self.timeout * self.max_hops + self.count * self.interval + 30)
            except subprocess.TimeoutExpired:
                process.terminate()
            # 解析原生输出以填充 hops
            self._parse_native_mtr_output('\n'.join(output_lines))
            return True
        except FileNotFoundError:
            self._log("找不到 mtr 命令", 'red')
            return False
        except Exception as e:
            self._log(f"原生 mtr 执行失败: {e}", 'red')
            return False

    def _parse_native_mtr_output(self, output):
        """解析原生 mtr --report 输出"""
        hops = {}
        for line in output.split('\n'):
            # 格式如: " 1. 192.168.1.1    0.0%   10   1.2  0.8  0.5  1.5   0.3"
            m = re.match(r'^\s*(\d+)\.\s+(\S+)\s+(\d+\.\d+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)', line)
            if m:
                ttl = int(m.group(1))
                ip = m.group(2)
                loss_pct = float(m.group(3))
                sent = int(m.group(4))
                last = float(m.group(5))
                avg = float(m.group(6))
                best = float(m.group(7))
                worst = float(m.group(8))
                stdev = float(m.group(9))
                lost = int(round(sent * loss_pct / 100))
                hostname = ip
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                hops[ttl] = {
                    'ip': ip, 'hostname': hostname,
                    'times': [last], 'sent': sent, 'lost': lost,
                    'last': last, 'best': best, 'worst': worst,
                    'avg': avg, 'stdev': stdev, 'm2': 0,
                }
                # 回调
                if self.hop_callback:
                    try:
                        self.hop_callback(ttl, hops[ttl])
                    except Exception:
                        pass
        self.hops = hops

    def _update_hop_stats(self, hop, rtt, is_lost=False):
        """使用 Welford 在线算法更新单跳统计 (含丢包模式)"""
        hop['times'].append(rtt)
        hop['last'] = rtt
        if hop['best'] is None or rtt < hop['best']:
            hop['best'] = rtt
        if hop['worst'] is None or rtt > hop['worst']:
            hop['worst'] = rtt
        n = len(hop['times'])
        if n == 1:
            hop['avg'] = rtt
            hop['m2'] = 0
            hop['stdev'] = 0.0
        else:
            delta = rtt - hop['avg']
            hop['avg'] += delta / n
            delta2 = rtt - hop['avg']
            hop['m2'] += delta * delta2
            if n > 1:
                hop['stdev'] = (hop['m2'] / (n - 1)) ** 0.5
        # 丢包模式: True=丢失, False=收到 (WinMTR 风格小图)
        if 'loss_history' not in hop:
            hop['loss_history'] = []
        hop['loss_history'].append(is_lost)
        # 限制最大长度 (避免内存无限增长)
        if len(hop['loss_history']) > 200:
            hop['loss_history'] = hop['loss_history'][-200:]

    def run(self):
        """执行 MTR：先发现路径，再逐跳统计"""
        self.running = True
        try:
            if not self._resolve_target():
                return {}

            self._log(f"MTR 报告 - 目标: {self.target} ({self.target_ip})", 'blue')
            self._log(f"参数: 最大跳数={self.max_hops}, 每跳ping数={self.count}, "
                      f"间隔={self.interval}秒, 超时={self.timeout}秒")
            self._log("=" * 80)

            # 优先尝试原生 mtr
            if self.use_native and self.native_mtr:
                if self._run_native_mtr():
                    self._status("MTR 完成")
                    return self.hops
                self._log("原生 mtr 失败，回退到标准模式", 'orange')

            # 标准模式
            self.hops = self._discover_path()

            if not self.hops:
                self._log("未能发现任何路由节点", 'red')
                return {}

            self._log(f"\n发现 {len(self.hops)} 个路由节点，开始统计...", 'blue')

            # 先把已知跳添加到 UI
            for ttl in sorted(self.hops.keys()):
                if self.hop_callback:
                    try:
                        self.hop_callback(ttl, self.hops[ttl])
                    except Exception:
                        pass

            # 多轮 ping - 并行 ping 所有跳 (极速实时模式)
            # 每一轮: 对所有跳同时发起 ping, 等待最慢的那个完成, 一次性更新所有跳的 loss%
            # 这才是真正 MTR 的工作方式 (而非逐跳串行)
            infinite = self.count <= 0
            max_rounds = self.count if not infinite else 1
            round_num = 0
            hop_ttls = sorted(self.hops.keys())
            while self.running:
                round_num += 1
                self._status(f"第 {round_num} 轮探测 (并行 {len(hop_ttls)} 跳)...")

                # 1) 同时给所有跳 +1 sent 计数
                for ttl in hop_ttls:
                    self.hops[ttl]['sent'] += 1

                # 2) 并行 ping 所有跳 (每个跳独立线程)
                ping_results = {}  # ttl -> (rtt_ms, is_lost)
                ping_threads = []

                def _do_one_ping(ttl):
                    if not self.running:
                        return
                    hop = self.hops[ttl]
                    # start 回调 (高亮当前正在 ping 的跳)
                    if self.ping_callback:
                        try:
                            self.ping_callback(ttl, hop, None, False, 'start')
                        except Exception:
                            pass
                    rtt = self._ping_host(hop['ip'])
                    ping_results[ttl] = (rtt, rtt is None)

                for ttl in hop_ttls:
                    if not self.running:
                        break
                    t = threading.Thread(target=_do_one_ping, args=(ttl,), daemon=True)
                    t.start()
                    ping_threads.append(t)
                # 等待所有 ping 完成 (取最慢的一个的耗时, 而非所有耗时之和)
                for t in ping_threads:
                    t.join(timeout=self.timeout + 3)

                # 3) 顺序更新每跳的统计并触发 done 回调 (loss% 此时已变化)
                for ttl in hop_ttls:
                    if ttl not in ping_results:
                        continue
                    hop = self.hops[ttl]
                    rtt, is_lost = ping_results[ttl]
                    if not is_lost:
                        self._update_hop_stats(hop, rtt, is_lost=False)
                    else:
                        hop['lost'] += 1
                        if 'loss_history' not in hop:
                            hop['loss_history'] = []
                        hop['loss_history'].append(True)
                        if len(hop['loss_history']) > 200:
                            hop['loss_history'] = hop['loss_history'][-200:]
                    # done 回调 - 此时 loss% 已真实变化
                    if self.ping_callback:
                        try:
                            self.ping_callback(ttl, hop, rtt, is_lost, 'done')
                        except Exception:
                            pass
                    if self.stats_callback:
                        try:
                            self.stats_callback(ttl, hop)
                        except Exception:
                            pass

                if self.progress_callback:
                    try:
                        if infinite:
                            self.progress_callback(round_num, 0)
                        else:
                            self.progress_callback(round_num, max_rounds)
                    except Exception:
                        pass

                if not infinite and round_num >= max_rounds:
                    break
                if self.running and self.interval > 0:
                    time.sleep(self.interval)

            self._log("\n" + "=" * 80, 'blue')
            self._log("MTR 完成", 'green')
            self._status("MTR 完成")
        except Exception as e:
            self._log(f"MTR 执行出错: {e}", 'red')
        finally:
            self.running = False
            if self.complete_callback:
                try:
                    self.complete_callback(self.hops)
                except Exception:
                    pass

        return self.hops

    def stop(self):
        self.running = False

    def get_summary_text(self):
        """生成格式化的 MTR 报告文本"""
        lines = []
        lines.append("=" * 100)
        lines.append("                     MTR (My Traceroute) 网络诊断报告")
        lines.append("=" * 100)
        lines.append(f"目标:        {self.target} ({self.target_ip})")
        lines.append(f"生成时间:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"参数:        最大跳数={self.max_hops}  每跳ping数={self.count if self.count > 0 else '无限'}  "
                     f"间隔={self.interval}秒  超时={self.timeout}秒")
        lines.append("")
        header = (f"{'Hop':<5} {'Host':<32} {'Loss%':>7} {'Sent':>5} "
                  f"{'Last':>9} {'Avg':>9} {'Best':>9} {'Wrst':>9} {'StDev':>9}")
        lines.append(header)
        lines.append("-" * 100)
        if not self.hops:
            lines.append("(无路由节点数据)")
        for ttl in sorted(self.hops.keys()):
            hop = self.hops[ttl]
            loss_pct = (hop['lost'] / hop['sent'] * 100) if hop['sent'] > 0 else 0.0
            hostname = hop['hostname']
            if len(hostname) > 30:
                hostname = hostname[:29] + '~'

            def fmt(v):
                return f"{v:>7.1f}ms" if v is not None else f"{'-':>9}"

            lines.append(
                f"{ttl:<5} {hostname:<32} {loss_pct:>6.1f}% {hop['sent']:>5} "
                f"{fmt(hop['last'])} {fmt(hop['avg'])} {fmt(hop['best'])} "
                f"{fmt(hop['worst'])} {fmt(hop['stdev'])}"
            )
        lines.append("=" * 100)
        return '\n'.join(lines)


class MTRScanGUI:
    """MTR 图形界面 - 路由追踪与丢包率统计"""

    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.scanner = None
        self.running = False
        self.root = None
        self.hop_items = {}  # ttl -> treeview item id
        self.active_hop = None  # 正在 ping 的跳数
        self.round_num = 0  # 当前轮数
        self.create_widgets()

    def set_root(self, root):
        self.root = root

    def create_widgets(self):
        # === 目标输入 ===
        input_frame = ttk.LabelFrame(self.frame, text="目标设置", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="目标 (IP/域名):", width=15).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_entry = ttk.Entry(input_frame, width=50, font=('Consolas', 10))
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.target_entry.insert(0, "8.8.8.8")
        self.target_entry.bind('<Return>', lambda e: self.start_mtr())

        # 快捷目标
        quick_frame = ttk.Frame(input_frame)
        quick_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(8, 0))
        ttk.Label(quick_frame, text="快捷目标:", foreground='gray').pack(side=tk.LEFT, padx=5)
        quick_targets = [
            ('Google DNS', '8.8.8.8'),
            ('Cloudflare', '1.1.1.1'),
            ('阿里DNS', '223.5.5.5'),
            ('114DNS', '114.114.114.114'),
            ('百度', 'baidu.com'),
            ('GitHub', 'github.com'),
            ('本机', '127.0.0.1'),
        ]
        for name, target in quick_targets:
            ttk.Button(quick_frame, text=name,
                       command=lambda t=target: self._set_target(t),
                       width=10).pack(side=tk.LEFT, padx=2)

        # === 参数设置 ===
        settings_frame = ttk.LabelFrame(self.frame, text="MTR 参数", padding="10")
        settings_frame.pack(fill=tk.X, pady=5)

        ttk.Label(settings_frame, text="最大跳数:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.max_hops_var = tk.StringVar(value="30")
        ttk.Spinbox(settings_frame, from_=1, to=64, width=10,
                    textvariable=self.max_hops_var).grid(row=0, column=1, padx=5)

        ttk.Label(settings_frame, text="每跳ping数:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.count_var = tk.StringVar(value="10")
        ttk.Spinbox(settings_frame, from_=0, to=1000, width=10,
                    textvariable=self.count_var).grid(row=0, column=3, padx=5)
        ttk.Label(settings_frame, text="(0 表示无限循环)", foreground='gray',
                  font=('微软雅黑', 8)).grid(row=0, column=4, sticky=tk.W, padx=5)

        ttk.Label(settings_frame, text="间隔 (秒):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.interval_var = tk.StringVar(value="1")
        ttk.Spinbox(settings_frame, from_=0.1, to=60, increment=0.5, width=10,
                    textvariable=self.interval_var).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(settings_frame, text="超时 (秒):").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.timeout_var = tk.StringVar(value="2")
        ttk.Spinbox(settings_frame, from_=0.5, to=30, increment=0.5, width=10,
                    textvariable=self.timeout_var).grid(row=1, column=3, padx=5, pady=5)

        # 命令预览
        cmd_frame = ttk.Frame(settings_frame)
        cmd_frame.grid(row=2, column=0, columnspan=5, sticky=tk.W, pady=(5, 0))
        ttk.Label(cmd_frame, text="命令预览:", foreground='gray').pack(side=tk.LEFT, padx=5)
        self.cmd_preview = ttk.Label(cmd_frame, text="tracert -d -h 30 -w 2000 8.8.8.8",
                                     font=('Consolas', 9), foreground='blue')
        self.cmd_preview.pack(side=tk.LEFT, padx=5)
        for var in [self.target_entry, self.max_hops_var, self.count_var,
                    self.interval_var, self.timeout_var]:
            pass
        # 绑定更新
        for var in [self.max_hops_var, self.interval_var, self.timeout_var]:
            var.trace_add('write', lambda *args: self._update_cmd_preview())
        self.target_entry.bind('<KeyRelease>', lambda e: self._update_cmd_preview())
        self._update_cmd_preview()

        # === 操作按钮 ===
        btn_frame = ttk.Frame(self.frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.start_btn = ttk.Button(btn_frame, text="▶ 开始 MTR", command=self.start_mtr, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="■ 停止", command=self.stop_mtr,
                                   width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空结果", command=self.clear_results,
                   width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出报告", command=self.export_results,
                   width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制表格", command=self.copy_results,
                   width=15).pack(side=tk.LEFT, padx=5)

        # === 进度条 ===
        progress_frame = ttk.Frame(self.frame)
        progress_frame.pack(fill=tk.X, pady=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                            maximum=100, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.status_label = ttk.Label(progress_frame, text="就绪", font=('Consolas', 9))
        self.status_label.pack(side=tk.LEFT, padx=5)

        # === 结果表格 ===
        result_frame = ttk.LabelFrame(self.frame, text="MTR 实时结果  (丢包率>=50%红色, >=10%橙色, >0%黄色)",
                                      padding="5")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)

        columns = ('hop', 'host', 'ip', 'loss', 'sent', 'last', 'avg', 'best', 'wrst', 'stdev')
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show='headings', height=15)
        col_config = [
            ('hop', '跳数', 60, tk.CENTER),
            ('host', '主机名', 220, tk.W),
            ('ip', 'IP 地址', 130, tk.W),
            ('loss', 'Loss%', 80, tk.CENTER),
            ('sent', 'Sent', 60, tk.CENTER),
            ('last', 'Last', 80, tk.CENTER),
            ('avg', 'Avg', 80, tk.CENTER),
            ('best', 'Best', 80, tk.CENTER),
            ('wrst', 'Wrst', 80, tk.CENTER),
            ('stdev', 'StDev', 80, tk.CENTER),
        ]
        for col, text, width, anchor in col_config:
            self.result_tree.heading(col, text=text)
            self.result_tree.column(col, width=width, anchor=anchor)

        tree_scroll_y = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=tree_scroll_y.set)
        self.result_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll_y.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # 颜色标签
        self.result_tree.tag_configure('high_loss', foreground='red')
        self.result_tree.tag_configure('med_loss', foreground='#FF8C00')
        self.result_tree.tag_configure('low_loss', foreground='#DAA520')
        self.result_tree.tag_configure('target', foreground='green')
        self.result_tree.tag_configure('normal', foreground='black')
        # 活动跳: 蓝色加粗背景
        try:
            self.result_tree.tag_configure('active_hop', background='#E3F2FD', foreground='#1565C0')
            self.result_tree.tag_configure('active_loss', background='#FFEBEE', foreground='red')
        except Exception:
            pass
        # 高亮表头提示
        style = ttk.Style()
        try:
            style.configure('Active.Horizontal.TScale', background='#1565C0')
        except Exception:
            pass

        # === 日志区域 ===
        log_frame = ttk.LabelFrame(self.frame, text="日志", padding="5")
        log_frame.pack(fill=tk.X, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=('Consolas', 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.X)
        for color in ['red', 'green', 'blue', 'orange', 'gray']:
            self.log_text.tag_configure(color, foreground=color)

    def _set_target(self, target):
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, target)
        self._update_cmd_preview()

    def _update_cmd_preview(self):
        target = self.target_entry.get().strip() or "TARGET"
        try:
            max_hops = self.max_hops_var.get()
            timeout = self.timeout_var.get()
        except Exception:
            max_hops, timeout = "30", "2"
        if platform.system() == 'Windows':
            try:
                t_ms = str(max(1, int(float(timeout) * 1000)))
            except Exception:
                t_ms = "2000"
            cmd = f"tracert -d -h {max_hops} -w {t_ms} {target}"
        else:
            cmd = f"traceroute -n -m {max_hops} -w {timeout} {target}"
        self.cmd_preview.config(text=cmd)

    # ---- 回调辅助 ----
    def _safe_after(self, fn, *args):
        if self.root:
            try:
                self.root.after(0, lambda: fn(*args))
            except Exception:
                pass
        else:
            try:
                fn(*args)
            except Exception:
                pass

    def log(self, msg, color=None):
        self._safe_after(self._log_ui, msg, color)

    def _log_ui(self, msg, color):
        self.log_text.insert(tk.END, msg + "\n", color if color else '')
        self.log_text.see(tk.END)

    def status(self, msg):
        self._safe_after(self.status_label.config, text=msg)

    # ---- 控制 ----
    def start_mtr(self):
        if self.running:
            messagebox.showinfo("提示", "MTR 正在运行中，请先停止")
            return

        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("输入错误", "请输入目标 IP 或域名")
            return

        try:
            max_hops = int(self.max_hops_var.get())
            count = int(self.count_var.get())
            interval = float(self.interval_var.get())
            timeout = float(self.timeout_var.get())
            if max_hops <= 0 or count < 0 or interval <= 0 or timeout <= 0:
                raise ValueError()
        except (ValueError, tk.TclError):
            messagebox.showerror("输入错误", "参数必须是有效的正整数")
            return

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_var.set(0)

        self.round_num = 0
        self.active_hop = None

        self.scanner = MTRScanner(
            target=target, max_hops=max_hops, count=count,
            interval=interval, timeout=timeout,
            hop_callback=self._on_hop_discovered,
            stats_callback=self._on_stats_updated,
            ping_callback=self._on_ping,  # 每包实时回调
            progress_callback=self._on_progress,
            status_callback=self.status,
            log_callback=self.log,
        )

        self.log_text.insert(tk.END, f"\n{'=' * 60}\n")
        self.log_text.insert(tk.END, f"开始 MTR: 目标={target}\n")
        self.log_text.insert(tk.END, f"{'=' * 60}\n")
        # 详细模式: 记录每包
        self._packet_log_enabled = True

        thread = threading.Thread(target=self._run_mtr, daemon=True)
        thread.start()

    def _run_mtr(self):
        try:
            self.scanner.run()
        except Exception as e:
            self.log(f"MTR 执行出错: {e}", 'red')
        finally:
            self._safe_after(self._scan_complete)

    def _on_hop_discovered(self, ttl, hop):
        self._safe_after(self._add_or_update_hop_row, ttl, hop)

    def _on_stats_updated(self, ttl, hop):
        self._safe_after(self._add_or_update_hop_row, ttl, hop)

    def _on_ping(self, ttl, hop, rtt, is_lost, phase):
        """每包实时回调: start=开始 ping, done=ping 结束 (结果已更新)
        用于高亮当前正在 ping 的跳, 并记录每包详情。
        """
        def _ui():
            # 显示状态: 当前正在 ping 的跳
            if phase == 'start':
                self.active_hop = ttl
                if self.running and self.scanner:
                    sent = hop.get('sent', 0)
                    self.status_label.config(
                        text=f"第 {sent} 包 → 正在 ping 跳 {ttl} ({hop.get('ip', '-')})"
                    )
                return
            # phase == 'done' - 此包已完成, loss% 已变化
            # 重置 active_hop 后清高亮 (依赖 _add_or_update_hop_row 设置的 tags)
            if self.active_hop == ttl:
                self.active_hop = None
            # 日志: 记录每包结果
            if getattr(self, '_packet_log_enabled', False):
                loss_pct = (hop['lost'] / hop['sent'] * 100) if hop['sent'] > 0 else 0.0
                ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                if is_lost:
                    self.log_text.insert(tk.END,
                        f"  [{ts}] 跳 {ttl} ({hop.get('ip', '-')}) 丢包  → Loss {loss_pct:.1f}%\n",
                        'red')
                else:
                    self.log_text.insert(tk.END,
                        f"  [{ts}] 跳 {ttl} ({hop.get('ip', '-')}) {rtt:.1f}ms  → Loss {loss_pct:.1f}%\n",
                        'green')
                self.log_text.see(tk.END)
        self._safe_after(_ui)

    def _add_or_update_hop_row(self, ttl, hop):
        # 计算丢包率
        loss_pct = (hop['lost'] / hop['sent'] * 100) if hop['sent'] > 0 else 0.0

        hostname = hop['hostname']
        if len(hostname) > 40:
            hostname = hostname[:39] + '~'

        def fmt(v):
            return f"{v:.1f}" if v is not None else '-'

        values = (
            str(ttl), hostname, hop['ip'],
            f"{loss_pct:.1f}%", str(hop['sent']),
            fmt(hop['last']), fmt(hop['avg']),
            fmt(hop['best']), fmt(hop['worst']),
            fmt(hop['stdev'])
        )

        # 颜色标签 (基于丢包率)
        tags = []
        try:
            target_ip = self.scanner.target_ip if self.scanner else None
        except Exception:
            target_ip = None
        if target_ip and hop['ip'] == target_ip:
            tags.append('target')
        elif loss_pct >= 50:
            tags.append('high_loss')
        elif loss_pct >= 10:
            tags.append('med_loss')
        elif loss_pct > 0:
            tags.append('low_loss')
        else:
            tags.append('normal')

        # 高亮当前正在 ping 的跳
        if self.active_hop == ttl:
            tags = [t for t in tags if t != 'normal']
            tags.append('active_hop')
        if getattr(self, '_flash_loss', None) == ttl:
            tags = [t for t in tags if t != 'normal']
            tags.append('active_loss')

        if ttl in self.hop_items:
            self.result_tree.item(self.hop_items[ttl], values=values, tags=tags)
        else:
            item_id = self.result_tree.insert('', tk.END, values=values, tags=tags)
            self.hop_items[ttl] = item_id

    def _on_progress(self, current, total):
        def _update():
            if total and total > 0:
                self.progress_var.set(current / total * 100)
            else:
                # 无限模式：周期性滚动
                self.progress_var.set((current % 100))
        self._safe_after(_update)

    def _scan_complete(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set(100)
        if self.status_label.cget('text') == '就绪':
            self.status_label.config(text="已完成")

    def stop_mtr(self):
        if self.scanner:
            self.scanner.stop()
        self.log("[用户停止] MTR 已停止", 'orange')
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="已停止")

    def clear_results(self):
        if self.running:
            if not messagebox.askyesno("确认", "MTR 正在运行，确定要清空吗？"):
                return
            self.stop_mtr()
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        self.hop_items = {}
        self.log_text.delete('1.0', tk.END)
        self.progress_var.set(0)
        self.active_hop = None
        self.round_num = 0
        self.status_label.config(text="就绪")

    def export_results(self):
        if not self.scanner or not self.scanner.hops:
            messagebox.showwarning("警告", "没有可导出的 MTR 结果！")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"mtr_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.scanner.get_summary_text())
                    f.write("\n\n---------- 运行日志 ----------\n")
                    f.write(self.log_text.get('1.0', tk.END))
                messagebox.showinfo("导出成功", f"报告已保存到:\n{filename}")
            except Exception as e:
                messagebox.showerror("导出失败", f"导出时发生错误:\n{e}")

    def copy_results(self):
        if not self.scanner or not self.scanner.hops:
            messagebox.showwarning("警告", "没有可复制的结果！")
            return
        text = self.scanner.get_summary_text()
        try:
            self.frame.clipboard_clear()
            self.frame.clipboard_append(text)
            messagebox.showinfo("复制成功", "结果已复制到剪贴板")
        except Exception as e:
            messagebox.showerror("复制失败", f"复制时发生错误:\n{e}")


def main():
    root = tk.Tk()
    root.title("NetKit - 网络工具箱")
    root.geometry("1400x950")
    root.minsize(1300, 850)
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    results_frame = ttk.Frame(notebook)
    notebook.add(results_frame, text="扫描结果")
    results_app = ScanResultsGUI(results_frame)
    scanner_frame = ttk.Frame(notebook)
    notebook.add(scanner_frame, text="端口扫描")
    nmap_frame = ttk.Frame(notebook)
    notebook.add(nmap_frame, text="Nmap扫描")
    mtr_frame = ttk.Frame(notebook)
    notebook.add(mtr_frame, text="MTR路由追踪")
    subnet_frame = ttk.Frame(notebook)
    notebook.add(subnet_frame, text="子网掩码计算")
    ipgeo_frame = ttk.Frame(notebook)
    notebook.add(ipgeo_frame, text="IP归属地查询")
    scanner_app = PortScannerGUI(scanner_frame, embedded=True, results_page=results_app)
    nmap_app = NmapScanGUI(nmap_frame)
    nmap_app.set_root(root)
    mtr_app = MTRScanGUI(mtr_frame)
    mtr_app.set_root(root)
    subnet_app = SubnetCalculatorGUI(subnet_frame)
    ipgeo_app = IPGeolocationGUI(ipgeo_frame)
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    root.mainloop()


if __name__ == "__main__":
    main()
