#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nmap封装模块 - 提供nmap-like扫描功能
支持原生python-nmap库（如果已安装），否则使用socket实现
"""

import socket
import subprocess
import platform
import threading
import re
from queue import Queue
from datetime import datetime


class NmapScanner:
    """nmap风格扫描器"""
    
    # 扫描类型常量
    SCAN_TYPES = {
        '-sS': 'TCP SYN扫描',
        '-sT': 'TCP Connect扫描',
        '-sU': 'UDP扫描',
        '-sN': 'TCP Null扫描',
        '-sF': 'TCP FIN扫描',
        '-sX': 'TCP Xmas扫描',
        '-sP': 'Ping扫描',
        '-sV': '版本检测',
        '-O': '操作系统检测',
        '-A': '综合扫描'
    }
    
    def __init__(self, nmap_path=None):
        """初始化nmap扫描器"""
        self.nmap_path = nmap_path or self._find_nmap()
        self.use_native = self.nmap_path is not None
        self.results = {}
    
    def _find_nmap(self):
        """查找系统中的nmap路径"""
        try:
            result = subprocess.run(['where', 'nmap'], 
                                 capture_output=True, 
                                 text=True,
                                 timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines:
                    return lines[0].strip()
        except:
            pass
        return None
    
    def scan(self, hosts, ports='1-1024', arguments='-sS -sV -O'):
        """执行扫描"""
        if self.use_native:
            return self._native_scan(hosts, ports, arguments)
        else:
            return self._socket_scan(hosts, ports, arguments)
    
    def _native_scan(self, hosts, ports, arguments):
        """使用原生nmap进行扫描"""
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=hosts, ports=ports, arguments=arguments)
            
            results = {}
            for host in nm.all_hosts():
                results[host] = {
                    'status': nm[host].state(),
                    'protocols': {}
                }
                
                for proto in nm[host].all_protocols():
                    results[host]['protocols'][proto] = {}
                    ports_list = nm[host][proto].keys()
                    for port in ports_list:
                        port_info = nm[host][proto][port]
                        results[host]['protocols'][proto][port] = {
                            'state': port_info.get('state', ''),
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
            
            self.results = results
            return results
        except ImportError:
            return self._socket_scan(hosts, ports, arguments)
        except Exception as e:
            print(f"nmap扫描错误: {e}")
            return self._socket_scan(hosts, ports, arguments)
    
    def _socket_scan(self, hosts, ports, arguments):
        """使用socket实现类似nmap的扫描功能"""
        results = {}
        
        # 解析hosts
        if isinstance(hosts, str):
            host_list = self._parse_hosts(hosts)
        else:
            host_list = hosts if isinstance(hosts, list) else [hosts]
        
        # 解析ports
        port_list = self._parse_ports(ports)
        
        for host in host_list:
            results[host] = {
                'status': 'unknown',
                'protocols': {'tcp': {}}
            }
            
            # Ping检测
            if '-sP' in arguments or '-sn' in arguments:
                if self._ping_host(host):
                    results[host]['status'] = 'up'
                else:
                    results[host]['status'] = 'down'
                    continue
            else:
                results[host]['status'] = 'up'
            
            # TCP扫描
            if '-sS' in arguments or '-sT' in arguments or '-sS' not in arguments:
                for port in port_list:
                    state = self._scan_tcp_port(host, port)
                    if state == 'open':
                        service = self._get_service_name(port)
                        results[host]['protocols']['tcp'][port] = {
                            'state': 'open',
                            'service': service,
                            'version': '',
                            'extrainfo': ''
                        }
        
        self.results = results
        return results
    
    def _parse_hosts(self, hosts_str):
        """解析hosts字符串"""
        host_list = []
        
        # CIDR格式
        if '/' in hosts_str:
            import ipaddress
            try:
                network = ipaddress.ip_network(hosts_str, strict=False)
                host_list = [str(ip) for ip in network.hosts()]
            except:
                host_list = [hosts_str]
        # 范围格式
        elif '-' in hosts_str and not ':' in hosts_str:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)-(\d+)', hosts_str)
            if match:
                base_ip = '.'.join(match.group(1).split('.')[:-1])
                start = int(match.group(1).split('.')[-1])
                end = int(match.group(2))
                for i in range(start, min(end + 1, 256)):
                    host_list.append(f"{base_ip}.{i}")
            else:
                host_list = [hosts_str]
        # 单个IP或主机名
        else:
            host_list = [hosts_str]
        
        return host_list
    
    def _parse_ports(self, ports_str):
        """解析ports字符串"""
        port_list = []
        
        # 常用端口别名
        aliases = {
            'top100': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443],
            'top1000': list(range(1, 1001)),
            'all': list(range(1, 65536)),
            'common': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080]
        }
        
        if ports_str in aliases:
            return aliases[ports_str]
        
        # 范围格式
        if '-' in ports_str:
            parts = ports_str.split('-')
            if len(parts) == 2:
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    port_list = list(range(start, min(end + 1, 65536)))
                except:
                    port_list = [80]  # 默认
            else:
                port_list = [int(ports_str)]
        # 逗号分隔
        elif ',' in ports_str:
            for p in ports_str.split(','):
                try:
                    port_list.append(int(p.strip()))
                except:
                    pass
        # 单个端口
        else:
            try:
                port_list = [int(ports_str)]
            except:
                port_list = [80]
        
        return port_list
    
    def _ping_host(self, host):
        """Ping检测主机"""
        try:
            param = '-n' if platform.system() == 'Windows' else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-w', '1000', host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False
    
    def _scan_tcp_port(self, host, port, timeout=1.0):
        """扫描TCP端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return 'open'
            else:
                return 'filtered'
        except:
            return 'closed'
    
    def _get_service_name(self, port):
        """获取服务名称"""
        services = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp',
            69: 'tftp', 80: 'http', 110: 'pop3', 119: 'nntp',
            123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm',
            139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 162: 'snmptrap',
            389: 'ldap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps',
            514: 'syslog', 515: 'printer', 587: 'submission', 636: 'ldaps',
            993: 'imaps', 995: 'pop3s', 1080: 'socks', 1433: 'mssql',
            1434: 'mssql-m', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            5985: 'winrm', 5986: 'winrm-ssl', 6379: 'redis', 8080: 'http-proxy',
            8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb'
        }
        return services.get(port, 'unknown')
    
    def command_line(self, hosts, ports, arguments):
        """返回nmap命令行"""
        if self.use_native:
            return f"nmap -v {arguments} -p {ports} {hosts}"
        else:
            return f"[模拟] nmap {arguments} -p {ports} {hosts}"
    
    def get_nmap_output(self):
        """获取格式化输出"""
        output_lines = []
        
        for host, data in self.results.items():
            output_lines.append(f"Nmap scan report for {host}")
            output_lines.append(f"Host is {data['status']}.")
            output_lines.append("")
            
            if 'tcp' in data['protocols']:
                output_lines.append("PORT      STATE    SERVICE")
                for port, info in sorted(data['protocols']['tcp'].items()):
                    state = info['state']
                    service = info['service']
                    output_lines.append(f"{port}/tcp    {state:8} {service}")
            
            output_lines.append("")
        
        return "\n".join(output_lines)


class NmapParallelScanner:
    """并行nmap风格扫描器"""
    
    def __init__(self, threads=50):
        self.threads = threads
        self.queue = Queue()
        self.results = {}
        self.lock = threading.Lock()
        self.running = False
        
        # 常见服务
        self.services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy',
            1433: 'MSSQL', 1521: 'Oracle', 27017: 'MongoDB',
            9200: 'Elasticsearch', 11211: 'Memcached'
        }
    
    def scan(self, target, ports='1-1024'):
        """执行并行扫描"""
        self.running = True
        self.results = {}
        
        # 解析ports
        if isinstance(ports, str):
            port_list = self._parse_ports(ports)
        else:
            port_list = ports if isinstance(ports, list) else [ports]
        
        # 填充队列
        for port in port_list:
            self.queue.put(port)
        
        # 创建工作线程
        threads = []
        for _ in range(min(self.threads, len(port_list))):
            t = threading.Thread(target=self._worker, args=(target,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 等待完成
        self.queue.join()
        self.running = False
        
        return self.results
    
    def _parse_ports(self, ports_str):
        """解析ports字符串"""
        port_list = []
        
        if '-' in ports_str:
            parts = ports_str.split('-')
            if len(parts) == 2:
                start = int(parts[0])
                end = int(parts[1])
                port_list = list(range(start, min(end + 1, 65536)))
        elif ',' in ports_str:
            for p in ports_str.split(','):
                try:
                    port_list.append(int(p.strip()))
                except:
                    pass
        else:
            try:
                port_list = [int(ports_str)]
            except:
                port_list = list(range(1, 1025))
        
        return port_list
    
    def _worker(self, target):
        """工作线程"""
        while self.running and not self.queue.empty():
            try:
                port = self.queue.get(timeout=0.5)
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        with self.lock:
                            self.results[port] = {
                                'state': 'open',
                                'service': self.services.get(port, 'unknown'),
                                'version': ''
                            }
                except:
                    pass
                
                self.queue.task_done()
            except:
                break
    
    def get_formatted_output(self, target):
        """获取格式化输出"""
        output = []
        output.append(f"Nmap scan report for {target}")
        output.append(f"Host is up.")
        output.append("")
        output.append("PORT      STATE    SERVICE")
        
        for port, info in sorted(self.results.items()):
            output.append(f"{port}/tcp    {info['state']:8} {info['service']}")
        
        output.append("")
        output.append(f"Read from raw sockets: {len(self.results)} ports scanned")
        
        return "\n".join(output)


# 快速使用示例
def quick_scan(target, ports='1-1024', use_nmap=True):
    """快速扫描函数"""
    if use_nmap:
        scanner = NmapScanner()
        results = scanner.scan(target, ports)
        print(scanner.get_nmap_output())
    else:
        scanner = NmapParallelScanner(threads=50)
        results = scanner.scan(target, ports)
        print(scanner.get_formatted_output(target))


# 测试代码
if __name__ == "__main__":
    print("=" * 60)
    print("Nmap风格扫描器测试")
    print("=" * 60)
    
    # 测试单端口
    print("\n[1] 测试单端口扫描 (localhost:80)")
    scanner = NmapScanner()
    results = scanner.scan('127.0.0.1', '80')
    print(scanner.get_nmap_output())
    
    # 测试多端口
    print("\n[2] 测试常见端口扫描 (localhost)")
    scanner = NmapParallelScanner(threads=20)
    results = scanner.scan('127.0.0.1', '80,443,22,3389')
    print(scanner.get_formatted_output('127.0.0.1'))
    
    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)