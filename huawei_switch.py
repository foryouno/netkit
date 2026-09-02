#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
华为交换机批量管理模块
功能:
    1. 批量保存(save) - 通过SSH/Telnet执行 save 保存配置
    2. 批量检查(check) - 检查版本/运行时长/CPU/内存等
依赖:
    - paramiko (首选, SSH)
    - telnetlib (标准库, Telnet)
"""

import socket
import time
import re
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ---------- 依赖检查 ----------
try:
    import paramiko  # type: ignore
    _HAS_PARAMIKO = True
except ImportError:
    _HAS_PARAMIKO = False

try:
    import telnetlib  # type: ignore
    _HAS_TELNETLIB = True
except ImportError:
    _HAS_TELNETLIB = False


def _has_paramiko():
    return _HAS_PARAMIKO


def _has_telnetlib():
    return _HAS_TELNETLIB


# ---------- 默认提示符模式 (华为 VRP 系列) ----------
_HUAWEI_PROMPTS = [
    rb'<[^\r\n<>]*>',         # 用户视图 <HUAWEI>
    rb'\[[^\r\n\[\]]*\]',     # 系统视图 [HUAWEI]
    rb'\w+#\s*$',
    rb'\w+>\s*$',
]


class SwitchConnectionError(Exception):
    pass


class _BaseConnection:
    """通用连接基类"""

    def __init__(self, host, port, username, password, timeout=10.0,
                 enable_password=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.timeout = timeout
        self._closed = False

    def _send(self, data: bytes):
        raise NotImplementedError

    def _recv_until(self, patterns, timeout=None) -> bytes:
        raise NotImplementedError

    def close(self):
        self._closed = True

    def send_line(self, line):
        if isinstance(line, str):
            line = line.encode('utf-8')
        self._send(line + b'\n')

    def recv_until_prompt(self, timeout=None) -> bytes:
        return self._recv_until(_HUAWEI_PROMPTS, timeout=timeout)

    def run_command(self, command, timeout=15.0) -> str:
        """执行单条命令并返回输出（去掉首尾空白）"""
        self.send_line(command)
        data = self.recv_until_prompt(timeout=timeout)
        text = data.decode('utf-8', errors='ignore')
        lines = text.splitlines()
        cleaned = []
        for ln in lines:
            s = ln.strip()
            if not s:
                continue
            if s == command.strip():
                continue
            cleaned.append(s)
        return '\n'.join(cleaned).strip()

    def login(self):
        raise NotImplementedError


# =====================================================================
# Paramiko (SSH) 实现
# =====================================================================
class _ParamikoSSHConnection(_BaseConnection):
    """基于 paramiko 的 SSH 连接"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = None
        self.shell = None

    def _send(self, data: bytes):
        if self.shell is None:
            raise SwitchConnectionError("SSH shell 未建立")
        self.shell.send(data)

    def _recv_until(self, patterns, timeout=None) -> bytes:
        if self.shell is None:
            raise SwitchConnectionError("SSH shell 未建立")
        if timeout is None:
            timeout = self.timeout
        import select
        buf = b''
        end_time = time.time() + timeout
        compiled = [re.compile(p) for p in patterns]
        while time.time() < end_time:
            if self.shell.closed:
                break
            r, _, _ = select.select([self.shell], [], [], 0.3)
            if self.shell in r:
                try:
                    chunk = self.shell.recv(65535)
                except Exception:
                    chunk = b''
                if not chunk:
                    break
                buf += chunk
                for cre in compiled:
                    if cre.search(buf):
                        return buf
        return buf

    def login(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            self.shell = self.client.invoke_shell(term='vt100', width=200, height=50)
            self.shell.settimeout(self.timeout)
            time.sleep(0.5)
            data = self.recv_until_prompt(timeout=self.timeout)
            text = data.decode('utf-8', errors='ignore').lower()
            # 极少数情况下第一次连接会再次提示输入密码
            if 'password' in text and 'username' not in text:
                self.send_line(self.password)
                time.sleep(0.5)
                self.recv_until_prompt(timeout=self.timeout)
            return True
        except Exception as e:
            self.close()
            raise SwitchConnectionError(f"SSH 登录失败: {e}")

    def close(self):
        try:
            if self.shell is not None:
                self.shell.close()
        except Exception:
            pass
        try:
            if self.client is not None:
                self.client.close()
        except Exception:
            pass
        self.shell = None
        self.client = None
        super().close()


# =====================================================================
# Telnet 实现 (基于标准库 telnetlib)
# =====================================================================
class _TelnetConnection(_BaseConnection):
    """基于 telnetlib 的 Telnet 连接"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tn = None

    def _send(self, data: bytes):
        if self.tn is None:
            raise SwitchConnectionError("Telnet 未建立")
        self.tn.write(data)

    def _recv_until(self, patterns, timeout=None) -> bytes:
        if self.tn is None:
            raise SwitchConnectionError("Telnet 未建立")
        if timeout is None:
            timeout = self.timeout
        compiled = [re.compile(p) for p in patterns]
        buf = b''
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                chunk = self.tn.read_very_eager()
                if chunk:
                    buf += chunk
                for cre in compiled:
                    if cre.search(buf):
                        return buf
                time.sleep(0.1)
            except EOFError:
                break
        return buf

    def login(self):
        try:
            self.tn = telnetlib.Telnet(self.host, self.port, timeout=self.timeout)
            time.sleep(0.3)
            data = self.tn.read_very_eager().decode('utf-8', errors='ignore')
            ldata = data.lower()
            if 'username' in ldata or 'login' in ldata:
                self.tn.write(self.username.encode('utf-8') + b'\n')
                time.sleep(0.3)
            # 等待 Password 提示
            try:
                self.tn.read_until(b'assword', timeout=self.timeout)
            except Exception:
                pass
            self.tn.write(self.password.encode('utf-8') + b'\n')
            time.sleep(0.5)
            self.recv_until_prompt(timeout=self.timeout)
            return True
        except Exception as e:
            self.close()
            raise SwitchConnectionError(f"Telnet 登录失败: {e}")

    def close(self):
        try:
            if self.tn is not None:
                self.tn.close()
        except Exception:
            pass
        self.tn = None
        super().close()


# =====================================================================
# 工厂函数: 根据协议返回对应连接
# =====================================================================
def create_connection(protocol, host, port, username, password,
                     timeout=10.0, enable_password=None):
    """根据 protocol ('ssh' 或 'telnet') 创建对应的连接对象"""
    protocol = (protocol or 'ssh').lower()
    if protocol == 'ssh':
        if not _HAS_PARAMIKO:
            raise SwitchConnectionError(
                "未安装 paramiko，无法使用 SSH 模式。"
                "请执行: pip install paramiko  或切换到 Telnet 模式"
            )
        return _ParamikoSSHConnection(
            host=host, port=port, username=username, password=password,
            timeout=timeout, enable_password=enable_password,
        )
    elif protocol == 'telnet':
        if not _HAS_TELNETLIB:
            raise SwitchConnectionError("当前 Python 环境缺少 telnetlib 模块")
        return _TelnetConnection(
            host=host, port=port, username=username, password=password,
            timeout=timeout, enable_password=enable_password,
        )
    else:
        raise SwitchConnectionError(f"不支持的协议: {protocol}")


# =====================================================================
# 解析辅助函数
# =====================================================================
def _extract_version(text):
    """从 display version 输出中提取 VRP 版本号"""
    patterns = [
        r'VRP\s*\(?R?\)?\s*software,\s*Version\s*([\w.\(\)\- ]+?)(?:\n|$)',
        r'Version\s*([Vv]?\d[\w.]+)',
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m.group(1).strip()
    for line in text.splitlines():
        s = line.strip()
        if s:
            return s[:80]
    return '-'


def _extract_uptime(text):
    """从 display version 输出中提取运行时长"""
    patterns = [
        r'(?:uptime|运行时间)[^\n:：]*[:：]\s*([^\n]+)',
        # 匹配 "32 weeks, 4 days, 3 hours, 50 minutes"
        r'(\d+\s+weeks?,\s*\d+\s+days?,\s*\d+\s+hours?,\s*\d+\s+minutes?)',
        # 匹配 "30 days, 2 hours, 15 minutes"
        r'(\d+\s+days?,\s*\d+\s+hours?,\s*\d+\s+minutes?)',
        # 匹配 "30 days 2 hours 15 minutes" (无逗号)
        r'(\d+\s+days?\s+\d+\s+hours?\s+\d+\s+minutes?)',
        # 匹配 "30 days"
        r'(\d+\s+days?)',
        # 中文
        r'(\d+\s+天\s*\d+\s+小时\s*\d+\s+分)',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return '-'


def _extract_cpu(text):
    """从 display cpu-usage 输出中提取 CPU 使用率"""
    patterns = [
        r'CPU\s*utilization[^\n]*?five\s*seconds[^\n]*?(\d{1,3})\s*%',
        r'CPU[^\n]*?(\d{1,3})\s*%',
        r'CPU利用率[^\n]*?(\d{1,3})\s*%',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return f"{m.group(1)}%"
    return '-'


def _extract_memory(text):
    """从 display memory-usage 输出中提取内存使用率"""
    patterns = [
        r'Memory Using Percentage Is:\s*(\d{1,3})\s*%',
        r'Memory\s*utilization[^\n]*?(\d{1,3})\s*%',
        r'内存利用率[^\n]*?(\d{1,3})\s*%',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return f"{m.group(1)}%"
    return '-'


# =====================================================================
# 业务类: 华为交换机批量操作
# =====================================================================
class HuaweiSwitchManager:
    """
    封装单台华为交换机的常用操作:
        - check(): 检查版本 / 运行时长 / CPU 等
        - save():  保存配置
    """

    SAVE_CMD_SEQUENCE = ['save', 'y']

    def __init__(self, host, username='admin', password='admin@123',
                 port=22, protocol='ssh', timeout=10.0, enable_password=None):
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port)
        self.protocol = protocol
        self.timeout = timeout
        self.enable_password = enable_password
        self.conn = None

    def _connect(self):
        if self.conn is not None:
            return
        self.conn = create_connection(
            protocol=self.protocol,
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            enable_password=self.enable_password,
        )
        self.conn.login()

    def disconnect(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def check(self):
        """
        检查交换机基本信息
        返回 dict:
            {
                'host': ..., 'port': ..., 'protocol': ...,
                'reachable': True/False,
                'version': 'VRP V200R...',
                'uptime':  '30 days, 2 hours...',
                'cpu':     '7%',
                'memory':  '32%',
                'elapsed': 5.2,   # 耗时(秒)
                'detail':  完整输出文本,
                'error':   错误信息(成功时为空),
            }
        """
        result = {
            'host': self.host, 'port': self.port, 'protocol': self.protocol,
            'reachable': False,
            'version': '-', 'uptime': '-',
            'cpu': '-', 'memory': '-',
            'elapsed': 0.0,
            'detail': '', 'error': '',
        }
        start_time = time.time()
        try:
            self._connect()
            result['reachable'] = True
            version_text = self.conn.run_command('display version', timeout=20)
            result['version'] = _extract_version(version_text)
            result['uptime'] = _extract_uptime(version_text)
            cpu_text = self.conn.run_command('display cpu-usage', timeout=10)
            result['cpu'] = _extract_cpu(cpu_text)
            mem_text = self.conn.run_command('display memory-usage', timeout=10)
            result['memory'] = _extract_memory(mem_text)
            detail_lines = [
                f"=== {self.host} 检查结果 ===",
                f"协议: {self.protocol.upper()}  端口: {self.port}",
                f"VRP 版本: {result['version']}",
                f"运行时长: {result['uptime']}",
                f"CPU 使用率: {result['cpu']}",
                f"内存使用率: {result['memory']}",
                '',
                '--- display version ---',
                version_text,
                '--- display cpu-usage ---',
                cpu_text,
                '--- display memory-usage ---',
                mem_text,
            ]
            result['detail'] = '\n'.join(detail_lines)
        except SwitchConnectionError as e:
            result['error'] = str(e)
        except Exception as e:
            result['error'] = f"未知错误: {e}"
        finally:
            result['elapsed'] = round(time.time() - start_time, 2)
            self.disconnect()
        return result

    def save(self):
        """
        保存交换机配置
        返回 dict:
            {
                'host': ..., 'port': ..., 'protocol': ...,
                'success': True/False,
                'elapsed': 5.2,           # 耗时(秒)
                'output': '...命令输出...',
                'error': '',
            }
        """
        result = {
            'host': self.host, 'port': self.port, 'protocol': self.protocol,
            'success': False, 'elapsed': 0.0,
            'output': '', 'error': '',
        }
        start_time = time.time()
        try:
            self._connect()
            outputs = []
            for cmd in self.SAVE_CMD_SEQUENCE:
                out = self.conn.run_command(cmd, timeout=20)
                outputs.append(f">>> {cmd}\n{out}\n")
            result['output'] = '\n'.join(outputs)
            result['success'] = True
        except SwitchConnectionError as e:
            result['error'] = str(e)
        except Exception as e:
            result['error'] = f"未知错误: {e}"
        finally:
            result['elapsed'] = round(time.time() - start_time, 2)
            self.disconnect()
        return result


# =====================================================================
# 批量任务调度器
# =====================================================================
class BatchTaskRunner:
    """
    使用线程池并发处理多台交换机的 check / save 任务
    通过回调函数把进度和最终结果送回 GUI 线程
    """

    def __init__(self, hosts, operation, username, password,
                 port=22, protocol='ssh', timeout=10.0,
                 enable_password=None, max_workers=5,
                 progress_cb=None, log_cb=None, done_cb=None):
        """
        :param hosts:        list[str]  交换机 IP 列表
        :param operation:    'check' 或 'save'
        :param progress_cb:  callable(done_count, total_count, result_dict)
        :param log_cb:       callable(msg)  实时日志回调
        :param done_cb:      callable(results: list) 全部完成回调
        """
        self.hosts = hosts
        self.operation = operation
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.timeout = timeout
        self.enable_password = enable_password
        self.max_workers = max(1, int(max_workers))

        self.progress_cb = progress_cb or (lambda *a, **k: None)
        self.log_cb = log_cb or (lambda msg: None)
        self.done_cb = done_cb or (lambda results: None)

        self._stop_flag = False
        self._results = []
        self._lock = threading.Lock()
        self._done_count = 0
        self._worker_thread = None

    def stop(self):
        self._stop_flag = True

    def _worker(self, host):
        if self._stop_flag:
            return
        mgr = HuaweiSwitchManager(
            host=host,
            username=self.username,
            password=self.password,
            port=self.port,
            protocol=self.protocol,
            timeout=self.timeout,
            enable_password=self.enable_password,
        )
        ts = datetime.now().strftime('%H:%M:%S')
        self.log_cb(f"[{ts}] [{self.operation.upper()}] 开始处理: {host}")
        try:
            if self.operation == 'check':
                result = mgr.check()
            elif self.operation == 'save':
                result = mgr.save()
            else:
                result = {'host': host, 'error': f'未知操作: {self.operation}'}
        except Exception as e:
            result = {
                'host': host, 'port': self.port, 'protocol': self.protocol,
                'error': f'执行异常: {e}',
                'success': False, 'reachable': False,
                'version': '-', 'uptime': '-',
                'cpu': '-', 'memory': '-',
                'detail': '', 'output': '',
            }
        with self._lock:
            self._results.append(result)
            self._done_count += 1
            done = self._done_count
        self.progress_cb(done, len(self.hosts), result)
        status = '成功' if result.get('success') or result.get('reachable') else '失败'
        err = result.get('error', '')
        ts2 = datetime.now().strftime('%H:%M:%S')
        if err:
            self.log_cb(f"[{ts2}] {host} {status} - {err}")
        else:
            self.log_cb(f"[{ts2}] {host} {status}")

    def start(self):
        """启动批量任务(非阻塞)"""
        self._stop_flag = False
        self._results = []
        self._done_count = 0

        executor = ThreadPoolExecutor(max_workers=self.max_workers)

        def _submit_all():
            try:
                futures = []
                for host in self.hosts:
                    if self._stop_flag:
                        break
                    f = executor.submit(self._worker, host)
                    futures.append(f)
                for f in futures:
                    try:
                        f.result()
                    except Exception:
                        pass
            finally:
                executor.shutdown(wait=True)
                try:
                    self.done_cb(self._results)
                except Exception:
                    pass

        self._worker_thread = threading.Thread(target=_submit_all, daemon=True)
        self._worker_thread.start()


# =====================================================================
# 自检 / 单元测试
# =====================================================================
if __name__ == '__main__':
    print("=" * 60)
    print("Huawei Switch 模块自检")
    print("=" * 60)
    print(f"paramiko 可用: {_has_paramiko()}")
    print(f"telnetlib 可用: {_has_telnetlib()}")
    print()
    # 测试解析函数
    sample = """VRP (R) software, Version 8.180 (S5735-S V200R022C10)
Copyright (C) 2000-2020 Huawei Technologies Co., Ltd.
HUAWEI S5735-S uptime is 30 days, 2 hours, 15 minutes
"""
    print("[extract_version]", _extract_version(sample))
    print("[extract_uptime]", _extract_uptime(sample))

    sample_cpu = """CPU utilization for five seconds: 7%; one minute: 8%; five minutes: 8%"""
    print("[extract_cpu]", _extract_cpu(sample_cpu))

    sample_mem = """System Total Memory Is: 1024 Mbytes
Total Memory Used Is:    320 Mbytes
Memory Using Percentage Is: 31%"""
    print("[extract_memory]", _extract_memory(sample_mem))
    print("自检完成")