#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mihomo Smart Proxy Manager
支持多种订阅格式的 Mihomo 代理管理面板
"""

import os
import sys
import re
import json
import base64
import time
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from collections import OrderedDict
import ipaddress

# ============== 配置 ==============
WORKDIR = Path("/etc/mihomo-smart")
PROXY_FILE = WORKDIR / "proxies.txt"
PROXY_YAML = WORKDIR / "proxies.yaml"
ACTIVE = WORKDIR / "active.txt"
CONFIG = WORKDIR / "config.yaml"
AUTH_FILE = WORKDIR / "auth.txt"
MODE_FILE = WORKDIR / "mode.txt"
SUB_URLS_FILE = WORKDIR / "sub_urls.txt"
SUB_DEFAULT_FILE = WORKDIR / "sub_default.txt"
WHITELIST_FILE = WORKDIR / "whitelist.txt"

HTTP_PORT = 18080
SOCKS_PORT = 18081
TEST_URL = os.getenv("TEST_URL", "http://api.ipify.org")
TEST_URL_HTTPS = os.getenv("TEST_URL_HTTPS", "https://api.ipify.org")
LATENCY_TIMEOUT = float(os.getenv("LATENCY_TIMEOUT", "3"))

# ============== 颜色输出 ==============
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    BLUE = '\033[34m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    CYAN = '\033[36m'

    @classmethod
    def disable(cls):
        cls.RESET = cls.BOLD = cls.BLUE = cls.GREEN = ''
        cls.YELLOW = cls.RED = cls.CYAN = ''

if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
    Colors.disable()

def c_print(msg: str, color: str = Colors.RESET):
    print(f"{color}{msg}{Colors.RESET}")

def line():
    c_print("-" * 55, Colors.GREEN)

def msg_info(msg: str):
    c_print(f"  {msg}", Colors.GREEN)

def msg_warn(msg: str):
    c_print(f"  {msg}", Colors.YELLOW)

def msg_err(msg: str):
    c_print(f"  {msg}", Colors.RED)

def msg_title(msg: str):
    c_print(f"  {msg}", Colors.BOLD)

# ============== Logo ==============
def logo():
    os.system('clear')
    print()
    c_print("███╗   ███╗██╗██╗  ██╗ ██████╗ ███╗   ███╗ ██████╗", Colors.CYAN)
    c_print("████╗ ████║██║██║  ██║██╔═══██╗████╗ ████║██╔═══██╗", Colors.CYAN)
    c_print("██╔████╔██║██║███████║██║   ██║██╔████╔██║██║   ██║", Colors.CYAN)
    c_print("██║╚██╔╝██║██║██╔══██║██║   ██║██║╚██╔╝██║██║   ██║", Colors.CYAN)
    c_print("██║ ╚═╝ ██║██║██║  ██║╚██████╔╝██║ ╚═╝ ██║╚██████╔╝", Colors.CYAN)
    c_print("╚═╝     ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝", Colors.CYAN)
    print()
    c_print("        MIHOMO 智能订阅代理管理面板 (Python版)", Colors.BOLD)
    line()
    print()

# ============== 工具函数 ==============
def rand_str(length: int = 12) -> str:
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_auth() -> Tuple[str, str]:
    if AUTH_FILE.exists():
        content = AUTH_FILE.read_text().strip()
        if ':' in content:
            user, pwd = content.split(':', 1)
            return user, pwd
    user = rand_str()
    pwd = rand_str()
    AUTH_FILE.write_text(f"{user}:{pwd}")
    return user, pwd

USER, PASS = get_auth()

def get_public_ip() -> str:
    try:
        ip = subprocess.check_output(
            ["curl", "-4", "-s", "--max-time", "6", "ip.sb"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        return ip if ip else "未获取到 IPv4"
    except:
        return "未获取到 IPv4"

# ============== YAML 解析与转换 ==============
class YAMLConverter:
    """YAML 格式转换器"""

    @staticmethod
    def normalize(content: str) -> str:
        """标准化 YAML 内容"""
        if content.startswith('\ufeff'):
            content = content[1:]
        content = content.replace('\r\n', '\n').replace('\r', '\n')

        def convert_inline(match):
            indent = len(match.group(1))
            items = match.group(2)
            lines = [" " * (indent + 2) + item.strip() for item in items.split(",")]
            return " " * indent + "-\n" + "\n".join(lines)

        content = re.sub(r'^(\s*)-\s*\{([^}]+)\}', convert_inline, content, flags=re.MULTILINE)
        return content

    @staticmethod
    def parse_proxies(content: str) -> List[Dict[str, Any]]:
        """解析 proxies 块"""
        proxies = []
        in_proxies = False
        base_indent = 0
        current_proxy = None

        def parse_scalar(val: str) -> Any:
            s = val.strip()
            lower = s.lower()
            if lower == "true":
                return True
            if lower == "false":
                return False
            if re.fullmatch(r"-?\d+", s):
                try:
                    return int(s)
                except Exception:
                    return s
            return s

        lines = content.split('\n')
        for line in lines:
            if not in_proxies:
                if re.match(r'^\s*proxies\s*:\s*$', line):
                    in_proxies = True
                    m = re.match(r'^(\s*)proxies\s*:\s*$', line)
                    base_indent = len(m.group(1)) if m else 0
                continue

            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if not stripped or (indent <= base_indent and not stripped.startswith('-')):
                if current_proxy:
                    proxies.append(current_proxy)
                    current_proxy = None
                if indent < base_indent:
                    break
                continue

            if stripped.startswith('-'):
                if current_proxy:
                    proxies.append(current_proxy)
                current_proxy = {}
                rest = stripped[1:].strip()
                if rest and ':' in rest:
                    key, val = rest.split(':', 1)
                    key = key.strip()
                    val = val.strip()
                    if val.startswith('"') and '"' in val[1:]:
                        val = val[1:val.index('"', 1)]
                    elif val.startswith("'") and "'" in val[1:]:
                        val = val[1:val.index("'", 1)]
                    else:
                        val = re.split(r'[},#]', val)[0].strip()
                    if key and val:
                        current_proxy[key] = val
                continue

            if current_proxy is not None and ':' in stripped:
                parts = stripped.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip()
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    elif val.startswith("'") and val.endswith("'"):
                        val = val[1:-1]
                    current_proxy[key] = parse_scalar(val)

        if current_proxy:
            proxies.append(current_proxy)

        return proxies

    @staticmethod
    def extract_proxies_block(content: str) -> str:
        lines = content.splitlines()
        out: List[str] = []
        in_block = False
        base_indent = None

        for line in lines:
            if not in_block:
                m = re.match(r'^(\s*)proxies\s*:\s*$', line)
                if m:
                    in_block = True
                    base_indent = len(m.group(1))
                    out.append(line.rstrip())
                continue
            if line.strip() == "":
                out.append(line.rstrip())
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= (base_indent or 0) and not line.lstrip().startswith('-'):
                break
            out.append(line.rstrip())

        return "\n".join(out).strip()

    @staticmethod
    def extract_proxy_names(content: str) -> List[str]:
        names = []
        seen = set()
        for line in content.split('\n'):
            m = re.search(r'\bname\s*:\s*', line)
            if not m:
                continue
            s = line[m.end():].strip()
            name = ""
            if s.startswith('"') and '"' in s[1:]:
                name = s[1:s.index('"', 1)]
            elif s.startswith("'") and "'" in s[1:]:
                name = s[1:s.index("'", 1)]
            else:
                name = re.split(r'[},#]', s)[0].strip()
                if ',' in name:
                    name = name.split(',')[0].strip()
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        return names

    @staticmethod
    def b64_decode(data: bytes) -> Optional[bytes]:
        try:
            data = b"".join(data.split())
            data = data.replace(b"-", b"+").replace(b"_", b"/")
            data += b"=" * (-len(data) % 4)
            return base64.b64decode(data, validate=False)
        except:
            return None

# ============== 节点列表解析 ==============
class NodeListConverter:
    """节点列表（v2rayN）转换器"""

    SCHEMES = ("vless://", "vmess://", "ss://")

    @staticmethod
    def is_node_list(content: str) -> bool:
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith(NodeListConverter.SCHEMES):
                return True
        return False

    @staticmethod
    def _b64decode(s: str) -> bytes:
        s = s.strip().replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s)

    @staticmethod
    def _parse_hostport(hp: str) -> Optional[Tuple[str, int]]:
        if hp.startswith("[") and "]" in hp:
            host = hp[1:hp.index("]")]
            rest = hp[hp.index("]") + 1:]
            if rest.startswith(":"):
                rest = rest[1:]
            port = int(rest) if rest else None
            return (host, port) if port else None
        if hp.count(":") == 1:
            host, port = hp.split(":", 1)
            return host, int(port)
        u = urllib.parse.urlsplit("ss://" + hp)
        if u.hostname and u.port:
            return u.hostname, int(u.port)
        return None

    @staticmethod
    def _ensure_name(name: str, fallback: str, used: set) -> str:
        name = (name or "").strip() or fallback
        base = name
        idx = 2
        while name in used:
            name = f"{base}-{idx}"
            idx += 1
        used.add(name)
        return name

    @staticmethod
    def _parse_vmess(line: str) -> Optional[OrderedDict]:
        raw = line[8:]
        try:
            data = NodeListConverter._b64decode(raw)
            js = json.loads(data.decode("utf-8", errors="ignore"))
        except Exception:
            return None
        server = js.get("add") or ""
        port = js.get("port")
        uuid = js.get("id") or ""
        if not server or not port or not uuid:
            return None
        p = OrderedDict()
        p["name"] = js.get("ps") or ""
        p["type"] = "vmess"
        p["server"] = server
        try:
            p["port"] = int(port)
        except Exception:
            return None
        p["uuid"] = uuid
        aid = js.get("aid", 0)
        try:
            p["alterId"] = int(aid)
        except Exception:
            p["alterId"] = 0
        p["cipher"] = js.get("scy") or js.get("cipher") or "auto"
        p["udp"] = True
        net = (js.get("net") or "tcp").lower()
        if net and net != "tcp":
            p["network"] = net
        tls = (js.get("tls") or "").lower()
        if tls in ("tls", "1", "true"):
            p["tls"] = True
        sni = js.get("sni") or ""
        if sni:
            p["servername"] = sni
        alpn = js.get("alpn") or ""
        if alpn:
            p["alpn"] = [x.strip() for x in str(alpn).split(",") if x.strip()]
        fp = js.get("fp") or ""
        if fp:
            p["fingerprint"] = fp
        host = js.get("host") or ""
        path = js.get("path") or ""
        if net == "ws":
            ws_opts = OrderedDict()
            if path:
                ws_opts["path"] = path
            headers = OrderedDict()
            if host:
                headers["Host"] = host
            if headers:
                ws_opts["headers"] = headers
            if ws_opts:
                p["ws-opts"] = ws_opts
        if net == "grpc":
            grpc_opts = OrderedDict()
            svc = js.get("serviceName") or path
            if svc:
                grpc_opts["grpc-service-name"] = svc
            if grpc_opts:
                p["grpc-opts"] = grpc_opts
        return p

    @staticmethod
    def _parse_vless(line: str) -> Optional[OrderedDict]:
        try:
            u = urllib.parse.urlsplit(line)
        except Exception:
            return None
        if not u.hostname or not u.port or not u.username:
            return None
        params = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        def q(key: str) -> str:
            return params.get(key, [""])[0]
        p = OrderedDict()
        p["name"] = urllib.parse.unquote(u.fragment or "")
        p["type"] = "vless"
        p["server"] = u.hostname
        p["port"] = int(u.port)
        p["uuid"] = u.username
        p["udp"] = True
        enc = q("encryption") or "none"
        p["encryption"] = enc
        flow = q("flow")
        if flow:
            p["flow"] = flow
        net = (q("type") or q("transport") or "tcp").lower()
        if net and net != "tcp":
            p["network"] = net
        if net == "ws":
            ws_opts = OrderedDict()
            path = q("path")
            if path:
                ws_opts["path"] = path
            host = q("host")
            headers = OrderedDict()
            if host:
                headers["Host"] = host
            if headers:
                ws_opts["headers"] = headers
            if ws_opts:
                p["ws-opts"] = ws_opts
        if net == "grpc":
            grpc_opts = OrderedDict()
            svc = q("serviceName") or q("service") or q("grpc-service-name")
            if svc:
                grpc_opts["grpc-service-name"] = svc
            if grpc_opts:
                p["grpc-opts"] = grpc_opts
        sec = (q("security") or "").lower()
        if sec in ("tls", "reality", "xtls"):
            p["tls"] = True
            sni = q("sni") or q("serverName") or q("servername")
            if sni:
                p["servername"] = sni
            alpn = q("alpn")
            if alpn:
                p["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
            fp = q("fp")
            if fp:
                p["fingerprint"] = fp
            if sec == "reality":
                ropts = OrderedDict()
                pbk = q("pbk") or q("publicKey") or q("public-key")
                sid = q("sid") or q("shortId") or q("short-id")
                if pbk:
                    ropts["public-key"] = pbk
                if sid:
                    ropts["short-id"] = sid
                if ropts:
                    p["reality-opts"] = ropts
        return p

    @staticmethod
    def _parse_ss(line: str) -> Optional[OrderedDict]:
        rest = line[5:]
        name = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
            name = urllib.parse.unquote(frag)
        plugin = ""
        if "?" in rest:
            rest, query = rest.split("?", 1)
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            plugin = params.get("plugin", [""])[0]
        method = password = None
        hostport = ""
        if "@" in rest:
            userinfo, hostport = rest.rsplit("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                try:
                    decoded = NodeListConverter._b64decode(userinfo).decode("utf-8", errors="ignore")
                    if ":" in decoded:
                        method, password = decoded.split(":", 1)
                    else:
                        return None
                except Exception:
                    return None
        else:
            try:
                decoded = NodeListConverter._b64decode(rest).decode("utf-8", errors="ignore")
            except Exception:
                return None
            if "@" not in decoded or ":" not in decoded:
                return None
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
        hp = NodeListConverter._parse_hostport(hostport)
        if not hp or not method:
            return None
        host, port = hp
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password or "")
        p = OrderedDict()
        p["name"] = name
        p["type"] = "ss"
        p["server"] = host
        p["port"] = int(port)
        p["cipher"] = method
        p["password"] = password
        p["udp"] = True
        if plugin:
            plugin = urllib.parse.unquote(plugin)
            parts = plugin.split(";")
            pname = parts[0]
            opts_raw = parts[1:]
            opts = OrderedDict()
            for item in opts_raw:
                if not item:
                    continue
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
                else:
                    opts[item] = True
            if pname in ("simple-obfs", "obfs-local"):
                pname = "obfs"
            if pname in ("v2ray", "v2ray-plugin"):
                pname = "v2ray-plugin"
            p["plugin"] = pname
            if pname == "obfs":
                opts2 = OrderedDict()
                if "obfs" in opts:
                    opts2["mode"] = opts["obfs"]
                if "mode" in opts:
                    opts2["mode"] = opts["mode"]
                if "obfs-host" in opts:
                    opts2["host"] = opts["obfs-host"]
                if "host" in opts:
                    opts2["host"] = opts["host"]
                if opts2:
                    p["plugin-opts"] = opts2
            elif pname == "v2ray-plugin":
                opts2 = OrderedDict()
                if "mode" in opts:
                    opts2["mode"] = opts["mode"]
                if "host" in opts:
                    opts2["host"] = opts["host"]
                if "path" in opts:
                    opts2["path"] = opts["path"]
                if "tls" in opts:
                    opts2["tls"] = True
                if opts2:
                    p["plugin-opts"] = opts2
            else:
                if opts:
                    p["plugin-opts"] = opts
        return p

    @staticmethod
    def parse_nodes(content: str) -> List[Dict[str, Any]]:
        proxies: List[Dict[str, Any]] = []
        used_names = set()
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            p = None
            if s.startswith("vmess://"):
                p = NodeListConverter._parse_vmess(s)
            elif s.startswith("vless://"):
                p = NodeListConverter._parse_vless(s)
            elif s.startswith("ss://"):
                p = NodeListConverter._parse_ss(s)
            if not p:
                continue
            fallback = f"{p.get('type', 'node')}-{p.get('server', '')}:{p.get('port', '')}"
            p["name"] = NodeListConverter._ensure_name(p.get("name") or "", fallback, used_names)
            proxies.append(p)
        return proxies

# ============== 订阅管理 ==============
class SubscriptionManager:
    """订阅管理器"""

    def __init__(self):
        self.workdir = WORKDIR
        self.workdir.mkdir(parents=True, exist_ok=True)

    def fetch(self, url: str, ua: str = "Mihomo") -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': ua, 'Accept-Encoding': 'gzip, deflate'}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
                if resp.info().get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                return data.decode('utf-8', errors='ignore')
        except Exception as e:
            return None

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        content = None

        for ua in ["Mihomo", "Clash", "Clash for Windows", "clash.meta", "Mozilla/5.0"]:
            content = self.fetch(url, ua)
            if content:
                break

        if not content:
            return None

        content = YAMLConverter.normalize(content)

        def build_result_from_yaml(text: str) -> Optional[Dict[str, Any]]:
            if 'proxies:' not in text:
                return None
            proxies_yaml = YAMLConverter.extract_proxies_block(text)
            if not proxies_yaml:
                return None
            names = YAMLConverter.extract_proxy_names(proxies_yaml)
            if not names:
                return None
            return {"proxies_yaml": proxies_yaml, "names": names, "proxies": None}

        result = build_result_from_yaml(content)
        if result:
            return result

        if NodeListConverter.is_node_list(content):
            proxies = NodeListConverter.parse_nodes(content)
            if proxies:
                names = [p.get('name', '') for p in proxies if p.get('name')]
                return {"proxies": proxies, "names": names, "proxies_yaml": None}

        decoded = YAMLConverter.b64_decode(content.encode())
        if decoded:
            decoded_text = YAMLConverter.normalize(decoded.decode('utf-8', errors='ignore'))
            result = build_result_from_yaml(decoded_text)
            if result:
                return result
            if NodeListConverter.is_node_list(decoded_text):
                proxies = NodeListConverter.parse_nodes(decoded_text)
                if proxies:
                    names = [p.get('name', '') for p in proxies if p.get('name')]
                    return {"proxies": proxies, "names": names, "proxies_yaml": None}

        return None

    def get_saved_subs(self) -> List[Tuple[str, str]]:
        subs = []
        if SUB_URLS_FILE.exists():
            for line in SUB_URLS_FILE.read_text().strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '|' in line:
                    name, url = line.split('|', 1)
                    subs.append((name.strip(), url.strip()))
                else:
                    subs.append(("未命名", line))
        return subs

    def add_sub(self, name: str, url: str) -> bool:
        subs = self.get_saved_subs()
        for _, u in subs:
            if u == url:
                return False

        with open(SUB_URLS_FILE, 'a') as f:
            f.write(f"{name}|{url}\n")

        if len(subs) == 0:
            SUB_DEFAULT_FILE.write_text(url)

        return True

    def remove_sub(self, index: int) -> bool:
        subs = self.get_saved_subs()
        if index < 0 or index >= len(subs):
            return False

        with open(SUB_URLS_FILE, 'w') as f:
            for i, (name, url) in enumerate(subs):
                if i != index:
                    f.write(f"{name}|{url}\n")

        return True

    def get_default_sub(self) -> Optional[str]:
        if SUB_DEFAULT_FILE.exists():
            return SUB_DEFAULT_FILE.read_text().strip()
        return None

    def set_default_sub(self, url: str) -> None:
        SUB_DEFAULT_FILE.write_text(url)

# ============== 节点测试 ==============
class NodeTester:
    """节点测试器"""

    @staticmethod
    def test_tcp(host: str, port: int, timeout: float = 5) -> bool:
        try:
            import socket
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except:
            return False

    @staticmethod
    def test_latency(host: str, port: int, timeout: float = 3) -> Optional[int]:
        try:
            import socket
            import time as t
            start = t.time()
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return int((t.time() - start) * 1000)
        except:
            return None

    @staticmethod
    def get_node_host_port(content: str, node_name: str) -> Optional[Tuple[str, int]]:
        in_node = False
        host = port = None

        for line in content.split('\n'):
            if (f'name: "{node_name}"' in line or f"name: '{node_name}'" in line
                    or f"name: {node_name}" in line):
                in_node = True
                continue

            if in_node:
                if 'server:' in line:
                    m = re.search(r'server:\s*(\S+)', line)
                    if m:
                        host = m.group(1).strip().strip('"').strip("'")
                elif 'port:' in line:
                    m = re.search(r'port:\s*(\d+)', line)
                    if m:
                        port = int(m.group(1))
                elif host and port:
                    return host, port
                if line.strip().startswith('- name:'):
                    break

        return None

# ============== 配置生成 ==============
class ConfigGenerator:
    """Mihomo 配置生成器"""

    def __init__(self, proxies: List[Dict[str, Any]]):
        self.proxies = proxies

    @staticmethod
    def yaml_scalar(val: Any) -> str:
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return str(val)
        s = str(val)
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        return f"\"{s}\""

    def gen_config(self, active_node: str) -> str:
        lines = [
            f"port: {HTTP_PORT}",
            f"socks-port: {SOCKS_PORT}",
            "allow-lan: true",
            "bind-address: 0.0.0.0",
            "mode: global",
            "log-level: info",
            "ipv6: false",
            "authentication:",
            f'  - "{USER}:{PASS}"',
            "",
            "proxies:"
        ]

        for proxy in self.proxies:
            name = proxy.get('name', '')
            if not name:
                continue
            lines.append(f"  - name: \"{name}\"")
            for k, v in proxy.items():
                if k == 'name':
                    continue
                if isinstance(v, bool):
                    lines.append(f"    {k}: {str(v).lower()}")
                elif isinstance(v, dict):
                    lines.append(f"    {k}:")
                    for kk, vv in v.items():
                        if isinstance(vv, bool):
                            lines.append(f"      {kk}: {str(vv).lower()}")
                        elif isinstance(vv, list):
                            lines.append(f"      {kk}:")
                            for item in vv:
                                lines.append(f"        - {self.yaml_scalar(item)}")
                        else:
                            lines.append(f"      {kk}: {self.yaml_scalar(vv)}")
                elif isinstance(v, list):
                    lines.append(f"    {k}:")
                    for item in v:
                        lines.append(f"      - {self.yaml_scalar(item)}")
                else:
                    lines.append(f"    {k}: {self.yaml_scalar(v)}")

        lines.extend([
            "",
            "proxy-groups:",
            "  - name: GLOBAL",
            "    type: select",
            "    proxies:",
            f"      - \"{active_node}\""
        ])

        return '\n'.join(lines)

    def gen_config_with_yaml(self, proxies_yaml: str, active_node: str) -> str:
        header = [
            f"port: {HTTP_PORT}",
            f"socks-port: {SOCKS_PORT}",
            "allow-lan: true",
            "bind-address: 0.0.0.0",
            "mode: global",
            "log-level: info",
            "ipv6: false",
            "authentication:",
            f'  - \"{USER}:{PASS}\"',
            "",
        ]
        block = proxies_yaml.strip()
        if not block.startswith("proxies:"):
            block = "proxies:\n" + block
        footer = [
            "",
            "proxy-groups:",
            "  - name: GLOBAL",
            "    type: select",
            "    proxies:",
            f"      - \"{active_node}\""
        ]
        return "\n".join(header) + block + "\n" + "\n".join(footer)

    def gen_direct_config(self) -> str:
        return f'''port: {HTTP_PORT}
socks-port: {SOCKS_PORT}
allow-lan: true
bind-address: 0.0.0.0
mode: direct
log-level: info
ipv6: false
authentication:
  - "{USER}:{PASS}"

rules:
  - MATCH,DIRECT
'''

# ============== 菜单系统 ==============
class Menu:
    """菜单系统"""

    def __init__(self):
        self.sub_manager = SubscriptionManager()
        self.running = True
        self.last_service_active: Optional[bool] = None
        self.last_service_error: str = ""

    def print_menu(self, items: List[Tuple[str, str]], title: str = "", zero_label: str = "返回上级"):
        print()
        if title:
            line()
            msg_title(title)
            line()
        for num, label in items:
            c_print(f"  {num}. {label}", Colors.YELLOW)
        print()
        c_print(f"  0. {zero_label}", Colors.YELLOW)
        print()

    def wait_back(self, prompt: str = "0. 返回上级"):
        while True:
            print()
            c_print(f"  {prompt}", Colors.YELLOW)
            try:
                v = input("  请输入选项: ").strip()
                if v == "0":
                    break
            except (EOFError, KeyboardInterrupt):
                print()
                break

    def ask_choice(self, prompt: str) -> str:
        print()
        c_print(f"  {prompt}", Colors.YELLOW)
        try:
            return input("  请输入选项: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return ""

    def ask_yes_no(self, prompt: str, default: bool = False) -> bool:
        suffix = " (Y/n)" if default else " (y/N)"
        print()
        c_print(f"  {prompt}{suffix}", Colors.YELLOW)
        try:
            val = input("  请输入选项: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not val:
            return default
        return val in ("y", "yes")

    def _iptables(self, args: List[str]) -> bool:
        try:
            return subprocess.run(
                ["iptables"] + args,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0
        except Exception:
            return False

    def _iptables_rule_exists(self, args: List[str]) -> bool:
        try:
            return subprocess.run(
                ["iptables", "-C"] + args,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0
        except Exception:
            return False

    def _apply_port_whitelist(self, ip: str) -> None:
        if not self._iptables(["-n", "-L"]):
            msg_warn("未检测到 iptables，无法设置白名单")
            return

        self.clear_whitelist()

        for port in (HTTP_PORT, SOCKS_PORT):
            accept_local = ["INPUT", "-p", "tcp", "-s", "127.0.0.1", "--dport", str(port), "-j", "ACCEPT"]
            accept_ip = ["INPUT", "-p", "tcp", "-s", ip, "--dport", str(port), "-j", "ACCEPT"]
            drop_other = ["INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"]

            if not self._iptables_rule_exists(accept_local):
                self._iptables(["-I"] + accept_local)
            if not self._iptables_rule_exists(accept_ip):
                self._iptables(["-I"] + accept_ip)
            if not self._iptables_rule_exists(drop_other):
                self._iptables(["-A"] + drop_other)

        WHITELIST_FILE.write_text(ip)
        msg_info(f"白名单已生效，仅允许 {ip} 访问代理")

    def clear_whitelist(self) -> None:
        if not WHITELIST_FILE.exists():
            return
        ip = WHITELIST_FILE.read_text().strip()
        if not ip:
            WHITELIST_FILE.unlink(missing_ok=True)
            return
        if not self._iptables(["-n", "-L"]):
            WHITELIST_FILE.unlink(missing_ok=True)
            return

        for port in (HTTP_PORT, SOCKS_PORT):
            rules = [
                ["INPUT", "-p", "tcp", "-s", "127.0.0.1", "--dport", str(port), "-j", "ACCEPT"],
                ["INPUT", "-p", "tcp", "-s", ip, "--dport", str(port), "-j", "ACCEPT"],
                ["INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
            ]
            for rule in rules:
                while self._iptables_rule_exists(rule):
                    self._iptables(["-D"] + rule)

        WHITELIST_FILE.unlink(missing_ok=True)

    def _restart_service_and_check(self) -> bool:
        test = subprocess.run(
            ["mihomo", "-t", "-d", str(WORKDIR), "-f", str(CONFIG)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if test.returncode != 0:
            msg_err("配置自检失败，已取消启动服务")
            output = (test.stdout or "").strip()
            if output:
                lines = [line.strip() for line in output.splitlines() if line.strip()]
                msg_warn("自检输出：")
                for line in lines[-3:]:
                    msg_warn(f"  {line[:200]}")
            self.last_service_active = False
            self.last_service_error = "\n".join((test.stdout or "").splitlines()[-3:])
            return False

        subprocess.run(["systemctl", "daemon-reload"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "enable", "mihomo-proxy"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        restart = subprocess.run(["systemctl", "restart", "mihomo-proxy"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.6)
        is_active = subprocess.run(
            ["systemctl", "is-active", "mihomo-proxy"],
            capture_output=True,
            text=True,
        ).returncode == 0
        self.last_service_active = is_active and restart.returncode == 0
        self.last_service_error = ""
        if restart.returncode != 0 or not is_active:
            msg_err("代理服务启动失败")
            err = self._get_service_error()
            if err:
                self.last_service_error = err
                msg_warn("失败原因：")
                for line in err.splitlines():
                    msg_warn(f"  {line}")
            msg_warn("请在菜单选择“查看日志”排查原因")
            return False
        return True

    def _get_service_error(self) -> str:
        try:
            result = subprocess.check_output(
                ["journalctl", "-u", "mihomo-proxy", "-n", "20", "--no-pager"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            result = ""
        if not result:
            try:
                result = subprocess.check_output(
                    ["systemctl", "status", "mihomo-proxy", "--no-pager", "-l"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
            except Exception:
                result = ""
        if not result:
            return ""
        lines = [line.strip() for line in result.splitlines() if line.strip()]
        if not lines:
            return ""
        keywords = ("error", "failed", "fatal", "panic")
        for line in reversed(lines):
            lower = line.lower()
            if any(k in lower for k in keywords):
                return line[-200:]
        return "\n".join(lines[-3:])[:400]

    def whitelist_menu(self):
        while True:
            logo()
            self.print_menu([
                ("1", "查看白名单状态"),
                ("2", "设置白名单"),
                ("3", "清除白名单"),
            ], "白名单管理", zero_label="返回上级")

            choice = self.ask_choice("请选择操作编号:")
            if not choice:
                continue

            if choice == "1":
                self.show_whitelist_status()
                self.wait_back()
            elif choice == "2":
                self.set_whitelist()
                self.wait_back()
            elif choice == "3":
                self.clear_whitelist()
                msg_info("白名单已清除")
                self.wait_back()
            elif choice == "0":
                break

    def show_whitelist_status(self):
        print()
        line()
        msg_title("白名单状态：")
        line()

        mode = "订阅模式"
        if MODE_FILE.exists() and MODE_FILE.read_text().strip() == "direct":
            mode = "直连模式"
        msg_info(f"当前模式：{mode}")
        msg_info(f"生效端口：HTTP {HTTP_PORT} / SOCKS {SOCKS_PORT}")

        if WHITELIST_FILE.exists():
            ip = WHITELIST_FILE.read_text().strip()
            if ip:
                msg_info(f"当前白名单 IP：{ip}")
                http_ok = self._iptables_rule_exists(
                    ["INPUT", "-p", "tcp", "-s", ip, "--dport", str(HTTP_PORT), "-j", "ACCEPT"]
                )
                socks_ok = self._iptables_rule_exists(
                    ["INPUT", "-p", "tcp", "-s", ip, "--dport", str(SOCKS_PORT), "-j", "ACCEPT"]
                )
                http_drop = self._iptables_rule_exists(
                    ["INPUT", "-p", "tcp", "--dport", str(HTTP_PORT), "-j", "DROP"]
                )
                socks_drop = self._iptables_rule_exists(
                    ["INPUT", "-p", "tcp", "--dport", str(SOCKS_PORT), "-j", "DROP"]
                )
                if http_ok and socks_ok:
                    msg_info("iptables 规则：HTTP/SOCKS 已生效")
                elif http_ok or socks_ok:
                    msg_warn("iptables 规则：部分端口已生效")
                else:
                    msg_warn("iptables 规则：未检测到")
                if http_drop and socks_drop:
                    msg_info("拦截规则：HTTP/SOCKS 已启用")
                elif http_drop or socks_drop:
                    msg_warn("拦截规则：部分端口已启用")
                else:
                    msg_warn("拦截规则：未检测到")
            else:
                msg_warn("白名单文件为空")
        else:
            msg_warn("未启用白名单")

        line()

    def set_whitelist(self):
        if MODE_FILE.exists() and MODE_FILE.read_text().strip() != "direct":
            msg_warn("当前非直连模式，白名单将影响订阅代理端口")

        if not self.ask_yes_no("确认设置白名单", default=False):
            return

        ip = self.ask_choice("请输入允许访问的 IP:")
        try:
            ipaddress.ip_address(ip)
            self._apply_port_whitelist(ip)
        except ValueError:
            msg_warn("IP 格式无效，已取消设置")

    def show_subs(self):
        subs = self.sub_manager.get_saved_subs()
        default = self.sub_manager.get_default_sub()

        print()
        line()
        msg_title("已保存订阅：")
        line()

        if not subs:
            c_print("  （暂无订阅）", Colors.YELLOW)
        else:
            for i, (name, url) in enumerate(subs, 1):
                mark = f" {Colors.GREEN}[默认]{Colors.RESET}" if url == default else ""
                c_print(f"  {i:2d}. {name:20s} | {url}{mark}", Colors.CYAN)

        line()

    def add_sub(self):
        try:
            url = input("  输入订阅链接 (支持 Clash/Mihomo 或 v2rayN): ").strip()
            if not url:
                msg_warn("未输入订阅链接")
                return

            name = input("  订阅名称 (可选，回车自动生成): ").strip()
            if not name:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                name = parsed.hostname or "订阅"

            if self.sub_manager.add_sub(name, url):
                msg_info("已添加订阅，正在更新...")
                self.update_sub_direct(url)
            else:
                msg_warn("订阅已存在")
        except (EOFError, KeyboardInterrupt):
            print()

    def update_sub(self):
        subs = self.sub_manager.get_saved_subs()
        default = self.sub_manager.get_default_sub()

        if not subs:
            msg_warn("未添加订阅，请先选择添加订阅")
            return

        self.show_subs()

        try:
            if default:
                idx = subs.index(next((s for s in subs if s[1] == default), subs[0]))
                prompt = f"  选择订阅编号 (回车默认 {idx + 1}): "
            else:
                prompt = "  选择订阅编号: "

            v = self.ask_choice(prompt)
            if not v and default:
                for i, (_, url) in enumerate(subs):
                    if url == default:
                        idx = i
                        break
            else:
                idx = int(v) - 1 if v else 0

            if idx < 0 or idx >= len(subs):
                msg_err("订阅编号无效")
                return

            url = subs[idx][1]
            self.update_sub_direct(url)
        except (ValueError, EOFError, KeyboardInterrupt):
            print()

    def update_sub_direct(self, url: str):
        msg_info("正在下载订阅并解析节点...")

        result = self.sub_manager.parse(url)

        if not result:
            msg_err("订阅解析失败或返回空节点")
            msg_warn("可能原因：订阅过期/绑定 IP/UA 限制/访问受限")
            return

        names = result.get("names", [])
        PROXY_FILE.write_text('\n'.join(names))

        proxies_yaml = result.get("proxies_yaml")
        proxies = result.get("proxies")

        if proxies_yaml:
            PROXY_YAML.write_text(proxies_yaml.rstrip() + "\n")
        elif proxies:
            with open(PROXY_YAML, 'w') as f:
                f.write("proxies:\n")
                for proxy in proxies:
                    name = proxy.get('name', '')
                    if not name:
                        continue
                    f.write(f"  - name: \"{name}\"\n")
                    for k, v in proxy.items():
                        if k == 'name':
                            continue
                        if isinstance(v, bool):
                            f.write(f"    {k}: {str(v).lower()}\n")
                        elif isinstance(v, dict):
                            f.write(f"    {k}:\n")
                            for kk, vv in v.items():
                                if isinstance(vv, bool):
                                    f.write(f"      {kk}: {str(vv).lower()}\n")
                                elif isinstance(vv, list):
                                    f.write(f"      {kk}:\n")
                                    for item in vv:
                                        f.write(f"        - {ConfigGenerator.yaml_scalar(item)}\n")
                                else:
                                    f.write(f"      {kk}: {ConfigGenerator.yaml_scalar(vv)}\n")
                        elif isinstance(v, list):
                            f.write(f"    {k}:\n")
                            for item in v:
                                f.write(f"      - {ConfigGenerator.yaml_scalar(item)}\n")
                        else:
                            f.write(f"    {k}: {ConfigGenerator.yaml_scalar(v)}\n")
        else:
            msg_err("订阅解析失败或返回空节点")
            return

        msg_info(f"解析完成，节点数量：{len(names)}")

    def delete_sub(self):
        subs = self.sub_manager.get_saved_subs()
        if not subs:
            msg_warn("暂无订阅")
            return

        self.show_subs()

        try:
            v = self.ask_choice("删除订阅编号:")
            idx = int(v) - 1
            if self.sub_manager.remove_sub(idx):
                msg_info("已删除订阅")
            else:
                msg_err("订阅编号无效")
        except (ValueError, EOFError, KeyboardInterrupt):
            print()

    def select_node(self):
        if not PROXY_FILE.exists():
            msg_warn("未找到节点，请先更新订阅")
            return

        names = PROXY_FILE.read_text().strip().split('\n')
        if not names or not names[0]:
            msg_warn("节点列表为空")
            return

        print()
        msg_title("选择节点：")
        line()

        for i, name in enumerate(names, 1):
            c_print(f"  {i:2d}. {name}", Colors.CYAN)

        line()

        try:
            v = self.ask_choice("选择节点编号:")
            idx = int(v) - 1
            if idx < 0 or idx >= len(names):
                msg_err("节点编号无效")
                return

            node_name = names[idx]
            ACTIVE.write_text(node_name)

            content = PROXY_YAML.read_text()
            result = NodeTester.get_node_host_port(content, node_name)

            if result:
                host, port = result
                if NodeTester.test_tcp(host, port):
                    msg_info(f"节点连通：{node_name}")
                    self.gen_service(node_name)
                else:
                    msg_warn(f"节点不可达：{node_name}")
            else:
                msg_warn(f"无法解析节点：{node_name}")

        except (ValueError, EOFError, KeyboardInterrupt):
            print()

    def gen_service(self, active_node: str):
        self.clear_whitelist()
        if not PROXY_YAML.exists() or not PROXY_YAML.read_text().strip():
            msg_warn("未找到节点配置")
            return

        proxies_yaml = PROXY_YAML.read_text()
        gen = ConfigGenerator([])
        config = gen.gen_config_with_yaml(proxies_yaml, active_node)
        CONFIG.write_text(config)

        service_content = f"""[Unit]
Description=Mihomo Smart Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/mihomo -d {WORKDIR} -f {CONFIG}
Restart=always

[Install]
WantedBy=multi-user.target
"""

        service_file = Path("/etc/systemd/system/mihomo-proxy.service")
        service_file.write_text(service_content)

        self._restart_service_and_check()

        ip = get_public_ip()
        is_active = subprocess.run(
            ["systemctl", "is-active", "mihomo-proxy"],
            capture_output=True
        ).returncode == 0

        status = Colors.GREEN + "运行中" + Colors.RESET if is_active else Colors.RED + "已停止" + Colors.RESET

        print()
        line()
        c_print(f"  服务状态：{status}", Colors.CYAN)
        line()
        c_print(f"  HTTP  : http://{USER}:{PASS}@{ip}:{HTTP_PORT}", Colors.CYAN)
        c_print(f"  SOCKS : socks5://{USER}:{PASS}@{ip}:{SOCKS_PORT}", Colors.CYAN)
        line()

    def direct_mode(self):
        gen = ConfigGenerator([])
        config = gen.gen_direct_config()
        CONFIG.write_text(config)

        MODE_FILE.write_text("direct")
        self.clear_whitelist()

        if self.ask_yes_no("搭建纯本地 HTTP 代理时加白名单", default=False):
            ip = self.ask_choice("请输入允许访问的 IP:")
            try:
                ipaddress.ip_address(ip)
                self._apply_port_whitelist(ip)
            except ValueError:
                msg_warn("IP 格式无效，已跳过白名单设置")

        service_content = f"""[Unit]
Description=Mihomo Smart Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/mihomo -d {WORKDIR} -f {CONFIG}
Restart=always

[Install]
WantedBy=multi-user.target
"""

        Path("/etc/systemd/system/mihomo-proxy.service").write_text(service_content)

        self._restart_service_and_check()

        ip = get_public_ip()
        print()
        line()
        c_print("  直连代理已启用（无需订阅）", Colors.GREEN)
        line()
        c_print(f"  HTTP  : http://{USER}:{PASS}@{ip}:{HTTP_PORT}", Colors.CYAN)
        c_print(f"  SOCKS : socks5://{USER}:{PASS}@{ip}:{SOCKS_PORT}", Colors.CYAN)
        line()

    def show_status(self):
        print()
        line()
        msg_title("当前状态：")
        line()

        if MODE_FILE.exists() and MODE_FILE.read_text() == "direct":
            msg_info("直连模式（无需订阅）")
        elif ACTIVE.exists():
            c_print(f"  当前节点：{ACTIVE.read_text()}", Colors.YELLOW)
        else:
            msg_warn("未选择节点")

        line()

        ip = get_public_ip()
        if self.last_service_active is None:
            is_active = subprocess.run(
                ["systemctl", "is-active", "mihomo-proxy"],
                capture_output=True
            ).returncode == 0
        else:
            is_active = self.last_service_active
        status = Colors.GREEN + "运行中" + Colors.RESET if is_active else Colors.RED + "已停止（请查看日志）" + Colors.RESET
        c_print(f"  服务状态：{status}", Colors.CYAN)
        line()
        c_print(f"  HTTP  : http://{USER}:{PASS}@{ip}:{HTTP_PORT}", Colors.CYAN)
        c_print(f"  SOCKS : socks5://{USER}:{PASS}@{ip}:{SOCKS_PORT}", Colors.CYAN)
        line()

    def test_connectivity(self):
        ip = get_public_ip()

        print()
        line()
        msg_title("代理连通性检测：")
        line()

        c_print(f"  HTTP 测试: {TEST_URL}", Colors.CYAN)
        try:
            result = subprocess.check_output([
                "curl", "-s", "--max-time", "10",
                "-x", f"http://{USER}:{PASS}@{ip}:{HTTP_PORT}",
                TEST_URL
            ], stderr=subprocess.DEVNULL).decode().strip()
            if result:
                msg_info(f"HTTP 出口 IP：{result}")
            else:
                msg_err("HTTP 测试失败")
        except:
            msg_err("HTTP 测试失败")

        c_print(f"  HTTPS 测试: {TEST_URL_HTTPS}", Colors.CYAN)
        try:
            result = subprocess.check_output([
                "curl", "-s", "--max-time", "10",
                "-x", f"http://{USER}:{PASS}@{ip}:{HTTP_PORT}",
                TEST_URL_HTTPS
            ], stderr=subprocess.DEVNULL).decode().strip()
            if result:
                msg_info(f"HTTPS 出口 IP：{result}")
            else:
                msg_err("HTTPS 测试失败")
        except:
            msg_err("HTTPS 测试失败")

        line()

    def test_latency(self):
        default = self.sub_manager.get_default_sub()
        if default:
            msg_info("正在同步默认订阅用于延迟检测...")
            self.update_sub_direct(default)

        if not PROXY_FILE.exists():
            msg_warn("未找到节点，请先更新订阅")
            return

        names = PROXY_FILE.read_text().strip().split('\n')
        if not names or not names[0]:
            msg_warn("节点列表为空")
            return

        print()
        line()
        msg_title("节点延迟检测（TCP 连接耗时）")
        line()

        content = PROXY_YAML.read_text() if PROXY_YAML.exists() else ""

        for name in names:
            result = NodeTester.get_node_host_port(content, name)
            if result:
                host, port = result
                ms = NodeTester.test_latency(host, port, LATENCY_TIMEOUT)
                if ms is not None:
                    c_print(f"  {name:30s} {Colors.GREEN}{ms}ms{Colors.RESET}", Colors.YELLOW)
                else:
                    c_print(f"  {name:30s} {Colors.RED}timeout{Colors.RESET}", Colors.YELLOW)
            else:
                c_print(f"  {name:30s} {Colors.RED}无法解析{Colors.RESET}", Colors.YELLOW)

        line()

    def stop_service(self):
        subprocess.run(["systemctl", "stop", "mihomo-proxy"], check=False)
        msg_info("代理服务已停止")

    def show_logs(self):
        print()
        line()
        msg_title("Mihomo 运行日志（最近 50 行）")
        line()
        try:
            result = subprocess.check_output([
                "journalctl", "-u", "mihomo-proxy", "-n", "50", "--no-pager"
            ], text=True)
            print(result)
        except:
            msg_err("无法读取日志")

    def uninstall(self):
        try:
            v = input("  确认卸载？y/n: ").strip().lower()
            if v == 'y':
                subprocess.run(["systemctl", "stop", "mihomo-proxy"], check=False)
                subprocess.run(["systemctl", "disable", "mihomo-proxy"], check=False)
                Path("/etc/systemd/system/mihomo-proxy.service").unlink(missing_ok=True)
                import shutil
                shutil.rmtree(WORKDIR, ignore_errors=True)
                msg_info("已卸载 Mihomo 代理管理环境")
        except (EOFError, KeyboardInterrupt):
            print()

    def run(self):
        while self.running:
            logo()
            self.print_menu([
                ("1", "订阅管理"),
                ("2", "选择节点"),
                ("3", "当前状态"),
                ("4", "停止服务"),
                ("5", "查看日志"),
                ("6", "连通检测"),
                ("7", "延迟检测"),
                ("8", "直连模式"),
                ("9", "白名单管理"),
                ("10", "卸载全部"),
            ], zero_label="退出")

            try:
                choice = input("  请输入选项: ").strip()
            except (EOFError, KeyboardInterrupt):
                choice = "0"

            if choice == "1":
                self.sub_menu()
            elif choice == "2":
                self.select_node()
                self.wait_back()
            elif choice == "3":
                self.show_status()
                self.wait_back()
            elif choice == "4":
                self.stop_service()
                self.wait_back()
            elif choice == "5":
                self.show_logs()
                self.wait_back()
            elif choice == "6":
                self.test_connectivity()
                self.wait_back()
            elif choice == "7":
                self.test_latency()
                self.wait_back()
            elif choice == "8":
                self.direct_mode()
                self.wait_back()
            elif choice == "9":
                self.whitelist_menu()
            elif choice == "10":
                self.uninstall()
                self.wait_back()
            elif choice == "0":
                self.running = False

    def sub_menu(self):
        while True:
            logo()
            self.print_menu([
                ("1", "添加订阅"),
                ("2", "更新订阅"),
                ("3", "查看订阅"),
                ("4", "设为默认"),
                ("5", "删除订阅"),
            ], "订阅管理", zero_label="返回上级")

            try:
                choice = input("  请输入选项: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if choice == "1":
                self.add_sub()
                self.wait_back()
            elif choice == "2":
                self.update_sub()
                self.wait_back()
            elif choice == "3":
                self.show_subs()
                self.wait_back()
            elif choice == "4":
                self.set_default_sub()
                self.wait_back()
            elif choice == "5":
                self.delete_sub()
                self.wait_back()
            elif choice == "0":
                break

    def set_default_sub(self):
        subs = self.sub_manager.get_saved_subs()
        if not subs:
            msg_warn("暂无订阅")
            return

        self.show_subs()
        try:
            v = self.ask_choice("选择默认订阅编号:")
            idx = int(v) - 1
            if 0 <= idx < len(subs):
                self.sub_manager.set_default_sub(subs[idx][1])
                msg_info(f"已设为默认：{subs[idx][0]}")
            else:
                msg_err("订阅编号无效")
        except (ValueError, EOFError, KeyboardInterrupt):
            print()

# ============== Mihomo 安装 ==============
def install_mihomo() -> bool:
    try:
        if subprocess.run(["which", "mihomo"], capture_output=True).returncode == 0:
            return True
    except:
        pass

    msg_info("未检测到 mihomo，正在安装...")

    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7",
        "armv7": "armv7",
    }

    import platform
    arch = platform.machine().lower()
    arch = arch_map.get(arch, arch)

    if arch not in ["amd64", "arm64", "armv7"]:
        msg_err(f"不支持的架构: {arch}")
        return False

    url = os.getenv("MIHOMO_URL")
    if not url:
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
                headers={"User-Agent": "mihomo-smart"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                for asset in data.get("assets", []):
                    name = asset.get("name", "").lower()
                    if f"linux-{arch}" in name and "sha256" not in name:
                        url = asset["browser_download_url"]
                        if name.endswith(".gz"):
                            break
        except:
            msg_err("获取发布信息失败")
            return False

    if not url:
        msg_err("未找到对应的发行包")
        return False

    msg_info(f"正在下载：{url}")
    tmp = Path("/tmp/mihomo.tmp")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "mihomo-smart"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            tmp.write_bytes(resp.read())

        if url.endswith(".gz"):
            import gzip
            data = gzip.decompress(tmp.read_bytes())
        else:
            data = tmp.read_bytes()

        Path("/usr/local/bin/mihomo").write_bytes(data)
        subprocess.run(["chmod", "+x", "/usr/local/bin/mihomo"], check=True)
        tmp.unlink()
        msg_info("Mihomo 安装成功")
        return True
    except Exception as e:
        msg_err(f"安装失败：{e}")
        tmp.unlink(missing_ok=True)
        return False

# ============== 主程序 ==============
def main():
    if os.geteuid() != 0:
        print("请使用 root 权限运行此脚本")
        sys.exit(1)

    if not install_mihomo():
        msg_err("Mihomo 安装失败，无法继续")
        sys.exit(1)

    WORKDIR.mkdir(parents=True, exist_ok=True)

    menu = Menu()
    try:
        menu.run()
    except KeyboardInterrupt:
        print()
        msg_info("程序已退出")

if __name__ == "__main__":
    main()
