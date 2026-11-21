"""Direct HTTPS transport for untrusted upstream URLs."""

from dataclasses import dataclass
from http.client import HTTPSConnection, HTTPException
from ipaddress import ip_address
from queue import Empty, Queue
import re
import socket
import ssl
from threading import Thread, Timer
from time import monotonic
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_BYTES = 2 * 1024 * 1024
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
ASSET_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}


class DownloadError(ValueError):
    def __init__(self, message, bytes_read=0):
        super().__init__(message)
        self.bytes_read = bytes_read


@dataclass
class Download:
    data: bytes
    final_url: str
    media_type: str
    redirects: tuple = ()


def endpoint(url, *, signed=False):
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if (len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url)
                or "\\" in url or parts.scheme != "https"
                or parts.netloc.lower() not in (host, host + ":443")
                or not 0 < len(host) <= 253 or len(host.split(".")) < 2
                or not all(HOST_LABEL.fullmatch(label) for label in host.split("."))
                or host.rsplit(".", 1)[-1].isdigit() or "#" in url
                or host.endswith((".localhost", ".local", ".internal", ".home.arpa"))
                or "?" in url and not (signed and host in ASSET_HOSTS)):
            raise ValueError
        return parts
    except ValueError:
        raise DownloadError("URL 被策略拒绝（仅允许无凭据、无查询参数的公开 HTTPS 域名）") from None


def public_addresses(host, deadline):
    remaining(deadline)
    result = Queue(maxsize=1)

    def resolve():
        try:
            result.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError:
            result.put([])

    Thread(target=resolve, daemon=True).start()
    try:
        answers = result.get(timeout=remaining(deadline))
    except Empty:
        raise DownloadError("DNS 解析超时") from None
    addresses = list(dict.fromkeys(item[4][0] for item in answers))
    if not addresses:
        raise DownloadError("DNS 无解析结果")
    for address in addresses:
        ip = ip_address(address)
        if (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback
                or ip.is_link_local or "%" in address or address == "168.63.129.16"
                or getattr(ip, "ipv4_mapped", None) or getattr(ip, "sixtofour", None)
                or getattr(ip, "teredo", None)):
            raise DownloadError("DNS 返回非公开或特殊地址，已拦截")
    # Avoid IPv6 translation/transition routes, including locally configured NAT64 prefixes.
    ipv4 = [address for address in addresses if ip_address(address).version == 4]
    if not ipv4:
        raise DownloadError("无公开 IPv4 地址")
    return ipv4


def remaining(deadline):
    seconds = deadline - monotonic()
    if seconds <= 0:
        raise DownloadError("下载超过时限")
    return seconds


class PinnedHTTPS(HTTPSConnection):
    def __init__(self, host, address, deadline):
        super().__init__(host, timeout=remaining(deadline), context=ssl.create_default_context())
        self.address = address
        self.deadline = deadline
        self.timer = None

    def connect(self):
        ip = ip_address(self.address)
        family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(remaining(self.deadline))
            raw.connect((self.address, 443))
            raw.settimeout(remaining(self.deadline))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
            # Abort slow TLS, response headers and bodies at the same absolute deadline.
            self.timer = Timer(remaining(self.deadline), self.abort, args=(self.sock,))
            self.timer.daemon = True
            self.timer.start()
            self.sock.do_handshake()
        except BaseException:
            if self.sock is not None:
                self.sock.close()
            raw.close()
            raise

    @staticmethod
    def abort(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def allow_redirect(previous, target, source):
    old = endpoint(previous, signed=True)
    new = endpoint(target, signed=True)
    allowed_assets = set(source.get("redirect_hosts", ())) & ASSET_HOSTS
    if old.hostname == new.hostname:
        if new.path in ("", "/") and old.path not in ("", "/"):
            raise DownloadError("来源重定向至站点首页")
        if old.hostname == "github.com" and allowed_assets:
            original = endpoint(source["url"])
            prefix = original.path.split("/latest/download/", 1)[0]
            release = re.fullmatch(re.escape(prefix) + r"/download/[^/]+/" + re.escape(original.path.rsplit("/", 1)[-1]), new.path)
            if new.path != original.path and not release:
                raise DownloadError("GitHub Release 跳转不属于原项目和资源")
        return
    if old.hostname == "github.com" and new.hostname in allowed_assets:
        return
    # GitHub's public Gist raw route. Keep the same owner and gist ID.
    match = re.fullmatch(r"/([^/]+)/([a-fA-F0-9]{5,64})/raw(?:/[^?#]*)?", old.path)
    if (old.hostname == "gist.github.com" and new.hostname == "gist.githubusercontent.com"
            and match and new.path.startswith(f"/{match[1]}/{match[2]}/raw/")):
        return
    raise DownloadError("跨域重定向未经允许，已拦截")


def download(url, source, deadline, max_bytes=MAX_BYTES):
    endpoint(url)
    deadline = min(deadline, monotonic() + 12)
    current = url
    redirects = []
    for _ in range(5):
        parts = endpoint(current, signed=bool(redirects))
        addresses = public_addresses(parts.hostname, deadline)
        connection = None
        data = bytearray()
        try:
            # Connect directly to a checked numeric address. No second DNS lookup.
            for address in addresses:
                connection = PinnedHTTPS(parts.hostname, address, deadline)
                try:
                    connection.connect()
                    break
                except OSError:
                    if connection.timer:
                        connection.timer.cancel()
                    connection.close()
            else:
                raise DownloadError("HTTPS 连接失败或超时")
            path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            connection.request("GET", path, headers={"Accept-Encoding": "identity", "User-Agent": "QX-monitor/3"})
            with connection.getresponse() as response:
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if not location or any(ord(c) < 33 or ord(c) > 126 for c in location):
                        raise DownloadError("重定向位置缺失或无效")
                    try:
                        target = urljoin(current, location)
                    except ValueError:
                        raise DownloadError("重定向位置格式无效") from None
                    allow_redirect(current, target, source)
                    redirects.append((parts.hostname, urlsplit(target).hostname))
                    current = target
                    continue
                if response.status != 200:
                    raise DownloadError(f"HTTP {response.status}")
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
                    raise DownloadError("不支持的响应编码")
                declared = response.getheader("Content-Length")
                if declared is not None and (not re.fullmatch(r"[0-9]{1,10}", declared) or int(declared) > max_bytes):
                    raise DownloadError("无效长度或文件超出下载预算")
                while remaining(deadline):
                    chunk = response.read1(min(65536, max_bytes + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > max_bytes:
                        raise DownloadError("文件超出下载预算")
                remaining(deadline)
                if declared is not None and len(data) != int(declared):
                    raise DownloadError("实际响应长度与 Content-Length 不符")
                media = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                public_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
                return Download(bytes(data), public_url, media, tuple(redirects))
        except DownloadError as exc:
            exc.bytes_read = len(data)
            raise
        except (OSError, HTTPException) as exc:
            message = "下载超时" if monotonic() >= deadline or isinstance(exc, TimeoutError) else "HTTPS 下载失败"
            raise DownloadError(message, bytes_read=len(data)) from None
        finally:
            if connection:
                if connection.timer:
                    connection.timer.cancel()
                connection.close()
    raise DownloadError("重定向次数超出限制")
