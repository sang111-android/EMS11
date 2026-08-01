# relay_vless.py
# بخش VLESS Relay — بازنویسی‌شده برای حداکثر سرعت
#
# منطق پروتکل VLESS دست‌نخورده است (کلاینت‌های Xray بدون تغییر کار می‌کنند)؛
# فقط لایه‌ی انتقال داده بازنویسی شده:
#
#   ۱) Early Data (?ed=2048): اولین پکت داخل هدر Sec-WebSocket-Protocol می‌آید
#      → یک RTT کامل از زمان باز شدن هر اتصال حذف می‌شود.
#   ۲) اتصال موازی به مقصد (Happy-Eyeballs): همزمان روی چند IP (IPv4/IPv6)
#      اتصال باز می‌شود و سریع‌ترین برنده می‌شود؛ بقیه بسته می‌شوند.
#   ۳) کش DNS با TTL → حذف تاخیر resolve در اتصال‌های بعدی.
#   ۴) بافر خواندن تطبیقی (۲۵۶KB → ۴MB) و high-water تطبیقی برای نوشتن (AIMD).
#   ۵) ارسال هدر پاسخ VLESS در فریم جداگانه → حذف کپی کل اولین چانک.
#   ۶) تیون سوکت: TCP_NODELAY + SO_SNDBUF/SO_RCVBUF = ۸MB + TCP_QUICKACK + سقف بافر ترانسپورت.
#   ۷) مسیر سریع (fast path): وقتی کانفیگ لیمیت سرعت ندارد، تراتل کاملاً دور زده می‌شود.
#   ۸) حسابرسی حجم دسته‌ای با QuotaGate (بدون گرفتن قفل سراسری به‌ازای هر چانک).
#   ۹) هدر VLESS می‌تواند تکه‌تکه برسد (تجمیع ایمن تا سقف ۱۶KB).

import asyncio
import base64
import secrets
import socket
import time
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
    log_activity,
    now_ir,
)
from speed_limit import throttle, QuotaGate

# ══════════════════════════════════════════════════════════════════════════════
# تنظیمات
# ══════════════════════════════════════════════════════════════════════════════

READ_MIN = 256 * 1024              # کف بافر خواندن از مقصد
READ_MAX = 4 * 1024 * 1024         # سقف بافر خواندن (حجم مهم نیست، سرعت مهم است)
READ_START = 512 * 1024

WRITE_HW_MIN = 256 * 1024          # کف high-water نوشتن روی TCP
WRITE_HW_MAX = 32 * 1024 * 1024    # سقف high-water
WRITE_HW_START = 2 * 1024 * 1024
FLOW_FAST_DRAIN_MS = 2.0
FLOW_SLOW_DRAIN_MS = 25.0

SOCK_BUF_SIZE = 8 * 1024 * 1024    # SO_SNDBUF / SO_RCVBUF
CONNECT_TIMEOUT = 10.0
HEADER_TIMEOUT = 15.0
HEADER_MAX = 16 * 1024             # سقف تجمیع برای پارس هدر VLESS

PARALLEL_CONNECT = 3               # تعداد تلاش اتصال موازی به مقصد
CONNECT_STAGGER = 0.12             # فاصله‌ی شروع تلاش‌ها (Happy-Eyeballs)
DNS_TTL = 300.0                    # طول عمر کش DNS (ثانیه)
DNS_CACHE_MAX = 4096

# سازگاری عقب‌رو (برخی ماژول‌ها این را وارد می‌کردند)
RELAY_BUF = READ_START

_dns_cache: dict[tuple[str, int], tuple[float, list]] = {}


# ══════════════════════════════════════════════════════════════════════════════
# کمکی‌ها
# ══════════════════════════════════════════════════════════════════════════════

class _AdaptiveFlow:
    """AIMD روی high-water نوشتن: اگر drain سریع بود سقف بزرگ‌تر، اگر کند بود نصف."""
    __slots__ = ("high_water",)

    def __init__(self) -> None:
        self.high_water = WRITE_HW_START

    def observe(self, drain_ms: float) -> None:
        if drain_ms <= FLOW_FAST_DRAIN_MS:
            self.high_water = min(int(self.high_water * 1.5) + 65536, WRITE_HW_MAX)
        elif drain_ms >= FLOW_SLOW_DRAIN_MS:
            self.high_water = max(self.high_water // 2, WRITE_HW_MIN)


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "نامشخص"


def _early_data(ws: WebSocket) -> bytes:
    """Xray در حالت `?ed=` اولین پکت را base64url داخل Sec-WebSocket-Protocol می‌گذارد.
    با خواندن آن، دیگر لازم نیست منتظر اولین فریم بمانیم → یک RTT صرفه‌جویی."""
    raw = ws.headers.get("sec-websocket-protocol")
    if not raw:
        return b""
    token = raw.split(",")[0].strip()
    if not token:
        return b""
    try:
        pad = "=" * (-len(token) % 4)
        return base64.urlsafe_b64decode(token + pad)
    except Exception:
        return b""


def _tune_socket(writer: asyncio.StreamWriter, high_water: int) -> None:
    transport = writer.transport
    sock = transport.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
        except OSError:
            pass
        quickack = getattr(socket, "TCP_QUICKACK", None)
        if quickack is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, quickack, 1)
            except OSError:
                pass
    try:
        transport.set_write_buffer_limits(high=high_water, low=high_water // 4)
    except Exception:
        pass


def _tune_client_socket(ws: WebSocket) -> None:
    """همان تیون روی سوکت سمت کلاینت تا مسیر برگشت هم پهن باشد.
    بسته به سرور (uvicorn/websockets/h11) ممکن است سوکت در دسترس نباشد → بی‌سروصدا رد می‌شویم."""
    sock = None
    try:
        scope = getattr(ws, "scope", {}) or {}
        transport = scope.get("transport")
        if transport is not None and hasattr(transport, "get_extra_info"):
            sock = transport.get_extra_info("socket")
        if sock is None:
            ext = scope.get("extensions") or {}
            sock = (ext.get("transport") or {}).get("socket") if isinstance(ext.get("transport"), dict) else None
    except Exception:
        sock = None
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
    except OSError:
        pass


async def _resolve(host: str, port: int) -> list:
    """resolve با کش TTLدار؛ خروجی لیست (family, sockaddr) مرتب (IPv4 اول)."""
    key = (host, port)
    now = time.monotonic()
    hit = _dns_cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = [(fam, sockaddr) for fam, _t, _p, _c, sockaddr in infos]
    # IPv4 اول امتحان می‌شود ولی IPv6 هم موازی امتحان خواهد شد
    addrs.sort(key=lambda a: 0 if a[0] == socket.AF_INET else 1)
    if len(_dns_cache) > DNS_CACHE_MAX:
        _dns_cache.clear()
    _dns_cache[key] = (now + DNS_TTL, addrs)
    return addrs


async def _open_upstream(address: str, port: int):
    """چند اتصال موازی به مقصد باز می‌کند و اولین اتصال موفق را برمی‌گرداند.
    بقیه‌ی تلاش‌ها لغو و سوکت‌هایشان بسته می‌شود."""
    try:
        addrs = await _resolve(address, port)
    except Exception:
        addrs = []
    if not addrs:
        return await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=CONNECT_TIMEOUT
        )

    candidates = addrs[:PARALLEL_CONNECT]

    async def attempt(idx: int, fam, sockaddr):
        if idx:
            await asyncio.sleep(CONNECT_STAGGER * idx)
        host = sockaddr[0]
        return await asyncio.open_connection(host=host, port=sockaddr[1], family=fam)

    tasks = {
        asyncio.create_task(attempt(i, fam, sa)) for i, (fam, sa) in enumerate(candidates)
    }
    winner = None
    last_exc: Exception | None = None
    deadline = time.monotonic() + CONNECT_TIMEOUT
    try:
        while tasks:
            timeout = max(deadline - time.monotonic(), 0.01)
            done, tasks = await asyncio.wait(
                tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                raise asyncio.TimeoutError
            for t in done:
                exc = t.exception()
                if exc is not None:
                    last_exc = exc if isinstance(exc, Exception) else last_exc
                    continue
                if winner is None:
                    winner = t.result()
                else:
                    _r, w = t.result()
                    try:
                        w.close()
                    except Exception:
                        pass
            if winner is not None:
                break
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                res = await t
            except (asyncio.CancelledError, Exception):
                continue
            try:
                res[1].close()
            except Exception:
                pass

    if winner is None:
        raise last_exc or OSError(f"connect failed: {address}:{port}")
    return winner


async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        if len(chunk) < pos + 4:
            raise ValueError("incomplete ipv4")
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        if len(chunk) < pos + dlen:
            raise ValueError("incomplete domain")
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        if len(chunk) < pos + 16:
            raise ValueError("incomplete ipv6")
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]


async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
    return True


def _speed_limited(uid: str) -> bool:
    link = LINKS.get(uid)
    return bool(link and link.get("speed_limit", 0))


# ══════════════════════════════════════════════════════════════════════════════
# مسیر آپلینک: WebSocket → TCP
# ══════════════════════════════════════════════════════════════════════════════

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    gate = QuotaGate(uid, check_and_use)
    conn = connections.get(conn_id)
    flow = _AdaptiveFlow()
    limited = _speed_limited(uid)
    transport = writer.transport
    receive = ws.receive
    ticks = 0
    try:
        while True:
            # هر ۶۴ فریم یک‌بار وضعیت لیمیت را تازه می‌کنیم (تغییر لیمیت وسط اتصال)
            ticks += 1
            if not (ticks & 63):
                limited = _speed_limited(uid)
            msg = await receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes")
            if data is None:
                text = msg.get("text")
                data = text.encode() if text else None
            if not data:
                continue
            n = len(data)
            if not await gate.add(n):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            if limited:
                await throttle(uid, n)
            stats["total_requests"] += 1
            if conn is not None:
                conn["bytes"] += n
            writer.write(data)
            if transport.get_write_buffer_size() >= flow.high_water:
                t0 = time.monotonic()
                await writer.drain()
                flow.observe((time.monotonic() - t0) * 1000.0)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            await gate.flush()
        except Exception:
            pass
        try:
            writer.write_eof()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# مسیر دانلینک: TCP → WebSocket
# ══════════════════════════════════════════════════════════════════════════════

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    gate = QuotaGate(uid, check_and_use)
    conn = connections.get(conn_id)
    limited = _speed_limited(uid)
    send = ws.send_bytes
    bufsize = READ_START
    ticks = 0
    try:
        # هدر پاسخ VLESS در فریم جداگانه — بدون کپی کردن کل اولین چانک
        await send(b"\x00\x00")
        while True:
            data = await reader.read(bufsize)
            if not data:
                break
            ticks += 1
            if not (ticks & 63):
                limited = _speed_limited(uid)
            n = len(data)
            # بافر تطبیقی: پر شد → دوبرابر، خلوت بود → نصف
            if n >= bufsize:
                bufsize = min(bufsize * 2, READ_MAX)
            elif n < bufsize // 4:
                bufsize = max(bufsize // 2, READ_MIN)
            if not await gate.add(n):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            if limited:
                await throttle(uid, n)
            if conn is not None:
                conn["bytes"] += n
            await send(data)
    except Exception:
        pass
    finally:
        try:
            await gate.flush()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# تونل اصلی
# ═════════════════════════════════════════════════════════════════��════════════

async def _collect_header(ws: WebSocket, early: bytes):
    """هدر VLESS را جمع می‌کند (ممکن است در چند فریم بیاید) و پارس می‌کند."""
    buf = bytearray(early)
    while True:
        if len(buf) >= 24:
            try:
                return (*await parse_vless_header(bytes(buf)), len(buf))
            except ValueError:
                pass
        if len(buf) >= HEADER_MAX:
            raise ValueError("vless header too large")
        msg = await asyncio.wait_for(ws.receive(), timeout=HEADER_TIMEOUT)
        if msg["type"] == "websocket.disconnect":
            raise WebSocketDisconnect(1006)
        chunk = msg.get("bytes")
        if chunk is None:
            text = msg.get("text")
            chunk = text.encode() if text else b""
        if not chunk:
            continue
        buf.extend(chunk)


async def websocket_tunnel(ws: WebSocket, uuid: str):
    # Early Data: اگر کلاینت subprotocol فرستاده، همان را قبول می‌کنیم تا دست‌دادن کامل شود
    early = _early_data(ws)
    await ws.accept()
    _tune_client_socket(ws)

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)")
        log_activity("connection", f"اتصال {ip} به کانفیگ «{link.get('label','?')}» رد شد (محدودیت تعداد آی‌پی)", "warn")
        await ws.close(code=1008, reason="ip limit reached")
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(
        f"✅ WS [{conn_id}] uuid={uuid[:8]}… ip={ip} ed={len(early)}B total={len(connections)}"
    )
    log_activity("connection", f"اتصال جدید از {ip} (کانفیگ {link.get('label','?')})", "info")
    writer = None

    try:
        command, address, port, payload, header_bytes = await _collect_header(ws, early)

        if not await check_and_use(uuid, header_bytes):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        c = connections.get(conn_id)
        if c is not None:
            c["bytes"] += header_bytes
        logger.info(f"➡️  [{conn_id}] → {address}:{port}")

        reader, writer = await _open_upstream(address, port)
        _tune_socket(writer, WRITE_HW_START)

        if payload:
            writer.write(payload)
            # بدون drain اجباری: پکت اول بلافاصله راهی می‌شود و یک await کمتر داریم

        up = asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid))
        down = asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid))
        done, pending = await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 WS closed [{conn_id}] total={len(connections)}")
