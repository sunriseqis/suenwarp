from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import ssl
import struct
import time
import uuid
from urllib.parse import urlparse


def _ws_upgrade_request(host: str, path: str) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "User-Agent: Mozilla/5.0",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def _build_vless_header(user_uuid: str, target_host: str, target_port: int) -> bytes:
    uid = uuid.UUID(user_uuid).bytes
    # version(1)=0, uuid(16), addons_len(1)=0, cmd(1)=1(TCP), port(2 BE)
    buf = bytearray([0])
    buf.extend(uid)
    buf.append(0)
    buf.append(1)
    buf.extend(struct.pack(">H", target_port))
    try:
        ip = ipaddress.ip_address(target_host)
        if ip.version == 4:
            buf.append(1)
            buf.extend(ip.packed)
        else:
            buf.append(3)
            buf.extend(ip.packed)
    except ValueError:
        host_b = target_host.encode("ascii")
        buf.append(2)
        buf.append(len(host_b))
        buf.extend(host_b)
    return bytes(buf)


def _encode_ws_frame(payload: bytes, opcode: int = 0x2) -> bytes:
    mask = os.urandom(4)
    length = len(payload)
    header = bytearray([0x80 | opcode])
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack(">Q", length))
    header.extend(mask)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


async def _read_ws_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    b1, b2 = await reader.readexactly(2)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        (length,) = struct.unpack(">H", await reader.readexactly(2))
    elif length == 127:
        (length,) = struct.unpack(">Q", await reader.readexactly(8))
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length) if length else b""
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


async def ws_probe(addr: str, port: int, worker_host: str, path: str, timeout: float) -> tuple[int, str]:
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(addr, port, ssl=ctx, server_hostname=worker_host),
            timeout=timeout,
        )
    except Exception as e:
        return 0, str(e)

    try:
        writer.write(_ws_upgrade_request(worker_host, path))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        line = status_line.decode("latin1", errors="ignore").strip()
        parts = line.split(" ", 2)
        code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        return code, ("" if code == 101 else f"HTTP {code or line}")
    except Exception as e:
        return 0, str(e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def tcp_connect_ms(addr: str, port: int, timeout: float) -> float | None:
    t0 = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(addr, port), timeout=timeout)
        dt = (time.perf_counter() - t0) * 1000.0
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return dt
    except Exception:
        return None


class VlessStream:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self._hdr_done = False

    async def write_data(self, data: bytes) -> None:
        self.writer.write(_encode_ws_frame(data, 0x2))
        await self.writer.drain()

    async def read_data(self, timeout: float = 10.0) -> bytes:
        while True:
            opcode, payload = await asyncio.wait_for(_read_ws_frame(self.reader), timeout=timeout)
            if opcode == 0x8:  # close
                return b""
            if opcode == 0x9:  # ping
                self.writer.write(_encode_ws_frame(payload, 0xA))
                await self.writer.drain()
                continue
            if opcode == 0xA:  # pong
                continue
            if not self._hdr_done:
                self._hdr_done = True
                if len(payload) >= 2:
                    addon_len = payload[1]
                    payload = payload[2 + addon_len:]
                if not payload:
                    continue
            return payload

    async def close(self) -> None:
        try:
            self.writer.write(_encode_ws_frame(b"", 0x8))
            await self.writer.drain()
        except Exception:
            pass
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


async def open_vless_stream(
    addr: str,
    port: int,
    worker_host: str,
    path: str,
    user_uuid: str,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
) -> VlessStream:
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(addr, port, ssl=ctx, server_hostname=worker_host),
        timeout=timeout,
    )
    try:
        writer.write(_ws_upgrade_request(worker_host, path))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if b"101" not in status_line:
            raise RuntimeError(f"WS upgrade failed: {status_line.decode('latin1', 'ignore').strip()}")
        while True:
            hdr_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if hdr_line in (b"\r\n", b"\n", b""):
                break
        vless_hdr = _build_vless_header(user_uuid, target_host, target_port)
        writer.write(_encode_ws_frame(vless_hdr, 0x2))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        return VlessStream(reader, writer)
    except Exception:
        writer.close()
        raise


async def probe_target_via_vless(
    addr: str,
    port: int,
    worker_host: str,
    path: str,
    user_uuid: str,
    target_url: str,
    timeout: float = 10.0,
) -> tuple[bool, bytes]:
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    host = parsed.hostname or ""
    tport = parsed.port or (443 if parsed.scheme == "https" else 80)
    req_path = parsed.path or "/"
    if parsed.query:
        req_path += "?" + parsed.query

    stream = await open_vless_stream(addr, port, worker_host, path, user_uuid, host, tport, timeout)
    try:
        # For HTTPS targets, wrap via memory BIO or simple TLS check:
        # Since VlessStream is custom WS-framed, for HTTP targets we send plain HTTP/1.1;
        # for HTTPS targets we use ssl.MemoryBIO handshake over VlessStream.
        if parsed.scheme == "https":
            ok, body = await _https_get_over_stream(stream, host, req_path, timeout)
            return ok, body
        req = (
            f"GET {req_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: curl/8.5.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        await stream.write_data(req)
        raw = await stream.read_data(timeout=timeout)
        return bool(raw), raw
    finally:
        await stream.close()


async def _https_get_over_stream(
    stream: VlessStream,
    host: str,
    req_path: str,
    timeout: float,
    read_limit: int = 16384,
) -> tuple[bool, bytes]:
    ctx = ssl.create_default_context()
    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()
    ssl_obj = ctx.wrap_bio(in_bio, out_bio, server_side=False, server_hostname=host)

    deadline = time.monotonic() + timeout
    while True:
        try:
            ssl_obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            out_data = out_bio.read()
            if out_data:
                await stream.write_data(out_data)
            rem = max(0.5, deadline - time.monotonic())
            chunk = await stream.read_data(timeout=rem)
            if not chunk:
                return False, b""
            in_bio.write(chunk)
        except ssl.SSLWantWriteError:
            out_data = out_bio.read()
            if out_data:
                await stream.write_data(out_data)

    out_data = out_bio.read()
    if out_data:
        await stream.write_data(out_data)

    req = (
        f"GET {req_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: curl/8.5.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    ssl_obj.write(req)
    out_data = out_bio.read()
    if out_data:
        await stream.write_data(out_data)

    buf = bytearray()
    while len(buf) < read_limit and time.monotonic() < deadline:
        try:
            data = ssl_obj.read(4096)
            if not data:
                break
            buf.extend(data)
            if b"\r\n\r\n" in buf and read_limit <= 16384:
                break
        except ssl.SSLWantReadError:
            rem = max(0.5, deadline - time.monotonic())
            try:
                chunk = await stream.read_data(timeout=rem)
            except Exception:
                break
            if not chunk:
                break
            in_bio.write(chunk)
        except Exception:
            break
    return len(buf) > 0, bytes(buf)


async def speed_test_vless(
    addr: str,
    port: int,
    worker_host: str,
    path: str,
    user_uuid: str,
    speed_url: str,
    duration_s: int = 10,
    max_bytes_mb: int = 0,
    timeout: float = 12.0,
) -> dict:
    parsed = urlparse(speed_url)
    host = parsed.hostname or ""
    tport = parsed.port or (443 if parsed.scheme == "https" else 80)
    req_path = parsed.path or "/"
    if parsed.query:
        req_path += "?" + parsed.query

    stream = await open_vless_stream(addr, port, worker_host, path, user_uuid, host, tport, timeout)
    max_bytes = max_bytes_mb * 1024 * 1024 if max_bytes_mb > 0 else 0
    try:
        ctx = ssl.create_default_context() if parsed.scheme == "https" else None
        in_bio = ssl.MemoryBIO() if ctx else None
        out_bio = ssl.MemoryBIO() if ctx else None
        ssl_obj = ctx.wrap_bio(in_bio, out_bio, server_side=False, server_hostname=host) if ctx else None

        if ssl_obj is not None and in_bio is not None and out_bio is not None:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    out_data = out_bio.read()
                    if out_data:
                        await stream.write_data(out_data)
                    chunk = await stream.read_data(timeout=max(0.5, deadline - time.monotonic()))
                    if not chunk:
                        raise RuntimeError("TLS EOF")
                    in_bio.write(chunk)
            out_data = out_bio.read()
            if out_data:
                await stream.write_data(out_data)

        req = (
            f"GET {req_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: curl/8.5.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

        if ssl_obj is not None and out_bio is not None:
            ssl_obj.write(req)
            out_data = out_bio.read()
            if out_data:
                await stream.write_data(out_data)
        else:
            await stream.write_data(req)

        start = time.perf_counter()
        end_at = start + max(2, duration_s)
        total_bytes = 0
        buckets: list[int] = [0] * max(2, duration_s)

        while time.perf_counter() < end_at:
            if max_bytes and total_bytes >= max_bytes:
                break
            rem = max(0.2, end_at - time.perf_counter())
            try:
                chunk = await stream.read_data(timeout=min(3.0, rem))
            except asyncio.TimeoutError:
                continue
            if not chunk:
                break
            if ssl_obj is not None and in_bio is not None:
                in_bio.write(chunk)
                while True:
                    try:
                        plain = ssl_obj.read(65536)
                        if not plain:
                            break
                        n = len(plain)
                        total_bytes += n
                        sec = min(len(buckets) - 1, int(time.perf_counter() - start))
                        buckets[sec] += n
                    except ssl.SSLWantReadError:
                        break
            else:
                n = len(chunk)
                total_bytes += n
                sec = min(len(buckets) - 1, int(time.perf_counter() - start))
                buckets[sec] += n

        elapsed = max(0.1, time.perf_counter() - start)
        avg_mbps = (total_bytes * 8.0) / (elapsed * 1_000_000.0)
        sec_mbps = [(b * 8.0) / 1_000_000.0 for b in buckets if b > 0]
        peak_mbps = max(sec_mbps) if sec_mbps else avg_mbps
        tail_mbps = sec_mbps[-1] if sec_mbps else avg_mbps
        stability = 75.0 if avg_mbps > 0 else 0.0
        return {
            "ok": total_bytes > 0,
            "speed_mbps": round(avg_mbps, 1),
            "speed_peak_mbps": round(peak_mbps, 1),
            "speed_tail_mbps": round(tail_mbps, 1),
            "stability": stability,
            "speed_diag": "ok" if total_bytes > 0 else "zero_bytes",
        }
    finally:
        await stream.close()
