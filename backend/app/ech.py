from __future__ import annotations

import base64
import struct
import httpx


def _build_dns_query(domain: str, qtype: int = 65) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode("ascii")
        for part in domain.strip(".").split(".")
        if part
    ) + b"\x00"
    question = labels + struct.pack(">HH", qtype, 1)
    return header + question


def _skip_dns_name(buf: bytes, offset: int) -> int:
    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _extract_ech_from_https_rdata(rdata: bytes) -> str:
    if len(rdata) < 3:
        return ""
    offset = 2  # priority
    offset = _skip_dns_name(rdata, offset)
    while offset + 4 <= len(rdata):
        key, val_len = struct.unpack(">HH", rdata[offset:offset + 4])
        offset += 4
        if offset + val_len > len(rdata):
            break
        val = rdata[offset:offset + val_len]
        offset += val_len
        if key == 5 and val:  # SvcParamKey 5 = ech
            return base64.b64encode(val).decode("ascii")
    return ""


def _parse_dns_response(pkt: bytes) -> str:
    if len(pkt) < 12:
        return ""
    _, _, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", pkt[:12])
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(pkt, offset) + 4
    for _ in range(ancount):
        if offset >= len(pkt):
            break
        offset = _skip_dns_name(pkt, offset)
        if offset + 10 > len(pkt):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", pkt[offset:offset + 10])
        offset += 10
        if offset + rdlen > len(pkt):
            break
        rdata = pkt[offset:offset + rdlen]
        offset += rdlen
        if rtype == 65:  # HTTPS RR
            ech = _extract_ech_from_https_rdata(rdata)
            if ech:
                return ech
    return ""


async def fetch_ech_config_list(doh_url: str, domain: str, timeout: float = 10.0) -> str:
    if not doh_url or not domain:
        return ""
    query = _build_dns_query(domain, 65)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            doh_url,
            content=query,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
        )
        resp.raise_for_status()
        return _parse_dns_response(resp.content)
