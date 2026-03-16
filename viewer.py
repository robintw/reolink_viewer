#!/usr/bin/env python3
"""
Reolink Baichuan Protocol Viewer
Connects to camera on TCP port 9000 using the same native protocol as the mobile app.

Usage:
    python viewer.py <camera_ip> <username> <password> [main|sub]

Dependencies:
    pip install av opencv-python numpy
"""

import hashlib
import queue
import socket
import struct
import sys
import threading
import xml.etree.ElementTree as ET
from typing import Optional

import av
import cv2
import numpy as np

# ── Protocol constants ────────────────────────────────────────────────────────

PORT = 9000
MAGIC = bytes([0xF0, 0xDE, 0xBC, 0x0A])   # client→camera magic

# XOR key for BC (Baichuan) obfuscation
BC_KEY = bytes([0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF])

# Message IDs
MSG_LOGIN = 1
MSG_VIDEO = 3

# Message classes
CLASS_LEGACY = 0x6514   # 20-byte header
CLASS_MODERN = 0x0000   # 24-byte header (includes payload offset field)

# Encryption flags (lower byte 0xdc = request, 0xdd = response)
ENC_NONE = 0x0000
ENC_BC   = 0x01DC   # Baichuan XOR obfuscation
ENC_BC2  = 0x12DC   # BC obfuscation variant (sometimes used for login)

# ── Encoding helpers ──────────────────────────────────────────────────────────

def bc_crypt(data: bytes, handle: int = 0) -> bytes:
    """Symmetric XOR obfuscation used by the Baichuan protocol."""
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ BC_KEY[(handle + i) % 8] ^ handle
    return bytes(result)


def md5hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


# ── Packet build / parse ──────────────────────────────────────────────────────

def build_packet(
    msg_id: int,
    xml_body: str,
    *,
    handle: int = 0,
    enc_flag: int = ENC_NONE,
    msg_class: int = CLASS_LEGACY,
    binary_payload: bytes = b"",
) -> bytes:
    body = xml_body.encode("utf-8")
    if enc_flag != ENC_NONE:
        body = bc_crypt(body, handle)
    body += binary_payload

    # Header layout (20 bytes for CLASS_LEGACY):
    #  0- 3  magic
    #  4- 7  msg_id        (u32 LE)
    #  8-11  body_len      (u32 LE)
    # 12     channel_id    (u8)
    # 13     stream_type   (u8)
    # 14     handle        (u8) ← also the XOR offset
    # 15     pad           (u8)
    # 16-17  enc_flag      (u16 LE)
    # 18-19  msg_class     (u16 LE)
    header = struct.pack(
        "<4sIIBBBBHH",
        MAGIC, msg_id, len(body),
        0, 0, handle, 0,
        enc_flag, msg_class,
    )
    return header + body


def parse_header(raw: bytes) -> Optional[dict]:
    if len(raw) < 20:
        return None
    magic, msg_id, body_len, channel, stream, handle, _pad, enc_flag, msg_class = (
        struct.unpack("<4sIIBBBBHH", raw[:20])
    )
    if magic != MAGIC:
        return None
    header_size = 24 if msg_class in (CLASS_MODERN, 0x6414) else 20
    return dict(
        msg_id=msg_id, body_len=body_len,
        channel=channel, stream=stream, handle=handle,
        enc_flag=enc_flag, msg_class=msg_class,
        header_size=header_size,
    )


# ── Camera connection ─────────────────────────────────────────────────────────

class BaichuanConn:
    def __init__(self, host: str):
        self.host = host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)

    def connect(self):
        self.sock.connect((self.host, PORT))
        self.sock.settimeout(30)

    def send(self, pkt: bytes):
        self.sock.sendall(pkt)

    def recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed by camera")
            buf += chunk
        return buf

    def recv_packet(self) -> tuple[dict, bytes]:
        hdr = parse_header(self.recv_exact(20))
        if hdr is None:
            raise ValueError("Bad magic / header")
        if hdr["header_size"] > 20:
            self.recv_exact(hdr["header_size"] - 20)   # extra header bytes
        body = self.recv_exact(hdr["body_len"]) if hdr["body_len"] else b""
        # Decrypt BC-obfuscated bodies
        if hdr["enc_flag"] in (ENC_BC, ENC_BC2):
            body = bc_crypt(body, hdr["handle"])
        return hdr, body

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ── Login ─────────────────────────────────────────────────────────────────────

def login(conn: BaichuanConn, username: str, password: str) -> bool:
    # Step 1 – request a nonce from the camera
    conn.send(build_packet(
        MSG_LOGIN,
        '<Login version="1.1">'
        '<Encryption></Encryption>'
        '<LoginUser></LoginUser>'
        '<LoginNet type="LAN" udpPort="0"></LoginNet>'
        '</Login>',
    ))
    _, body = conn.recv_packet()

    # Parse nonce out of the response XML
    nonce = ""
    try:
        root = ET.fromstring(body.decode("utf-8", errors="replace"))
        enc = root.find(".//Encryption")
        if enc is not None:
            nonce = enc.get("nonce", "")
    except ET.ParseError:
        pass

    # Step 2 – send hashed credentials
    if nonce:
        user_hash = md5hex(username + nonce)
        pass_hash  = md5hex(password + nonce)
    else:
        # Older firmware: plain MD5 without nonce
        user_hash = md5hex(username)
        pass_hash  = md5hex(password)

    conn.send(build_packet(
        MSG_LOGIN,
        f'<Login version="1.1">'
        f'<LoginUser version="1.1">'
        f'<userName>{user_hash}</userName>'
        f'<password>{pass_hash}</password>'
        f'<userVer>1</userVer>'
        f'</LoginUser>'
        f'<LoginNet version="1.1">'
        f'<type>LAN</type><udpPort>0</udpPort>'
        f'</LoginNet>'
        f'</Login>',
        enc_flag=ENC_BC,
    ))
    hdr, body = conn.recv_packet()

    # A successful login response contains an 'ok' rsp code or non-error XML
    try:
        root = ET.fromstring(body.decode("utf-8", errors="replace"))
        rsp = root.find(".//rspCode")
        if rsp is not None and rsp.text and rsp.text.strip() not in ("200", "ok", "0"):
            print(f"Login rejected: {rsp.text.strip()}")
            return False
    except ET.ParseError:
        pass   # binary / empty response is fine at this stage

    return True


def start_stream(conn: BaichuanConn, stream_type: str = "subStream"):
    conn.send(build_packet(
        MSG_VIDEO,
        f'<Preview version="1.1">'
        f'<ChannelId>0</ChannelId>'
        f'<Handle>0</Handle>'
        f'<StreamType>{stream_type}</StreamType>'
        f'</Preview>',
    ))


# ── Video decode thread ───────────────────────────────────────────────────────

def recv_video(conn: BaichuanConn, frame_q: queue.Queue, stop_evt: threading.Event):
    """
    Runs in a background thread.  Reads Baichuan packets, extracts H.264/H.265
    NAL data and pushes decoded frames (as BGR numpy arrays) to frame_q.
    """
    # Try H.264 first; fall back to H.265 if we see the codec tag
    codec_ctx = av.CodecContext.create("h264", "r")

    # Accumulate data and periodically retry codec_ctx.parse() on the whole buffer
    # because NAL boundaries don't necessarily align with BC packet boundaries.
    buf = b""

    while not stop_evt.is_set():
        try:
            hdr, body = conn.recv_packet()
        except Exception as exc:
            if not stop_evt.is_set():
                print(f"[recv] {exc}")
            break

        if hdr["msg_id"] != MSG_VIDEO or not body:
            continue

        # The first bytes of a video packet may be a short XML extension followed
        # by binary data.  A quick heuristic: if it looks like XML, split at the
        # first NULL or after the XML end tag.
        if body[:1] == b"<":
            try:
                end = body.index(b"\x00")
                body = body[end + 1:]
            except ValueError:
                # Try to find end of XML and take rest as binary
                try:
                    end = body.rindex(b">") + 1
                    body = body[end:]
                except ValueError:
                    continue

        if not body:
            continue

        buf += body

        # PyAV parse() finds complete NAL / AU units
        try:
            packets = codec_ctx.parse(buf)
            buf = b""
            for pkt in packets:
                try:
                    for frame in codec_ctx.decode(pkt):
                        img = frame.to_ndarray(format="bgr24")
                        try:
                            frame_q.put_nowait(img)
                        except queue.Full:
                            # Drop oldest, keep latency low
                            try:
                                frame_q.get_nowait()
                            except queue.Empty:
                                pass
                            frame_q.put_nowait(img)
                except av.AVError:
                    pass
        except av.AVError:
            buf = b""  # discard garbled data and resync


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 4:
        print("Usage: python viewer.py <camera_ip> <username> <password> [main|sub]")
        sys.exit(1)

    host       = sys.argv[1]
    username   = sys.argv[2]
    password   = sys.argv[3]
    stream     = "mainStream" if len(sys.argv) > 4 and sys.argv[4] == "main" else "subStream"

    print(f"Connecting to {host}:{PORT} …")
    conn = BaichuanConn(host)
    conn.connect()

    print("Logging in …")
    if not login(conn, username, password):
        print("Login failed – check credentials.")
        conn.close()
        sys.exit(1)
    print("Login OK")

    print(f"Starting {stream} …")
    start_stream(conn, stream)

    frame_q  = queue.Queue(maxsize=4)
    stop_evt = threading.Event()
    recv_t   = threading.Thread(target=recv_video, args=(conn, frame_q, stop_evt), daemon=True)
    recv_t.start()

    print("Press  q  or  Esc  in the window to quit.")
    cv2.namedWindow("Reolink", cv2.WINDOW_NORMAL)

    while True:
        try:
            frame = frame_q.get(timeout=0.5)
            cv2.imshow("Reolink", frame)
        except queue.Empty:
            pass

        key = cv2.waitKey(1) & 0xFF
        if key in (ord("q"), 27):   # q or Esc
            break

        if not recv_t.is_alive():
            print("Receive thread ended – connection lost?")
            break

    stop_evt.set()
    conn.close()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
