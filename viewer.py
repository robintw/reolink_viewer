#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "av",
#     "opencv-python",
#     "pycryptodomex",
# ]
# ///
"""
Reolink Baichuan Protocol Viewer
Connects to camera on TCP port 9000 using the same native protocol as the mobile app.

Usage:
    uv run viewer.py <camera_ip> <username> <password> [main|sub]
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
from Cryptodome.Cipher import AES

# ── Protocol constants ────────────────────────────────────────────────────────

PORT = 9000
MAGIC = bytes([0xF0, 0xDE, 0xBC, 0x0A])

# XOR key for BC (Baichuan) obfuscation
BC_KEY = bytes([0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF])
AES_IV = b"0123456789abcdef"

# Command IDs
CMD_LOGIN = 1
CMD_VIDEO = 3

# Message classes
CLASS_LEGACY = 0x6514   # 20-byte header (used for nonce request)
CLASS_MODERN = 0x6414   # 24-byte header with payload_offset (used for login + commands)

# Encryption flags (in legacy header enc_flag field)
ENC_BC2  = 0xDC12   # Baichuan XOR, used for nonce request
ENC_BC2R = 0xDD12   # BC2 response variant

# ── Encoding helpers ──────────────────────────────────────────────────────────

def bc_crypt(data: bytes, offset: int = 0) -> bytes:
    """Symmetric XOR obfuscation used by the Baichuan protocol."""
    offset = offset % 256
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ BC_KEY[(offset + i) % 8] ^ offset
    return bytes(result)


def md5_modern(s: str) -> str:
    """MD5 hash as used by modern Baichuan firmware: 31-char uppercase hex."""
    return hashlib.md5(s.encode()).hexdigest()[:31].upper()


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.encrypt(plaintext)


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.decrypt(ciphertext)


# ── Packet build / parse ──────────────────────────────────────────────────────

def build_legacy(cmd_id: int, body: bytes = b"", *, msg_id: int = 0,
                 enc_flag: int = ENC_BC2) -> bytes:
    """Build a 20-byte legacy header packet (class 0x6514)."""
    header = struct.pack("<4sIIIHH",
                         MAGIC, cmd_id, len(body), msg_id, enc_flag, CLASS_LEGACY)
    return header + body


def build_modern(cmd_id: int, body: bytes = b"", *, msg_id: int = 0,
                 extension: bytes = b"") -> bytes:
    """Build a 24-byte modern header packet (class 0x6414)."""
    payload = extension + body
    header = struct.pack("<4sIIIHHI",
                         MAGIC, cmd_id, len(payload), msg_id,
                         0, CLASS_MODERN, len(extension))
    return header + payload


def parse_header(raw: bytes) -> Optional[dict]:
    if len(raw) < 20:
        return None
    magic, cmd_id, body_len, msg_id, field16, msg_class = (
        struct.unpack("<4sIIIHH", raw[:20])
    )
    if magic != MAGIC:
        return None
    is_modern = msg_class in (0x0000, CLASS_MODERN, 0x6414)
    header_size = 24 if is_modern else 20
    return dict(
        cmd_id=cmd_id, body_len=body_len, msg_id=msg_id,
        enc_flag=field16,       # legacy: encryption type
        status_code=field16,    # modern: HTTP-style status (200=ok)
        msg_class=msg_class, header_size=header_size,
        is_modern=is_modern,
    )


# ── Camera connection ─────────────────────────────────────────────────────────

class BaichuanConn:
    def __init__(self, host: str):
        self.host = host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self._msg_seq = 0
        self.aes_key: Optional[bytes] = None

    def next_msg_id(self) -> int:
        self._msg_seq += 1
        return self._msg_seq

    def connect(self):
        self.sock.connect((self.host, PORT))
        self.sock.settimeout(30)

    def send(self, pkt: bytes):
        self.sock.sendall(pkt)

    def recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                raise ConnectionError("Timed out waiting for camera response")
            if not chunk:
                raise ConnectionError("Connection closed by camera")
            buf += chunk
        return buf

    def recv_packet(self) -> tuple[dict, bytes]:
        hdr = parse_header(self.recv_exact(20))
        if hdr is None:
            raise ValueError("Bad magic / header")
        payload_offset = 0
        if hdr["header_size"] > 20:
            extra = self.recv_exact(hdr["header_size"] - 20)
            payload_offset = struct.unpack("<I", extra[:4])[0]
        raw_body = self.recv_exact(hdr["body_len"]) if hdr["body_len"] else b""

        # Split extension and body
        extension = raw_body[:payload_offset]
        body = raw_body[payload_offset:]

        # Decrypt based on header type
        if not hdr["is_modern"]:
            # Legacy header: enc_flag tells us the encryption type
            if hdr["enc_flag"] in (ENC_BC2, ENC_BC2R):
                body = bc_crypt(body, hdr["msg_id"] % 256)
                if extension:
                    extension = bc_crypt(extension, hdr["msg_id"] % 256)
        elif self.aes_key:
            # Modern header: AES-decrypt extension (XML metadata)
            if extension:
                extension = aes_decrypt(extension, self.aes_key)
            # Body encryption is indicated by <encryptLen> in the extension XML.
            # Continuation packets (raw video/audio data) are NOT encrypted.
            encrypt_len = 0
            if extension:
                try:
                    ext_xml = extension.decode("utf-8", errors="replace").rstrip("\x00")
                    ext_root = ET.fromstring(ext_xml)
                    el = ext_root.find(".//encryptLen")
                    if el is not None and el.text:
                        encrypt_len = int(el.text)
                except Exception:
                    pass
            if encrypt_len > 0 and body:
                body = aes_decrypt(body[:encrypt_len], self.aes_key) + body[encrypt_len:]

        hdr["payload_offset"] = payload_offset
        hdr["_extension"] = extension
        return hdr, body

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ── Login ─────────────────────────────────────────────────────────────────────

def login(conn: BaichuanConn, username: str, password: str) -> bool:
    # Step 1 – request nonce: empty body, legacy header, ENC_BC2
    mid1 = conn.next_msg_id()
    conn.send(build_legacy(CMD_LOGIN, msg_id=mid1, enc_flag=ENC_BC2))

    hdr0, body = conn.recv_packet()
    if not body:
        return False

    # Parse nonce from response XML
    xml_str = body.decode("utf-8", errors="replace")
    nonce = ""
    try:
        root = ET.fromstring(xml_str)
        # Try attribute first, then element text
        enc = root.find(".//Encryption")
        if enc is not None:
            nonce = enc.get("nonce", "")
        if not nonce:
            nonce_el = root.find(".//nonce")
            if nonce_el is not None and nonce_el.text:
                nonce = nonce_el.text.strip()
    except ET.ParseError:
        pass

    if not nonce:
        return False

    # Derive AES key (will be set on conn only after successful login)
    aes_key_str = md5_modern(f"{nonce}-{password}")[:16]
    aes_key = aes_key_str.encode("utf-8")

    # Step 2 – send hashed credentials via BC2-encrypted modern packet
    user_hash = md5_modern(username + nonce)
    pass_hash = md5_modern(password + nonce)

    login_xml = (
        '<?xml version="1.0" encoding="UTF-8" ?>'
        '<body>'
        '<LoginUser version="1.1">'
        f'<userName>{user_hash}</userName>'
        f'<password>{pass_hash}</password>'
        '<userVer>1</userVer>'
        '</LoginUser>'
        '<LoginNet version="1.1">'
        '<type>LAN</type><udpPort>0</udpPort>'
        '</LoginNet>'
        '</body>'
    )
    # Login packet uses BC2 XOR encryption (not AES — AES is only after login)
    login_bytes = login_xml.encode("utf-8")
    mid2 = conn.next_msg_id()
    body_enc = bc_crypt(login_bytes, mid2 % 256)
    conn.send(build_modern(CMD_LOGIN, body_enc, msg_id=mid2))

    # Login response is also BC2-encrypted (AES key not active yet)
    hdr, raw_body = conn.recv_packet()
    if raw_body:
        body = bc_crypt(raw_body, hdr["msg_id"] % 256)
    else:
        body = b""

    if hdr.get("status_code") == 200:
        conn.aes_key = aes_key  # activate AES for all future packets
        return True

    return False


def start_stream(conn: BaichuanConn, stream_type: str = "subStream"):
    stream_xml = (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<body>\n'
        '<Preview version="1.1">\n'
        '<channelId>0</channelId>\n'
        '<handle>0</handle>\n'
        f'<streamType>{stream_type}</streamType>\n'
        '</Preview>\n'
        '</body>\n'
    )
    mid = conn.next_msg_id()
    body_enc = aes_encrypt(stream_xml.encode("utf-8"), conn.aes_key)
    conn.send(build_modern(CMD_VIDEO, body_enc, msg_id=mid))


# ── Video decode thread ───────────────────────────────────────────────────────

def recv_video(conn: BaichuanConn, frame_q: queue.Queue, stop_evt: threading.Event):
    """
    Runs in a background thread.  Reads Baichuan packets, extracts H.264/H.265
    NAL data and pushes decoded frames (as BGR numpy arrays) to frame_q.
    """
    codec_name = "h264"
    codec_ctx = None
    buf = b""

    while not stop_evt.is_set():
        try:
            hdr, body = conn.recv_packet()
        except Exception:
            break

        if not body or hdr["cmd_id"] != CMD_VIDEO:
            continue

        # Video body contains AVI-style binary chunks:
        #   "xxdc" + "H264"/"H265" + binary header + NAL data
        #   "xxwb" = audio (skip)
        #   Small unknown packets = metadata (skip)
        #   Large packets without chunk header = NAL continuation data

        if len(body) >= 4 and body[2:4] == b"wb":
            continue  # audio chunk

        if len(body) >= 8 and body[2:4] == b"dc":
            # Video chunk header — detect codec
            codec_tag = body[4:8]
            if codec_tag in (b"H265", b"H264"):
                new_codec = "hevc" if codec_tag == b"H265" else "h264"
                if new_codec != codec_name:
                    codec_name = new_codec
                    codec_ctx = None
            # Find NAL start code after chunk header
            idx = body.find(b"\x00\x00\x00\x01", 8)
            if idx >= 0:
                buf += body[idx:]
            elif len(body) > 16:
                buf += body[16:]  # skip header, hope for the best
        elif len(body) <= 64:
            continue  # small metadata packet, skip
        else:
            # Continuation data — pure NAL data
            buf += body

        if not codec_ctx and buf:
            codec_ctx = av.CodecContext.create(codec_name, "r")

        if codec_ctx and buf:
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
                                try:
                                    frame_q.get_nowait()
                                except queue.Empty:
                                    pass
                                frame_q.put_nowait(img)
                    except Exception:
                        pass
            except Exception:
                buf = b""


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 4:
        print("Usage: python viewer.py <camera_ip> <username> <password> [main|sub]")
        sys.exit(1)

    host       = sys.argv[1]
    username   = sys.argv[2]
    password   = sys.argv[3]
    stream     = "mainStream" if len(sys.argv) > 4 and sys.argv[4] == "main" else "subStream"

    conn = BaichuanConn(host)
    conn.connect()

    if not login(conn, username, password):
        print("Login failed – check credentials.")
        conn.close()
        sys.exit(1)

    start_stream(conn, stream)

    frame_q  = queue.Queue(maxsize=4)
    stop_evt = threading.Event()
    recv_t   = threading.Thread(target=recv_video, args=(conn, frame_q, stop_evt), daemon=True)
    recv_t.start()

    win_name = "Reolink"
    cv2.namedWindow(win_name, cv2.WINDOW_NORMAL)
    resized = False

    while True:
        try:
            frame = frame_q.get(timeout=0.5)
            if not resized:
                h, w = frame.shape[:2]
                win_w, win_h = w * 2, h * 2
                cv2.resizeWindow(win_name, win_w, win_h)
                cv2.moveWindow(win_name, 0, 0)
                resized = True
            cv2.imshow(win_name, frame)
        except queue.Empty:
            pass

        key = cv2.waitKey(1) & 0xFF
        if key in (ord("q"), 27):
            break
        if cv2.getWindowProperty(win_name, cv2.WND_PROP_VISIBLE) < 1:
            break
        if not recv_t.is_alive():
            break

    stop_evt.set()
    conn.close()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
