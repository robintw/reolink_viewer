# Reolink Baichuan Protocol Viewer

A Python application that streams video directly from Reolink IP cameras using the proprietary Baichuan protocol (TCP port 9000) — the same native protocol used by Reolink's mobile app. This bypasses the slower RTSP implementation for lower-latency live video, and works with cameras that don't expose ONVIF or RTSP (e.g. some B800 models).

It has very limited functionality: it will display a video stream, and that is it. It won't convert to other formats, take snapshots or anything else.

Most of this code was written by Claude Opus 4.6, so please bear that in mind. It works for me, with my Reolink cameras, but hasn't been tested on a broader range of cameras. It shouldn't do anything dangerous, but please review the code if you are concerned.

## Requirements

- Python 3.10+
- A Reolink camera accessible on your network

## Installation

### Using uv (recommended)

No installation step needed, as `uv run` handles dependencies automatically via the inline script metadata in `viewer.py`:

```bash
uv run viewer.py <IP address> <username> <password>
```

To install `uv` itself, see [docs.astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/).

### Using pip

```bash
pip install -r requirements.txt
```

## Usage

### Live Viewer

```bash
python viewer.py <camera_ip> <username> <password> [main|sub]
```

- `main` — full-resolution stream
- `sub` — lower-resolution stream (default, lower latency)

Example:

```bash
python viewer.py 192.168.1.100 admin mypassword sub
```

Press **q** or **Esc** to exit the viewer window.

### Acknowledgments
- [reolink_aio](https://github.com/starkillerOG/reolink_aio) was useful for understanding authentication, but doesn't provide access to streamed video directly
