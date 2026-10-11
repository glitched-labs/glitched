"""
How each robot is pictured in the UI: a drawing from the library
(web_static/library) or the user's own photo, plus where each part sits on it.

Part positions are fractions of the picture's width and height, so they stay
put however large the picture is drawn. The library is 3D renders on a
transparent background (made by tools/render_library.py), each with its part
positions projected from the model;
an uploaded photo starts with none and the user places each part on it.
Photos stay on this computer (data_home()/robot-images); JPEG metadata such as
the GPS location a phone records is removed before saving.
"""

from __future__ import annotations

import functools
import json
import uuid
from pathlib import Path
from typing import Any

from psycopg2.extensions import cursor as Cursor
from psycopg2.extras import Json

from glitched.paths import data_home

LIBRARY_DIR = Path(__file__).resolve().parent / "web_static" / "library"
PARTS = ("network", "cloud_link", "main_controller", "debug_port", "peripherals")
MAX_IMAGE_BYTES = 8 * 1024 * 1024
IMAGE_TYPES = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}
DEFAULT_TEMPLATE = "wheeled"

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_visuals (
    device_id INT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('library', 'upload')),
    template TEXT,
    image_file TEXT,
    image_type TEXT,
    anchors JSONB NOT NULL DEFAULT '{}',
    labels JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


@functools.cache
def library() -> list[dict[str, Any]]:
    """
    The picture library, read once per process - like the UI's page files
    (glitched.web.load_static), so a running server's list and pictures always
    match each other, even after Glitched is updated on disk.
    """
    return json.loads((LIBRARY_DIR / "library.json").read_text())["templates"]


def template(template_id: str) -> dict[str, Any]:
    for t in library():
        if t["id"] == template_id:
            return t
    raise SystemExit(f"no picture called {template_id!r} in the library")


def default_template(platforms: list[str]) -> str:
    """A sensible first picture from the profile: Unitree -> quadruped, UR -> arm, ..."""
    for t in library():
        if set(t.get("platforms", [])) & set(platforms):
            return t["id"]
    return DEFAULT_TEMPLATE


def images_dir() -> Path:
    path = data_home() / "robot-images"
    path.mkdir(parents=True, exist_ok=True)
    return path


# --------------------------------------------------------------------------
# Reading and choosing
# --------------------------------------------------------------------------


def get(cur: Cursor, device_id: int, platforms: list[str]) -> dict[str, Any]:
    """The robot's picture; the profile's default library drawing if none was chosen."""
    cur.execute("SELECT source, template, image_type, anchors, labels, updated_at FROM device_visuals "
                "WHERE device_id = %s", (device_id,))
    row = cur.fetchone()
    if row is None:
        t = template(default_template(platforms))
        return {"source": "library", "template": t["id"], "anchors": t["anchors"], "labels": t["labels"],
                "chosen": False, "file": t["file"], "credit": t.get("credit")}
    source, template_id, image_type, anchors, labels, updated_at = row
    visual = {"source": source, "template": template_id, "anchors": anchors, "labels": labels, "chosen": True}
    if source == "library":
        try:
            t = template(template_id)
            visual.update(file=t["file"], credit=t.get("credit"))
        except SystemExit:  # a picture that's no longer in the library
            t = template(DEFAULT_TEMPLATE)
            visual.update(template=t["id"], file=t["file"], credit=t.get("credit"))
    if source == "upload":
        # The version in the URL makes the browser fetch a new photo after a re-upload.
        visual["image_version"] = int(updated_at.timestamp())
        visual["image_type"] = image_type
    return visual


def choose_template(cur: Cursor, device_id: int, template_id: str) -> None:
    t = template(template_id)
    old = _upload_file(cur, device_id)
    cur.execute(
        """INSERT INTO device_visuals (device_id, source, template, anchors, labels, updated_at)
           VALUES (%s, 'library', %s, %s, %s, now())
           ON CONFLICT (device_id) DO UPDATE SET source = 'library', template = EXCLUDED.template,
               image_file = NULL, image_type = NULL, anchors = EXCLUDED.anchors, labels = EXCLUDED.labels,
               updated_at = now()""",
        (device_id, t["id"], Json(t["anchors"]), Json(t["labels"])),
    )
    _remove(old)


def save_upload(cur: Cursor, device_id: int, data: bytes) -> None:
    """Store the user's photo for this robot. Parts start unplaced."""
    image_type = image_kind(data)
    if image_type is None:
        raise SystemExit("Upload a PNG, JPEG or WebP photo.")
    if len(data) > MAX_IMAGE_BYTES:
        raise SystemExit("That photo is larger than 8 MB - use a smaller one.")
    data = strip_metadata(data)
    name = f"{device_id}-{uuid.uuid4().hex[:12]}.{IMAGE_TYPES[image_type]}"
    (images_dir() / name).write_bytes(data)
    old = _upload_file(cur, device_id)
    cur.execute(
        """INSERT INTO device_visuals (device_id, source, image_file, image_type, anchors, labels, updated_at)
           VALUES (%s, 'upload', %s, %s, '{}', '{}', now())
           ON CONFLICT (device_id) DO UPDATE SET source = 'upload', template = NULL,
               image_file = EXCLUDED.image_file, image_type = EXCLUDED.image_type,
               anchors = '{}', labels = '{}', updated_at = now()""",
        (device_id, name, image_type),
    )
    _remove(old)


def set_anchors(cur: Cursor, device_id: int, platforms: list[str], anchors: dict, labels: dict) -> None:
    """Save where each part sits (fractions 0-1) and any renamed labels."""
    clean_anchors = {}
    for part, position in anchors.items():
        if part not in PARTS:
            raise SystemExit(f"unknown part {part!r}")
        if position is None:
            continue
        if (not isinstance(position, list) or len(position) != 2
                or not all(isinstance(v, (int, float)) and 0 <= v <= 1 for v in position)):
            raise SystemExit(f"{part}: a position is [x, y], each between 0 and 1")
        clean_anchors[part] = [round(float(position[0]), 4), round(float(position[1]), 4)]
    clean_labels = {}
    for part, label in labels.items():
        if part not in PARTS or not isinstance(label, str):
            raise SystemExit(f"bad label for {part!r}")
        if label.strip():
            clean_labels[part] = label.strip()[:40]
    current = get(cur, device_id, platforms)
    if not current["chosen"]:  # positions for the default drawing: save that choice too
        choose_template(cur, device_id, current["template"])
    cur.execute("UPDATE device_visuals SET anchors = %s, labels = %s, updated_at = now() WHERE device_id = %s",
                (Json(clean_anchors), Json(clean_labels), device_id))


def image(cur: Cursor, device_id: int) -> tuple[bytes, str]:
    cur.execute("SELECT image_file, image_type FROM device_visuals WHERE device_id = %s AND source = 'upload'",
                (device_id,))
    row = cur.fetchone()
    if row is None:
        raise SystemExit("this robot has no uploaded photo")
    path = images_dir() / Path(row[0]).name  # never a path from elsewhere
    try:
        return path.read_bytes(), row[1]
    except OSError:
        raise SystemExit("the photo file is missing - upload it again") from None


def _upload_file(cur: Cursor, device_id: int) -> str | None:
    cur.execute("SELECT image_file FROM device_visuals WHERE device_id = %s", (device_id,))
    row = cur.fetchone()
    return row[0] if row else None


def _remove(name: str | None) -> None:
    if name:
        (images_dir() / Path(name).name).unlink(missing_ok=True)


# --------------------------------------------------------------------------
# Image checks
# --------------------------------------------------------------------------


def image_kind(data: bytes) -> str | None:
    """The image type from its first bytes - never from the file name or the browser's say-so."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def strip_jpeg_metadata(data: bytes) -> bytes:
    """
    Drop the APP1 (EXIF/XMP, incl. GPS) and comment segments from a JPEG,
    keeping everything the image needs. Returns the input unchanged if the
    file doesn't parse as expected.
    """
    if not data.startswith(b"\xff\xd8"):
        return data
    out = bytearray(b"\xff\xd8")
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            return data
        marker = data[i + 1]
        if marker == 0xDA:  # start of scan: the rest is image data
            out += data[i:]
            return bytes(out)
        if marker == 0xD8 or 0xD0 <= marker <= 0xD7 or marker == 0x01:  # no length field
            out += data[i:i + 2]
            i += 2
            continue
        length = int.from_bytes(data[i + 2:i + 4], "big")
        if length < 2 or i + 2 + length > len(data):
            return data
        if marker not in (0xE1, 0xFE):  # APP1 = EXIF/XMP, COM = comment
            out += data[i:i + 2 + length]
        i += 2 + length
    return data


# PNG chunks that carry text or metadata (comments, camera data, EXIF incl. GPS, timestamps).
PNG_METADATA_CHUNKS = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}


def strip_png_metadata(data: bytes) -> bytes:
    """Drop PNG text/EXIF/time chunks, keeping the image. Returns the input unchanged if it doesn't parse."""
    signature = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(signature):
        return data
    out = bytearray(signature)
    i = len(signature)
    while i + 12 <= len(data):
        length = int.from_bytes(data[i:i + 4], "big")
        kind = data[i + 4:i + 8]
        end = i + 12 + length
        if end > len(data):
            return data
        if kind not in PNG_METADATA_CHUNKS:
            out += data[i:end]
        i = end
        if kind == b"IEND":
            return bytes(out)
    return data


def strip_webp_metadata(data: bytes) -> bytes:
    """Drop WebP EXIF and XMP chunks (and clear their flags), keeping the image. Unchanged if it doesn't parse."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return data
    if int.from_bytes(data[4:8], "little") + 8 != len(data):
        return data  # truncated or padded: not what it says it is
    chunks = bytearray()
    i = 12
    while i + 8 <= len(data):
        kind = data[i:i + 4]
        length = int.from_bytes(data[i + 4:i + 8], "little")
        end = i + 8 + length + (length & 1)  # chunks are padded to an even length
        if i + 8 + length > len(data):
            return data
        chunk = bytearray(data[i:min(end, len(data))])
        if kind == b"VP8X" and length >= 1:
            chunk[8] &= ~0x0C & 0xFF  # clear the EXIF (0x08) and XMP (0x04) flags
        if kind not in (b"EXIF", b"XMP "):
            chunks += chunk
        i = end
    return b"RIFF" + (len(chunks) + 4).to_bytes(4, "little") + b"WEBP" + bytes(chunks)


def strip_metadata(data: bytes) -> bytes:
    """Remove location and other metadata from a PNG, JPEG or WebP photo."""
    kind = image_kind(data)
    if kind == "image/jpeg":
        return strip_jpeg_metadata(data)
    if kind == "image/png":
        return strip_png_metadata(data)
    if kind == "image/webp":
        return strip_webp_metadata(data)
    return data
