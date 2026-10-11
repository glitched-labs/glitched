"""
Robot pictures (glitched.visuals): the drawing library, upload checks and
removing location metadata from JPEG photos. No database needed.
"""

import struct
import unittest

from glitched import visuals


def segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


JFIF = segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
EXIF = segment(0xE1, b"Exif\x00\x00" + b"GPSLatitude 52.3676 GPSLongitude 4.9041")
COMMENT = segment(0xFE, b"taken in the lab at home")
QUANT = segment(0xDB, b"\x00" + bytes(range(64)))
SCAN = segment(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x12\x34\xff\x00\x56" + b"\xff\xd9"
PHOTO = b"\xff\xd8" + JFIF + EXIF + COMMENT + QUANT + SCAN


class JpegMetadataTest(unittest.TestCase):
    def test_location_and_comments_are_removed(self):
        clean = visuals.strip_jpeg_metadata(PHOTO)
        self.assertNotIn(b"GPS", clean)
        self.assertNotIn(b"lab at home", clean)

    def test_the_image_itself_is_kept(self):
        clean = visuals.strip_jpeg_metadata(PHOTO)
        self.assertEqual(clean, b"\xff\xd8" + JFIF + QUANT + SCAN)

    def test_unparseable_files_are_left_alone(self):
        broken = b"\xff\xd8" + b"\xff\xe1\x00"  # truncated segment
        self.assertEqual(visuals.strip_jpeg_metadata(broken), broken)


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    import zlib
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))


PNG = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
       + png_chunk(b"tEXt", b"Comment\x00taken at home") + png_chunk(b"eXIf", b"MM\x00*GPSLatitude")
       + png_chunk(b"IDAT", b"\x78\x9c\x63\x60\x00\x00\x00\x02\x00\x01") + png_chunk(b"IEND", b""))


def webp_chunk(kind: bytes, payload: bytes) -> bytes:
    return kind + struct.pack("<I", len(payload)) + payload + (b"\x00" if len(payload) % 2 else b"")


WEBP_BODY = (webp_chunk(b"VP8X", bytes([0x0C, 0, 0, 0]) + b"\x00" * 6) + webp_chunk(b"VP8 ", b"frame")
             + webp_chunk(b"EXIF", b"GPSLatitude 52.3") + webp_chunk(b"XMP ", b"<x:xmpmeta>home</x:xmpmeta>"))
WEBP = b"RIFF" + struct.pack("<I", len(WEBP_BODY) + 4) + b"WEBP" + WEBP_BODY


class PngWebpMetadataTest(unittest.TestCase):
    def test_png_text_and_exif_are_removed(self):
        clean = visuals.strip_metadata(PNG)
        self.assertNotIn(b"taken at home", clean)
        self.assertNotIn(b"GPS", clean)
        for kind in (b"IHDR", b"IDAT", b"IEND"):
            self.assertIn(kind, clean)
        self.assertEqual(visuals.image_kind(clean), "image/png")

    def test_webp_exif_and_xmp_are_removed(self):
        clean = visuals.strip_metadata(WEBP)
        self.assertNotIn(b"GPS", clean)
        self.assertNotIn(b"home", clean)
        self.assertIn(b"VP8 ", clean)
        self.assertEqual(struct.unpack("<I", clean[4:8])[0], len(clean) - 8)  # RIFF size still right
        self.assertEqual(clean[20] & 0x0C, 0)  # EXIF/XMP flags cleared

    def test_broken_files_are_left_alone(self):
        self.assertEqual(visuals.strip_metadata(PNG[:40]), PNG[:40])
        self.assertEqual(visuals.strip_metadata(WEBP[:30]), WEBP[:30])


class ImageKindTest(unittest.TestCase):
    def test_kinds_come_from_the_bytes(self):
        self.assertEqual(visuals.image_kind(b"\x89PNG\r\n\x1a\n...."), "image/png")
        self.assertEqual(visuals.image_kind(PHOTO), "image/jpeg")
        self.assertEqual(visuals.image_kind(b"RIFF\x00\x00\x00\x00WEBPVP8 "), "image/webp")

    def test_svg_and_others_are_refused(self):
        for data in (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
                     b"GIF89a...", b"<html>", b""):
            self.assertIsNone(visuals.image_kind(data), data[:10])


class LibraryTest(unittest.TestCase):
    def test_every_picture_is_a_transparent_render_that_places_every_part(self):
        templates = visuals.library()
        self.assertGreaterEqual(len(templates), 6)
        for t in templates:
            data = (visuals.LIBRARY_DIR / t["file"]).read_bytes()
            self.assertEqual(visuals.image_kind(data), "image/png", t["file"])
            self.assertEqual(data[25], 6, f"{t['file']} has no alpha channel")  # PNG colour type 6 = RGBA
            self.assertLess(len(data), 700_000, f"{t['file']} is too big")
            self.assertEqual(set(t["anchors"]), set(visuals.PARTS), t["id"])
            self.assertEqual(set(t["labels"]), set(visuals.PARTS), t["id"])
            for part, (x, y) in t["anchors"].items():
                self.assertTrue(0.03 <= x <= 0.97 and 0.03 <= y <= 0.97, (t["id"], part))

    def test_library_is_read_once_per_process(self):
        # It must match the page files the UI server loaded at start-up, not whatever is on disk later.
        self.assertIs(visuals.library(), visuals.library())

    def test_every_library_picture_is_served_by_the_ui(self):
        from glitched import web
        static = web.load_static()
        for t in visuals.library():
            self.assertIn(f"library/{t['file']}", static, t["id"])

    def test_default_picture_follows_the_platform(self):
        self.assertEqual(visuals.default_template(["unitree"]), "quadruped")
        self.assertEqual(visuals.default_template(["universal-robots"]), "arm")
        self.assertEqual(visuals.default_template([]), visuals.DEFAULT_TEMPLATE)
        self.assertTrue((visuals.LIBRARY_DIR / visuals.template(visuals.DEFAULT_TEMPLATE)["file"]).is_file())


if __name__ == "__main__":
    unittest.main()
