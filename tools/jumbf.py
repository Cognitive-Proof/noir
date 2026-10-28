"""Minimal JPEG -> C2PA JUMBF parser (enough for the Noir-C2PA fixtures)."""
import struct
from dataclasses import dataclass, field


# Description-box content type of a C2PA Manifest Store ("c2pa" UUID)
C2PA_STORE_TYPE = b"c2pa" + bytes.fromhex("00110010800000aa00389b71")


def jumbf_from_jpeg(data: bytes) -> bytes:
    """Reassemble the C2PA Manifest Store from JPEG APP11 segments.

    APP11 segments are grouped by instance number (En); only a group whose
    superbox is a C2PA Manifest Store counts. Other JUMBF is ignored, and a
    file with more than one C2PA store is rejected rather than guessing which
    one a validator used.
    """
    pos, chunks = 2, {}
    assert data[:2] == b"\xff\xd8", "not a JPEG"
    while pos < len(data):
        marker, length = struct.unpack(">HH", data[pos:pos + 4])
        seg = data[pos + 4:pos + 2 + length]
        if marker == 0xFFEB and seg[:2] == b"JP":
            en, z = struct.unpack(">HI", seg[2:8])
            chunks.setdefault(en, []).append((z, seg[8:]))
        if marker == 0xFFDA:  # start of scan
            break
        pos += 2 + length
    stores = []
    for parts in chunks.values():
        parts = sorted(parts)
        # continuation segments repeat the 8-byte LBox/TBox header
        jumbf = parts[0][1] + b"".join(p[8:] for _, p in parts[1:])
        if jumbf[4:8] == b"jumb" and jumbf[12:16] == b"jumd" and jumbf[16:32] == C2PA_STORE_TYPE:
            stores.append(jumbf)
    assert stores, "no C2PA Manifest Store found"
    if len(stores) > 1:
        raise ValueError(f"{len(stores)} C2PA Manifest Stores in one file")
    return stores[0]


@dataclass
class Box:
    type: str
    offset: int          # offset of box header within the JUMBF buffer
    length: int
    label: str = ""
    content_type: bytes = b""
    children: list = field(default_factory=list)
    payload: bytes = b""

    @property
    def end(self):
        return self.offset + self.length


def parse_boxes(buf: bytes, start: int, end: int):
    out, pos = [], start
    while pos < end:
        lbox, tbox = struct.unpack(">I4s", buf[pos:pos + 8])
        hdr = 8
        if lbox == 1:
            lbox = struct.unpack(">Q", buf[pos + 8:pos + 16])[0]
            hdr = 16
        elif lbox == 0:
            lbox = end - pos
        box = Box(tbox.decode("latin1"), pos, lbox)
        body = buf[pos + hdr:pos + lbox]
        if box.type == "jumb":
            kids = parse_boxes(buf, pos + hdr, pos + lbox)
            desc = kids[0]
            assert desc.type == "jumd"
            box.content_type = desc.payload[:16]
            toggles = desc.payload[16]
            if toggles & 0x02:
                lab_end = desc.payload.index(b"\0", 17)
                box.label = desc.payload[17:lab_end].decode()
            box.children = kids
        else:
            box.payload = body
        out.append(box)
        pos += lbox
    return out


def walk(boxes, depth=0):
    for b in boxes:
        yield depth, b
        yield from walk(b.children, depth + 1)


def find(boxes, label):
    for _, b in walk(boxes):
        if b.label == label:
            return b
    return None
