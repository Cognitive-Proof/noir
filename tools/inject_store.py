"""Test helper: insert another file's C2PA store ahead of a JPEG's own.

Copies DONOR.jpg's APP11 (JUMBF) segments, renumbered to APP11 instance
0x0212, into TARGET.jpg just before its first APP11 segment. A verifier that
reads "the first JUMBF in the file" then inspects the donor's store, while a
C2PA validator may validate the target's.

--not-c2pa retypes the copied store's description box away from the C2PA
Manifest Store UUID, so C2PA validators ignore it (and validate the target's
store) while its contents still look like a manifest store.

usage: inject_store.py DONOR.jpg TARGET.jpg OUT.jpg [--not-c2pa]
"""
import struct
import sys


def segments(data):
    pos = 2
    while pos < len(data):
        marker, length = struct.unpack(">HH", data[pos:pos + 4])
        yield pos, marker, data[pos:pos + 2 + length]
        if marker == 0xFFDA:
            return
        pos += 2 + length


def copied_store(donor: bytes, not_c2pa: bool) -> bytes:
    """DONOR's APP11 segments as instance 0x0212, optionally retyped."""
    out = b""
    for _, marker, seg in segments(donor):
        if marker == 0xFFEB and seg[4:6] == b"JP":
            seg = seg[:6] + struct.pack(">H", 0x0212) + seg[8:]
            # marker, Le, CI, En, Z (12) + store LBox/TBox (8) + jumd LBox/TBox (8)
            if not_c2pa and seg[8:12] == b"\0\0\0\1":
                seg = seg[:28] + b"xxxx" + seg[32:]
            out += seg
    return out


if __name__ == "__main__":
    donor, target = (open(p, "rb").read() for p in sys.argv[1:3])
    first_app11 = next(pos for pos, marker, _ in segments(target) if marker == 0xFFEB)
    injected = copied_store(donor, "--not-c2pa" in sys.argv)
    open(sys.argv[3], "wb").write(target[:first_app11] + injected + target[first_app11:])
