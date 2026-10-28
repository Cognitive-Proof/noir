"""Write the batch demo's source images and manifest definitions.

usage: batch_fixtures.py OUT_DIR
Prints one line per image: "<name> <signer-or-'-'>" for make_batch_fixtures.sh.
"""
import json
import os
import sys

from PIL import Image, ImageDraw

DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"

CAPTURE = {"action": "c2pa.created", "digitalSourceType": DST + "digitalCapture"}

# name -> (signer, colour, actions); signer None means no manifest at all
IMAGES = {
    "camera-a": ("camera-a", (40, 90, 160), [CAPTURE]),
    "camera-b": ("camera-b", (160, 60, 40), [
        CAPTURE,
        {"action": "c2pa.color_adjustments", "softwareAgent": {"name": "Darkroom 4"}},
    ]),
    "ai-gen": ("ai-tool", (90, 40, 160), [
        {"action": "c2pa.created", "digitalSourceType": DST + "trainedAlgorithmicMedia",
         "softwareAgent": {"name": "ImageGen 3"}},
    ]),
    "ai-edit": ("camera-a", (40, 160, 90), [
        CAPTURE,
        {"action": "c2pa.edited",
         "digitalSourceType": DST + "compositeWithTrainedAlgorithmicMedia",
         "softwareAgent": {"name": "GenFill 2"}},
    ]),
    "rogue": ("rogue", (200, 200, 60), [CAPTURE]),
    "plain": (None, (120, 120, 120), None),
}


def manifest(name, signer, actions):
    return {
        "alg": "es256",
        "private_key": f"../../certs/signer-{signer}.key",
        "sign_cert": f"../../certs/signer-{signer}.chain.pem",
        "claim_generator_info": [{"name": "noir-c2pa-fixture", "version": "0.2.0"}],
        "title": f"{name}.jpg",
        "assertions": [
            {"label": "c2pa.actions.v2", "data": {"actions": actions}},
            {"label": "stds.exif", "data": {
                "@context": {"exif": "http://ns.adobe.com/exif/1.0/",
                             "dc": "http://purl.org/dc/elements/1.1/"},
                "exif:GPSLatitude": "39,21.102N",
                "exif:GPSLongitude": "74,26.5737W",
                "dc:creator": [f"Photographer of {name}"],
            }},
        ],
    }


out = sys.argv[1]
os.makedirs(f"{out}/src", exist_ok=True)
os.makedirs(f"{out}/manifests", exist_ok=True)
for name, (signer, colour, actions) in IMAGES.items():
    img = Image.new("RGB", (64, 48), colour)
    ImageDraw.Draw(img).rectangle([10, 10, 40, 30], fill=(240, 200, 60))
    img.save(f"{out}/src/{name}.jpg", quality=90)
    if signer:
        with open(f"{out}/manifests/{name}.json", "w") as f:
            json.dump(manifest(name, signer, actions), f, indent=2)
    print(name, signer or "-")
