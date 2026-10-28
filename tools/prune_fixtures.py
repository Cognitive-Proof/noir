"""Write the pruning demo's ingredient images and manifest definitions.

Three ingredients with no AI (straight captures, no ingredients of their
own) plus one AI-generated ingredient used as a negative case.

usage: prune_fixtures.py OUT_DIR
Prints one line per ingredient: "<name> <signer>" for make_prune_fixtures.sh.
"""
import json
import os
import sys

from PIL import Image, ImageDraw

DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"

# name -> (signer, colour, actions)
INGREDIENTS = {
    "ingr-1": ("camera-a", (40, 90, 160), [
        {"action": "c2pa.created", "digitalSourceType": DST + "digitalCapture"},
    ]),
    "ingr-2": ("camera-b", (160, 60, 40), [
        {"action": "c2pa.created", "digitalSourceType": DST + "digitalCapture"},
        {"action": "c2pa.color_adjustments", "softwareAgent": {"name": "Darkroom 4"}},
    ]),
    "ingr-3": ("scanner", (40, 160, 90), [
        {"action": "c2pa.created", "digitalSourceType": DST + "negativeFilm"},
    ]),
    "ai-ingr": ("ai-tool", (90, 40, 160), [
        {"action": "c2pa.created", "digitalSourceType": DST + "trainedAlgorithmicMedia",
         "softwareAgent": {"name": "ImageGen 3"}},
    ]),
}


def manifest(name, signer, actions):
    return {
        "alg": "es256",
        "private_key": f"../../certs/signer-{signer}.key",
        "sign_cert": f"../../certs/signer-{signer}.chain.pem",
        "claim_generator_info": [{"name": "noir-c2pa-fixture", "version": "0.3.0"}],
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
for name, (signer, colour, actions) in INGREDIENTS.items():
    img = Image.new("RGB", (64, 48), colour)
    ImageDraw.Draw(img).ellipse([12, 8, 52, 40], fill=(240, 200, 60))
    img.save(f"{out}/src/{name}.jpg", quality=90)
    with open(f"{out}/manifests/{name}.json", "w") as f:
        json.dump(manifest(name, signer, actions), f, indent=2)
    print(name, signer)
