#!/usr/bin/python3

import os

png_ext = ".png"
jpg_ext = ".jpg"
avif_ext = ".avif"

for filename in os.listdir("."):
    if not (filename.endswith(png_ext) or filename.endswith(jpg_ext)):
        continue
    print(filename)
    if png_ext in filename:
        basename = filename.removesuffix(png_ext)
    elif jpg_ext in filename:
        basename = filename.removesuffix(jpg_ext)

    avifname = basename + avif_ext
    os.system(f'magick {filename} {avifname}')
    os.system(f'convert {avifname} -resize 1024x\> {avifname}')
