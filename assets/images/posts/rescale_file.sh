#!/bin/bash
echo "Resizing " $1
convert $1 -resize 50% $1_resized
