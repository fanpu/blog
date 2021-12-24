#!/bin/bash
echo "Resizing " $1
convert $1 -resize 1920x $1_resized
