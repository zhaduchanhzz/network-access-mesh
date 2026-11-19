#!/bin/bash
# đẩy script dep4x vào /root/dep4x của host lồng
set -e
for f in "$@"; do sudo install -m 0700 "$HOME/dep4/$f" "$HOME/dep4/root/rootdir/dep4x/$f"; done
