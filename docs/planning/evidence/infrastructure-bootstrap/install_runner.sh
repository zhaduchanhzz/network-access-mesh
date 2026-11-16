#!/bin/bash
# Install the GitHub Actions runner on mg-ci-runner WITHOUT registering it (P0-T07, persistent mode chosen by the
# owner on 2026-11-16). Registration needs a one-time token and is a separate step.
# The tarball is checked against the SHA-256 published in the release notes of actions/runner.
# Undo: sudo /opt/actions-runner/svc.sh uninstall (if installed); sudo rm -rf /opt/actions-runner; sudo userdel -r ghrunner
set -euo pipefail
VER="2.338.2"
SHA="baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40"
DIR=/opt/actions-runner

if [ -x "$DIR/bin/Runner.Listener" ]; then echo "runner already installed: $("$DIR/bin/Runner.Listener" --version)"; exit 0; fi
id ghrunner >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir /home/ghrunner --shell /usr/sbin/nologin ghrunner
sudo usermod -aG docker ghrunner     # container jobs and docker build; docker group == root on this dedicated VM (R-28)
sudo install -d -o ghrunner -g ghrunner -m 0750 "$DIR"
tmp=$(mktemp)
curl -fsSL -o "$tmp" "https://github.com/actions/runner/releases/download/v${VER}/actions-runner-linux-x64-${VER}.tar.gz"
echo "${SHA}  ${tmp}" | sha256sum -c --status || { echo "checksum MISMATCH — aborting"; rm -f "$tmp"; exit 1; }
echo "tarball sha256 OK"
sudo tar -xzf "$tmp" -C "$DIR"
rm -f "$tmp"
sudo chown -R ghrunner:ghrunner "$DIR"
sudo "$DIR/bin/installdependencies.sh" 2>&1 | tail -1
echo "runner $(sudo -u ghrunner "$DIR/bin/Runner.Listener" --version) installed in $DIR — not registered"
id ghrunner
