#!/usr/bin/env bash

set -euxo pipefail

nix build
sudo ./result/bin/main.py