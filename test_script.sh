#!/bin/bash
for i in {1..10}; do ./target/release/paton filesystem --config assets/config_faked.yaml --path ../ --omit ".git .rar .deb .DS_ .zip target .rpm .tgz .tar.gz .png"; done
