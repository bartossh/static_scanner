#!/bin/bash
for i in {1..10}; do ./target/release/rogue filesystem --config assets/config.yaml --path ../ --omit ".git .rar .deb .DS_ .zip target .rpm .tgz .tar.gz .png .dll --nodeps --dedup"; done
