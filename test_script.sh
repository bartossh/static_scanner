#!/bin/bash
for i in {1..100}; do ./target/release/paton filesystem --config ./assets/config_faked.yaml --path ../expired-creds; done
