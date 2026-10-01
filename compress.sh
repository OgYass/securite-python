#!/bin/sh

zip -r ./out/projet.zip . -x '.venv/*' '*__pycache__*' '.idea/*' '.vscode/*' '.*_cache/*' 'sample.pcap'
