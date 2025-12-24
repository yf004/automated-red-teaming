#!/bin/bash

URL="https://resist-celebrity-peer-vitamins.trycloudflare.com/level2"

for i in {1..5}; do
  echo "Running scan $i..."
  uv run scanner-test1.py "$URL" > "level1_report${i}.md"
done
