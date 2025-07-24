#!/usr/bin/env python3
import os
import re

RULE_DIR = "/var/ossec/ruleset/rules"

# Pola: cari rule dengan ID dan deskripsi mengandung brute force / login fail
rule_pattern = re.compile(
    r'<rule id="(?P<id>\d+)"[^>]*>.*?<description>(?P<desc>.*?)</description>',
    re.IGNORECASE | re.DOTALL
)

# Filter deskripsi yang mengandung kata kunci brute force
keywords = ["attacks","sql injection"]

found_rules = []

if not os.path.isdir(RULE_DIR):
    print(f"❌ Direktori tidak ditemukan: {RULE_DIR}")
    exit()

for filename in os.listdir(RULE_DIR):
    if filename.endswith(".xml"):
        filepath = os.path.join(RULE_DIR, filename)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for match in rule_pattern.finditer(content):
                rule_id = match.group("id")
                desc = match.group("desc").strip()
                if any(k.lower() in desc.lower() for k in keywords):
                    found_rules.append((rule_id, desc, filename))

# Tampilkan hasil
print("\n📋 Ditemukan rule brute-force:\n")
for rule_id, desc, source_file in sorted(found_rules, key=lambda x: int(x[0])):
    print(f"🆔 Rule ID: {rule_id}\n📄 File: {source_file}\n📝 Deskripsi: {desc}\n{'-'*60}")
