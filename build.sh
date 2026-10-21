#!/bin/bash
# Builds the distributable kit into dist/
set -e
cd "$(dirname "$0")"
VERSION=${1:-1.0}
[ -f cis7.json ] || curl -sL -o cis7.json https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/compliance/m365/cis_7.0_m365.json
python3 build_catalogue.py && mkdir -p 2-Scripts/controls && cp out/2-Scripts/controls/cis-m365-v7-controls.json 2-Scripts/controls/
[ -d node_modules/docx ] || npm install --silent docx
node build_runbook.js && node build_report_template.js
python3 -c "import openpyxl" 2>/dev/null || pip3 install --quiet openpyxl
python3 build_templates.py
rm -rf dist && mkdir -p dist/kit
cp -r out/1-Runbook out/3-Templates out/4-Reference dist/kit/
mkdir -p dist/kit/2-Scripts/controls dist/kit/5-Worked-examples
cp 2-Scripts/*.ps1 dist/kit/2-Scripts/ && cp out/2-Scripts/controls/cis-m365-v7-controls.json dist/kit/2-Scripts/controls/

cp 5-Worked-examples/* dist/kit/5-Worked-examples/
cp README.txt CHANGELOG.txt dist/kit/
(cd dist/kit && zip -qr "../M365-CIS-v7-Review-Kit-v$VERSION.zip" .)
echo "built dist/M365-CIS-v7-Review-Kit-v$VERSION.zip"
