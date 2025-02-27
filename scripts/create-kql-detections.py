#!/usr/bin/env python3
import logging
import sys
from llama_index.core import SummaryIndex
from llama_index.readers.web import SimpleWebPageReader
import os

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

# --- Step 1: Summarize the blog ---
url = "https://medium.com/@0xHossam/powershell-exploits-modern-apts-and-their-malicious-scripting-tactics-7f98b0e8090c"
documents = SimpleWebPageReader(html_to_text=True).load_data([url])
index = SummaryIndex.from_documents(documents)
query_engine = index.as_query_engine()

# Query prompt instructs the model to produce a summary and 5 detection options.
text_summary = query_engine.query(
    'You are a Cyber Security expert with vast knowledge of detection engineering. '
    'I am an SOC Analyst and need help writing a Detection. First, consume threat intelligence '
    'from the following blog URL. Briefly summarize the blog in 5 sentences or less, then output '
    'five options for creating detections of adversary behavior using Sysmon with CommandLine data. '
    'These detections will use KQL for Azure Sentinel analytics rules. '
    'List the options as 1) ... 2) ... 3) ... 4) ... 5) ...'
)

# Print the summary and the detection options
print("=== Blog Summary & Detection Options ===")
print(text_summary)
print("==========================================")

# Save the summary to file
with open('summary.txt', "w", encoding="utf-8") as file:
    file.write(str(text_summary))
print("[+] Summary written to summary.txt")

# --- Step 2: Ask the user which detection option to build ---
option = input("Select the detection option you want to build (enter a number 1-5): ").strip()
if option not in ["1", "2", "3", "4", "5"]:
    print("Invalid selection. Exiting.")
    sys.exit(1)

# For this example, we'll simulate a mapping from option number to a KQL query snippet.
# In your real scenario, you might parse the summary or have predefined queries.
detection_kql_mapping = {
    "1": "SysmonEvent | where CommandLine contains 'EncodedCommand' and ProcessName == 'powershell.exe'",
    "2": "SysmonEvent | where ProcessCommandLine has 'Invoke-Expression' and Account != 'SYSTEM'",
    "3": "SysmonEvent | where CommandLine has 'Start-Process' and ProcessParent !in ('explorer.exe', 'wininit.exe')",
    "4": "SysmonEvent | where CommandLine matches regex '[A-Za-z0-9+/]{100,}'",
    "5": "SysmonEvent | where CommandLine contains 'DownloadString' and ProcessId != 0",
}

selected_detection_kql = detection_kql_mapping[option]

# --- Step 3: Create a new YAML detection file ---

# Read the KQL Sysmon parser lines from a file (e.g., 'kql_parser.txt')
# This file should contain the parser lines that set up parsing of the CommandLine field.
try:
    with open("Sysmon-AllVersions_Parser.txt", "r", encoding="utf-8") as f:
        kql_parser_lines = f.read().strip()
except FileNotFoundError:
    print("Error: 'kql_parser.txt' not found. Please provide the Sysmon parser KQL lines file.")
    sys.exit(1)

# Read the YAML template file which contains a placeholder {{QUERY}} for the KQL query.
try:
    with open("detection-template.yaml", "r", encoding="utf-8") as f:
        template_yaml = f.read()
except FileNotFoundError:
    print("Error: 'template.yaml' not found. Please provide a YAML template file for the detection rule.")
    sys.exit(1)

# Combine the parser lines with the selected detection query.
full_kql_query = kql_parser_lines + "\n\n" + selected_detection_kql

# Replace the placeholder in the YAML template with the full KQL query.
detection_yaml = template_yaml.replace("{{QUERY}}", full_kql_query)

# Write out the new detection YAML file.
output_yaml_file = "new_detection.yaml"
with open(output_yaml_file, "w", encoding="utf-8") as f:
    f.write(detection_yaml)

print(f"[+] New detection file created: {output_yaml_file}")
