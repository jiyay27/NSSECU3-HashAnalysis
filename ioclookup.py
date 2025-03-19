import os
import requests
import pandas as pd
import csv
import time
from datetime import datetime, timezone

API_KEYS = [
    "60813ac8842a5083a18fa5850cc4085fd4871a1158c77b78bf7af7e89c1371bc",
    "6faa0213eefabfc356f44156f81791ec98cc68fdc9b1c277a17dea976f0af88f",
    "0b8165a081704eae088a9151f2281f8c23673c9e23b754290f644c6a38da78f2"
]

CURRENT_KEY_INDEX = 0

VT_URL = "https://www.virustotal.com/api/v3/files/{}"

def get_next_api_key():
    """Switch to the next API key when the rate limit is hit."""
    global CURRENT_KEY_INDEX
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(API_KEYS)
    return API_KEYS[CURRENT_KEY_INDEX]

# Load hashes from Excel file
input_file = "hashes.xlsx"
df = pd.read_excel(input_file, header=0, usecols="A")

# Ensure the column name is correct (adjust if needed)
hash_column = "Hashes"  # Update if your column has a different name

# Set scan range
# Done with:
# 1 - 15        ✅
# 15 - 433      ✅
# 433 - 490     ✅
# 490 - 1000    ❌
# 1500 - 1648   ❌
hashes = df.iloc[490:1000, 0].dropna().tolist()

# Output CSV file
output_file = "hash_analysis.csv"
columns = [
    "File_Hash", "Detection_Count", "Hash-MD5", "Hash-SHA1", "Hash-SHA256", "File_Type", "Magic",
    "Creation_Time", "Signature_Date", "First_Seen", "First_Submission", "Last_Submission", "Last_Analysis",
    "Name1", "Name2", "Name3", "Verdict"
]

def convert_time(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(timestamp, int) else "N/A"

# Function to query VirusTotal
def query_virustotal(file_hash):
    global CURRENT_KEY_INDEX
    for _ in range(len(API_KEYS)):  # Try all API keys before failing
        api_key = API_KEYS[CURRENT_KEY_INDEX]
        headers = {"x-apikey": api_key}
        
        response = requests.get(VT_URL.format(file_hash), headers=headers)

    if response.status_code == 200:
        data = response.json().get("data", {}).get("attributes", {})
        
        # Extract relevant fields
        hash = file_hash
        detection_count = data.get("last_analysis_stats", {}).get("malicious", 0)
        md5 = data.get("md5", "N/A")
        sha1 = data.get("sha1", "N/A")
        sha256 = data.get("sha256", "N/A")
        file_type = data.get("type_description", "N/A")
        magic = data.get("magic", "N/A")
        creation_time = convert_time(data.get("creation_date", "N/A"))
        signature_date = convert_time(data.get("signature_date", "N/A"))
        first_seen = convert_time(data.get("first_seen_itw_date", "N/A"))
        first_submission = convert_time(data.get("first_submission_date", "N/A"))
        last_submission = convert_time(data.get("last_submission_date", "N/A"))
        last_analysis = convert_time(data.get("last_analysis_date", "N/A"))
        
        # Extract top 3 names (or "N/A" if fewer than 3 names exist)
        names = data.get("names", [])
        name1, name2, name3 = (names + ["N/A"] * 3)[:3]
        
        # Simple verdict
        verdict = "Malicious" if isinstance(detection_count, int) and detection_count > 5 else "Benign"
        
        return [
            hash, detection_count, md5, sha1, sha256, file_type, magic,
            creation_time, signature_date, first_seen, first_submission, last_submission, last_analysis,
            name1, name2, name3, verdict
        ]
    
    elif response.status_code == 429:
            print(f"Rate limit exceeded for API key {api_key}, switching keys...")
            api_key = get_next_api_key()
            time.sleep(3)  # Short delay before retrying
            query_virustotal(file_hash)

    else:
        print(f"Error fetching data for {file_hash}")
    
    return [file_hash] + ["N/A"] * (len(columns) - 1)



# Check if file exists
file_exists = os.path.isfile(output_file)
file_mode = "a" if file_exists else "w"  # Use "a" if the file exists, otherwise "w"

# Process hashes and write/append to CSV
with open(output_file, file_mode, newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)

    if not file_exists:
        writer.writerow(columns)

    for file_hash in hashes:
        print(f"Processing {file_hash}...")
        result = query_virustotal(file_hash)
        writer.writerow(result)
        time.sleep(15)  # Prevent API rate limiting

print(f"Analysis complete. Results saved to {output_file}")
