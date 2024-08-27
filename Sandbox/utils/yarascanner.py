import yara
import os
import json
import sys 

sample_path = sys.argv[1]
sample_name = sys.argv[2]
rules_file = os.path.join(sample_path, 'rules.yar')
rules = yara.compile(filepath=rules_file)

def scan_file(filepath):
    try:
        matches = rules.match(filepath)
        results = {
            'file': filepath,
            'matches': [{'rule': match.rule} for match in matches]
        }
        return results
    except Exception as e:
        return {
            'file': filepath,
            'error': str(e)
        }

def save_report(results, output_file='yara-report.json'):
    with open(os.path.join(sample_path,output_file), 'w') as f:
        json.dump(results, f, indent=4)


scan_results = [scan_file(os.path.join(sample_path,sample_name))]
save_report(scan_results)
