import subprocess
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

def analyze_memory_dump(volatility_path, dump_path):
    command = f'python {volatility_path}/vol.py -r json -f {dump_path}/postexec windows.pslist.PsList'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print('Error executing Volatility command:', result.stderr)
        return ''
    return result.stdout

def generate_report(analysis_result, sample_report_path):
    report_path = sample_report_path + '/volatility-report.json'
    with open(report_path, 'w') as f:
        f.write(analysis_result)
    return report_path

def run(sample_report_path):
    volatility_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'volatility3'))
    dump_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'memdump'))
    if os.path.exists(volatility_path):
        analysis_result = analyze_memory_dump(volatility_path, dump_path)
        if analysis_result:
            report_path = generate_report(analysis_result, sample_report_path)
            return f'Report generated: {report_path}'
        else:
            return 'No analysis result generated.'
    else:
        return 'Volatility3 is not installed.'

