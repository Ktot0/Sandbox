import subprocess
import os
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

def analyze_memory_dump(volatility_path, dump_path):
    plugins = [
        'windows.pslist.PsList',       # List processes
        'windows.pstree.PsTree',       # Process tree
        'windows.dlllist.DllList',     # List loaded DLLs
        'windows.handles.Handles',     # List handles
        'windows.malfind.Malfind'      # Detect injected code
    ]
    
    results = {}
    
    for plugin in plugins:
        command = f'python {volatility_path}/vol.py -r json -f {dump_path}/postexec {plugin}'
        print(f'Executing command: {command}')
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f'Error executing Volatility command for plugin {plugin}:', result.stderr)
        else:
            results[plugin] = json.loads(result.stdout)
    
    return results

def generate_report(analysis_results, sample_report_path):
    report_path = os.path.join(sample_report_path, 'volatility-report.json')
    with open(report_path, 'w') as f:
        json.dump(analysis_results, f, indent=4)
    return report_path

def run(sample_report_path):
    volatility_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'volatility3'))
    dump_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'memdump'))
    if os.path.exists(volatility_path):
        analysis_results = analyze_memory_dump(volatility_path, dump_path)
        if analysis_results:
            report_path = generate_report(analysis_results, sample_report_path)
            return f'Report generated: {report_path}'
        else:
            return 'No analysis result generated.'
    else:
        return 'Volatility3 is not installed.'




