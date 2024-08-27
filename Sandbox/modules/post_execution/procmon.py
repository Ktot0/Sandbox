import xml.etree.ElementTree as ET
import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from database import Database

def categorize_event(operation):
    if 'Reg' in operation:
        return 'Registry'
    elif 'File' in operation:
        return 'File'
    elif 'Network' in operation:
        return 'Network'
    else:
        return 'Others'

def run(sample_report_path):
    db = Database()
    target_process_name = db.get_value('running',1,'file_name')
    xml_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'memdump/procmonlog.xml'))
    json_file = sample_report_path + '/procmon-report.json'
    
    tree = ET.parse(xml_file)
    root = tree.getroot()

    processes = {}
    events = []

    process_list = root.find('processlist')
    if process_list is not None:
        for process in process_list.findall('process'):
            process_name = process.find('ProcessName')
            process_id = process.find('ProcessId')
            if process_name is not None and process_id is not None:
                processes[process_id.text] = process_name.text

    event_list = root.find('eventlist')
    if event_list is not None:
        for event in event_list.findall('event'):
            process_name = event.find('Process_Name')
            if process_name is not None and process_name.text == target_process_name:
                event_details = {
                    'Time_of_Day': event.find('Time_of_Day').text if event.find('Time_of_Day') is not None else None,
                    'Process_Name': process_name.text,
                    'PID': event.find('PID').text if event.find('PID') is not None else None,
                    'Operation': event.find('Operation').text if event.find('Operation') is not None else None,
                    'Path': event.find('Path').text if event.find('Path') is not None else None,
                    'Result': event.find('Result').text if event.find('Result') is not None else None,
                    'Detail': event.find('Detail').text if event.find('Detail') is not None else None,
                    'Type': categorize_event(event.find('Operation').text if event.find('Operation') is not None else '')
                }
                events.append(event_details)

    with open(json_file, 'w') as jsonf:
        json.dump(events, jsonf, indent=4)


