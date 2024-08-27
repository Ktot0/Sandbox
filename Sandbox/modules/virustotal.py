import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import controller
from database import Database

def run(agent_url, sample_name):
    db = Database()
    file_path = db.get_value('configuration', 1, "vm_default_path")
    api_key = db.get_value('configuration', 1, "virustotal_api_key")
    utils_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'utils'))
    virustotalscanner_path = os.path.join(utils_dir, 'virustotalscanner.py')
    if not os.path.exists(virustotalscanner_path):
        return {'error': 'virustotalscanner.py not found in the utils directory'}

    try:
        upload_response = controller.upload_file(virustotalscanner_path, agent_url)
        if upload_response.get('error'):
            return upload_response
    except Exception as e:
        return {'error': f'Error uploading file: {str(e)}'}

    command = f'python {file_path}\\virustotalscanner.py {file_path}\\{sample_name} {api_key} {file_path}\\'
    print(command)
    try:
        execute_response = controller.execute_command(command, agent_url)
        if execute_response.get('error'):
            return execute_response
    except Exception as e:
        return {'error': f'Error executing module: {str(e)}'}
    return {'message': 'Execution completed successfully'}
