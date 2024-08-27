import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import controller
from database import Database

def run(agent_url, sample_name):
    try: 
        db = Database()
    except Exception as e:
        return {'error': f'Error starting database: {str(e)}'}
    
    file_path = db.get_value('configuration', 1, "vm_default_path")
    sample_name = db.get_value('running', 1, "file_name")
    utils_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'utils'))
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yara'))
    yarascanner_path = os.path.join(utils_dir, 'yarascanner.py')
    rules_path = os.path.join(rules_dir, 'rules.yar')

    with open(rules_path, 'w') as outfile:
        for filename in os.listdir(rules_dir):
            if filename.endswith('.yar') and 'rules' not in filename:
                rule_file = os.path.join(rules_dir, filename)
                with open(rule_file, 'r') as infile:
                    outfile.write(infile.read())
                    outfile.write('\n')

    if not os.path.exists(yarascanner_path):
        return {'error': 'yarascanner.py not found in the utils directory'}
    if not os.path.exists(rules_path):
        return {'error': 'rules.yar not found in the yara directory'}
    try:
        upload_response = controller.upload_file(yarascanner_path, agent_url)
        if upload_response.get('error'):
            return upload_response
    except Exception as e:
        return {'error': f'Error uploading file: {str(e)}'}
    
    try:
        upload_response = controller.upload_file(rules_path, agent_url)
        if upload_response.get('error'):
            return upload_response
    except Exception as e:
        return {'error': f'Error uploading file: {str(e)}'}

    command = f'python {file_path}\\yarascanner.py {file_path} {sample_name}'
    print(command)
    try:
        execute_response = controller.execute_command(command, agent_url)
        if execute_response.get('error'):
            return execute_response
    except Exception as e:
        return {'error': f'Error executing module: {str(e)}'}
    return {'message': 'Execution completed successfully'}

    
