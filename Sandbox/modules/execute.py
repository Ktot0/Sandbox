import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import controller
from database import Database

def run(agent_url, sample_name):
    db = Database()
    file_path = db.get_value('configuration', 1, "vm_default_path")
    
    command = f'{file_path}\\{sample_name}'
    try:
        execute_response = controller.execute_command(command, agent_url)
        if execute_response.get('error'):
            return execute_response
    except Exception as e:
        return {'error': f'Error executing module: {str(e)}'}
    return {'message': 'Execution completed successfully'}
