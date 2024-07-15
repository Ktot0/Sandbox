import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import controller
import configparser


def run(agent_url, sample_name):
    config = configparser.ConfigParser()
    config.read('configuration/config.ini')
    file_path = config['DEFAULT']['VM_DEFAULT_PATH']
    
    command = f'{file_path}\\{sample_name}'
    try:
        execute_response = controller.execute_command(command, agent_url)
        if execute_response.get('error'):
            return execute_response
    except Exception as e:
        return {'error': f'Error executing module: {str(e)}'}
    return {'message': 'Execution completed successfully'}
