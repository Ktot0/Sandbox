import requests
from database import Database

# Initialize the global UPLOAD_FOLDER from the database
db = Database()

def check_online(agent_url):
    try:
        response = requests.get(f'{agent_url}/ping')
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def upload_file(file_path, agent_url):
    try:
        with open(file_path, 'rb') as f:
            UPLOAD_FOLDER = db.get_value('configuration', 1, 'vm_default_path')
            files = {'file': f}
            params = {'folder_path': UPLOAD_FOLDER}
            response = requests.post(f'{agent_url}/upload', files=files, params=params)
            response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def download_file(filename, save_path, agent_url):
    try:
        UPLOAD_FOLDER = db.get_value('configuration', 1, 'vm_default_path')
        params = {'folder_path': UPLOAD_FOLDER}
        response = requests.get(f'{agent_url}/download/{filename}', params=params, stream=True)
        response.raise_for_status()
        if response.status_code == 200:
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return {'message': 'File downloaded successfully'}
        else:
            return {'error': 'Failed to download file'}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def execute_command(command, agent_url):
    try:
        payload = {'command': command}
        response = requests.post(f'{agent_url}/execute', json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}
