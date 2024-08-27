import os
import subprocess

REQUIRED_FOLDERS = ['db', 'memdump', 'reports', 'uploads']

def create_required_folders(folders):
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            
create_required_folders(REQUIRED_FOLDERS)

# Start the Flask app
subprocess.run(['python', 'webapp.py'])


