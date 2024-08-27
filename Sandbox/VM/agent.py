from flask import Flask, request, jsonify, send_from_directory
import os
import subprocess
import threading
import queue
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command, result_queue, timeout):
    app.logger.debug(f'Running command: "{command}" with timeout {timeout} seconds')

    # Start the process
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        # Wait for the process to complete with a timeout
        stdout, stderr = process.communicate(timeout=timeout)
        result_data = {
            'output': stdout,
            'error': stderr,
            'returncode': process.returncode
        }
        app.logger.info(f'Command completed with return code {process.returncode}')
    except subprocess.TimeoutExpired:
        # Process did not complete in time, terminate it
        app.logger.warning('Command timed out. Terminating process.')
        process.kill()
        stdout, stderr = process.communicate()  # Ensure we get remaining output
        result_data = {
            'output': stdout,
            'error': stderr,
            'returncode': -1,
            'error_msg': 'Command timed out and was terminated'
        }
        app.logger.error('Command was terminated due to timeout')
    except Exception as e:
        result_data = {'error': str(e)}
        app.logger.error(f'Error executing command: {str(e)}')

    result_queue.put(result_data)

@app.route('/ping', methods=['GET'])
def ping():
    app.logger.debug('Ping endpoint called')
    return jsonify({'status': 'online'})

@app.route('/upload', methods=['POST'])
def upload_file():
    app.logger.debug('Upload endpoint called')
    
    folder_path = request.args.get('folder_path')
    
    if not os.path.isdir(folder_path):
        os.makedirs(folder_path, exist_ok=True)
    
    if 'file' not in request.files:
        app.logger.error('No file part in request')
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        app.logger.error('No selected file')
        return jsonify({'error': 'No selected file'}), 400
    
    file_path = os.path.join(folder_path, file.filename)
    app.logger.debug(f'Saving file to {file_path}')
    file.save(file_path)
    
    app.logger.info(f'File {file.filename} uploaded successfully')
    return jsonify({'message': 'File uploaded successfully', 'file': file.filename})

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    app.logger.debug(f'Download endpoint called for {filename}')
    
    folder_path = request.args.get('folder_path')
    if not folder_path:
        folder_path = '/default/path'  # Fallback to default path or handle error

    if not os.path.isdir(folder_path):
        os.makedirs(folder_path, exist_ok=True)

    return send_from_directory(folder_path, filename, as_attachment=True)

@app.route('/execute', methods=['POST'])
def execute_command():
    app.logger.debug('Execute endpoint called')
    
    data = request.json
    if 'command' not in data:
        app.logger.error('No command provided in request')
        return jsonify({'error': 'No command provided'}), 400

    command = data['command']
    timeout = data.get('timeout', 60)  # Default timeout to 60 seconds ToDo time slider in the submit page
    result_queue = queue.Queue()
    
    # Create and start a new thread to run the command
    thread = threading.Thread(target=run_command, args=(command, result_queue, timeout))
    thread.start()
    
    app.logger.debug('Command thread started')
    
    try:
        # Retrieve result from queue with a timeout
        result = result_queue.get(timeout=timeout + 10)  # Slightly longer timeout to account for processing
        app.logger.debug(f'Result retrieved from queue: {result}')
    except queue.Empty:
        app.logger.error('Command result not retrieved from queue within timeout')
        result = {
            'error': 'Request timed out while waiting for command result',
            'returncode': -1
        }
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
