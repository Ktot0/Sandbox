import os
import json
from functools import wraps
from flask import Flask, request, redirect, url_for, render_template, jsonify
from flask_socketio import SocketIO, emit
import scheduler
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from database import Database
from datetime import datetime

app = Flask(__name__)
db = Database()

def is_configured():
    return True if db.get_value('configuration', 1, "id") is not None else False

def check_config(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_configured():
            return redirect(url_for('configure'))
        return f(*args, **kwargs)
    return decorated_function

if is_configured():
    config = db.get_row('configuration',1)

socketio = SocketIO(app)
UPLOAD_FOLDER = 'uploads'
MODULES_FOLDER = 'modules'
CORE_MODULES_FOLDER = 'coremodules'
REPORT_FOLDER = 'reports'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

vm_scheduler = scheduler.Scheduler(socketio)

@app.route('/')
def index():
    if not is_configured():
        return redirect(url_for('configure'))
    return redirect(url_for('submit'))

@app.route('/configure', methods=['GET', 'POST'])
def configure():
    if request.method == 'POST':
        vm_label = request.form['vm_label']
        snapshot = request.form['snapshot']
        vm_default_path = request.form['vm_default_path']
        vboxmanage_path = request.form['vboxmanage_path']
        virustotal_api_key = request.form['virustotal_api_key']

        config_dict = {
            'vm_label': vm_label,
            'snapshot': snapshot,
            'vm_default_path': vm_default_path,
            'vboxmanage_path': vboxmanage_path,
            'virustotal_api_key': virustotal_api_key
        }
        
        db.delete_row('configuration', 1)
        db.insert("configuration",config_dict)
        return redirect(url_for('index'))
    
    return render_template('configuration.html')

@app.route('/submit')
@check_config
def submit():
    modules = [f[:-3] for f in os.listdir(MODULES_FOLDER) if f.endswith('.py') and not f.startswith('__')]
    post_modules = [f[:-3] for f in os.listdir(os.path.join(MODULES_FOLDER, 'post_execution')) if f.endswith('.py') and not f.startswith('__')]
    return render_template('submit.html', modules=modules, post_modules=post_modules)

@app.route('/pending')
def pending():
    return render_template('pending.html')

@app.route('/results')
def results():
    return render_template('results.html')

@app.route('/upload', methods=['POST'])
@check_config
def upload_file():
    VM_LABEL = db.get_value('configuration',1, "vm_label")
    selected_modules = request.form.getlist('modules')
    selected_post_modules = request.form.getlist('post_modules')
    if not selected_modules:
        return jsonify({'error': 'No modules selected. Please select at least one module.'})

    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file:
        formatted_time = datetime.now().strftime('%Y.%m.%d-%H.%M.%S')
        file_repo = os.path.join(UPLOAD_FOLDER,f'{file.filename}-{formatted_time}')
        os.mkdir(file_repo)
        file_path = os.path.join(file_repo,file.filename)
        file.save(file_path)
        core_modules = [__import__(f'coremodules.{module}', fromlist=[module]) for module in [f[:-3] for f in os.listdir(CORE_MODULES_FOLDER) if f.endswith('.py') and not f.startswith('__')]]
        modules = [__import__(f'modules.{module}', fromlist=[module]) for module in selected_modules]
        modules.extend(core_modules)
        post_modules = [__import__(f'modules.post_execution.{module}', fromlist=[module]) for module in selected_post_modules]

        submit_dict = {
            'file_path': file_path,
            'vm_label': VM_LABEL,
            'modules': json.dumps(extract_module_info(modules)),
            'post_modules': json.dumps(extract_module_info(post_modules)),
            'status': 'Pending',
            'submission_time': formatted_time,
            'file_name': file.filename
        }

        db.insert('submit', submit_dict)
        vm_scheduler.add_to_queue()
        #vm_scheduler.load_pending_tasks()
        return redirect(url_for('pending'))

@app.route('/reports', methods=['GET'])
def list_reports():
    reports = db.get_table('report')
    reports_list = [{'id': report[0], 'file_path': report[1], 'submission_time': report[6]} for report in reports]
    return jsonify({'reports': reports_list})

def extract_module_info(mod_list):
    return [{'name': mod.__name__} for mod in mod_list]

def humansize(nbytes):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])

@app.route('/reports/<report_name>')
def report(report_name):
    report_file = os.path.join('reports', report_name, 'core_summary-report.json')
    with open(report_file) as f:
        report_data = json.load(f)
    report_time = '.'.join(report_name.split('.')[1:])
    execution_date = report_time.split('-')[1]
    execution_time = report_time.split('-')[2]

    return render_template(
        'report.html',
        report_name=report_name,
        execution_date=execution_date,
        execution_time=execution_time,
        report_data=report_data
    )

@app.route('/reports/<report_name>/files', methods=['GET'])
def list_report_files(report_name):
    report_path = os.path.join(REPORT_FOLDER, report_name)
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404

    files = [f for f in os.listdir(report_path) if f.endswith('.json')]
    return jsonify({'files': files})

@app.route('/reports/<report_name>/<file_name>', methods=['GET'])
def get_report_file(report_name, file_name):
    report_path = os.path.join(REPORT_FOLDER, report_name, file_name)
    if not os.path.exists(report_path):
        return jsonify({'error': 'File not found'}), 404

    template_name = file_name.split(".")[0] + '.html'

    if not os.path.exists(os.path.join(app.template_folder, template_name)):
        return jsonify({'error': 'Template not found'}), 404

    with open(report_path, 'r') as file:
        json_content = json.load(file)

    return render_template(template_name, json_content=json_content, report_name=report_name, file_name=file_name)

@app.route('/status', methods=['GET'])
def get_status():
    status = vm_scheduler.get_status()
    return jsonify(status)

@app.route('/report_status', methods=['GET'])
def report_status():
    return jsonify(vm_scheduler.get_report_status())

if __name__ == '__main__':
    socketio.run(app, debug=True)
    #app.run(host='0.0.0.0', port=5000)
