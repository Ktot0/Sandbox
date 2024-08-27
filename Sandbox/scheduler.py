import os
import asyncio
import VirtualBox
import controller
from flask_socketio import SocketIO, emit
from queue import Queue
import threading
import json
from datetime import datetime
from log import log
import utils
from database import Database
import network

class Scheduler:
    def __init__(self, socketio):
        self.vbox = VirtualBox.VirtualBoxManager()
        self.socketio = socketio
        self.queue = Queue()
        self.current_task = None
        self.completed_reports = []
        self.lock = threading.Lock()
        self.db = Database()
        threading.Thread(target=self.worker, daemon=True).start()

    def worker(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        while True:
            label, file_path, formatted_time, modules, post_modules = self.queue.get()
            self.move_to_table('submit', 'running',formatted_time, 'Running')
            self.current_task = (label, file_path, formatted_time)
            loop.run_until_complete(self.upload_and_execute(label, file_path, formatted_time, modules, post_modules))
            self.current_task = None
            self.completed_reports.append([file_path, formatted_time])
            self.move_to_table('running', 'report',formatted_time, 'Completed')
            self.queue.task_done()
            loop.run_until_complete(asyncio.sleep(5))

    def move_to_table(self, from_table_name, to_table_name, formatted_time, status):
        row_id = self.db.get_id(from_table_name, 'submission_time', formatted_time)
        row = self.db.get_row(from_table_name,row_id)
        move_dict = {
            'file_path': row[1],
            'vm_label': row[2],
            'modules': row[3],
            'post_modules': row[4],
            'status': status,
            'submission_time': formatted_time,
            'file_name': row[7]
        }
        self.db.delete_row(from_table_name, row_id)
        self.db.insert(to_table_name, move_dict)


    async def start_vm(self, label):
        async def wait_for_vm_startup(label):
            log(f'Starting VM {label}')
            await self.vbox.start_vm(label)
            await asyncio.sleep(30)
            for _ in range(60):
                if await self.vbox.status(label) == '1':
                    return True
                await asyncio.sleep(1)
            log(f'VM {label} startup timeout, restarting VM {label}')
            await self.vbox.kill_vm(label)
            return False

        while not await wait_for_vm_startup(label):
            log(f'Restarting VM {label}')
        
        ip = await self.vbox.get_ip(label)
        log(f'Logging into VM {label}')
        log(f'Establishing connection to VM {label}')
        
        return ip

    async def load_modules(self, directory):
        modules = []
        for filename in os.listdir(directory):
            if filename.endswith('.py'):
                module_name = filename[:-3]
                module = __import__(f'modules.{module_name}', fromlist=[module_name])
                modules.append(module)
        return modules

    async def check_connection(self, agent_url):
        for _ in range(60):
            try:
                response = controller.check_online(agent_url)
                if response.get('status') == 'online':
                    return True
            except Exception as e:
                log(f'Error checking connection: {str(e)}')
            await asyncio.sleep(1)
        return False
    
    async def get_report(self, agent_url, module_name, sample_report_path):
        report =  f'{module_name}-report.json'
        save_path = os.path.join(sample_report_path, report)
        try:
            response = controller.download_file(report, save_path, agent_url)
            return response
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
        
    async def upload_and_execute(self, label, file_path, formatted_time, modules, post_modules):
        sample_name = os.path.basename(file_path)
        sample_report_path = os.path.join('reports', f'{sample_name}-{formatted_time}')
        os.mkdir(sample_report_path)
        machine_ip = await self.start_vm(label)
        agent_url = f'http://{machine_ip}:5000'

        if not await self.check_connection(agent_url):
            log(f'Connection error: Unable to establish connection to VM {label}')
            return {'error': 'Connection error: Unable to establish connection to VM'}
        
        log(f'Starting Traffic Monitoring on VM {label}')
        network_thread = network.run('Ethernet 3', machine_ip) #ToDo: Add Interface to configuration
        log(f'Uploading sample {sample_name} to VM {label}')
        try:
            upload_response = controller.upload_file(file_path, agent_url)
            if upload_response.get('error'):
                log(f'Error uploading sample {sample_name}')
                return upload_response
        except Exception as e:
            log(f'Error uploading sample {sample_name}: {str(e)}')
            return {'error': f'Error uploading file: {str(e)}'}
        
        await asyncio.sleep(10)

        import importlib

        for i, module in enumerate(modules):
            await self.exe_modules(module, sample_report_path, agent_url, sample_name)
          
        await self.vbox.dump_memory(label)
        await utils.stop_procmon(agent_url)
        await utils.convert_procmon_log(agent_url)
        await utils.get_procmon_log(agent_url)
        network.stop(network_thread,f'{sample_report_path}\\network-report.json' )
        await self.vbox.stop_vm(label)

        await asyncio.sleep(5)

        for i, module in enumerate(post_modules):
            await self.exe_post_modules(module, sample_report_path)  

        await asyncio.sleep(5)

        os.remove('memdump/postexec')
        os.remove('memdump/procmonlog.xml')
        os.remove(f'uploads/{sample_name}-{formatted_time}/{sample_name}')
        os.rmdir(f'uploads/{sample_name}-{formatted_time}')

        log('Execution completed successfully')
        return {'message': 'Execution completed successfully'}
    
    async def exe_modules(self, module, sample_report_path, agent_url, sample_name):
        module_name = module['name'].split('.')[1]
        if 'core' in module_name:
            module_path = f'coremodules.{module_name}'
        else:
            module_path = module['name']
        try:
            module = __import__(module_path, fromlist=[module_name])
            if hasattr(module, 'run'):
                log(f'Executing Module {module_name}')
                try:
                    execute_response = module.run(agent_url, sample_name)
                    await self.get_report(agent_url, module_name, sample_report_path)
                    if execute_response.get('error'):
                        log('Error executing module')
                        return execute_response
                except Exception as e:
                    log(f'Error executing module: {str(e)}')
                    return {'error': f'Error executing module: {str(e)}'}
        except ImportError:
            log(f'Error importing module {module_name}')
            return {'error': f'Error importing module {module_name}'}
            
    async def exe_post_modules(self, module, sample_report_path):
        module_name = module['name'].split('.')[2]
        module_path = module['name']
        try:
            module = __import__(module_path, fromlist=[module_name])
            if hasattr(module, 'run'):
                log(f'Executing Module {module_name}')
                try:
                    execute_response = module.run(sample_report_path)
                    if execute_response.get('error'):
                        log('Error executing module')
                        return execute_response
                except Exception as e:
                    log(f'Error executing module: {str(e)}')
                    return {'error': f'Error executing module: {str(e)}'}
        except ImportError:
            log(f'Error importing module {module_name}')
            return {'error': f'Error importing module {module_name}'}

    def is_task_in_queue(self, task):
        queue_list = list(self.queue.queue)
        return True if task in queue_list else False

    def add_to_queue(self):
        pending_tasks = self.db.get_table('submit')
        for row in pending_tasks:
            task = (
                    row[2],
                    row[1],
                    row[6],
                    json.loads(row[3]),
                    json.loads(row[4])
                )
            if not self.is_task_in_queue(task):
                self.queue.put(task)
    
    def get_report_status(self):
        with self.lock:
            status = []
            report_directory = 'reports'
            for report in os.listdir(report_directory):
                if os.path.isdir(os.path.join(report_directory, report)):
                    status.append({
                        'file': report.split('-')[0],
                        'path': report,
                        'date': report.split('-')[1],
                        'time': report.split('-')[2],
                        'status': 'Completed'
                    }) 
            return status

    def get_status(self):
        with self.lock:
            status = []

            # Fetch running tasks from the 'running' table
            running_tasks = self.db.get_table('running')
            for row in running_tasks:
                status.append({
                    'file': os.path.basename(row[1]),
                    'date': row[6].split('-')[0],
                    'time': row[6].split('-')[1],
                    'status': 'Running'
                })

            # Fetch pending tasks from the 'submit' table
            pending_tasks = self.db.get_table('submit')
            for row in pending_tasks:
                if row[5] == 'Pending':
                    status.append({
                        'file': os.path.basename(row[1]),
                        'date': row[6].split('-')[0],
                        'time': row[6].split('-')[1],
                        'status': 'Pending'
                    })

            # Fetch completed tasks from the 'report' table
            completed_reports = self.db.get_table('report')
            for row in completed_reports:
                status.append({
                    'file': os.path.basename(row[1]),
                    'date': row[6].split('-')[0],
                    'time': row[6].split('-')[1],
                    'status': 'Completed'
                })

            return status

