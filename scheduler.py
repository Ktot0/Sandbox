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

class Scheduler:
    def __init__(self, socketio):
        self.vbox = VirtualBox.VirtualBoxManager()
        self.socketio = socketio
        self.queue = Queue()
        self.current_task = None
        self.completed_reports = []
        self.lock = threading.Lock()
        threading.Thread(target=self.worker, daemon=True).start()

    def worker(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        while True:
            label, file_path, formatted_time, modules, post_modules = self.queue.get()
            self.current_task = (label, file_path, formatted_time)
            loop.run_until_complete(self.upload_and_execute(label, file_path, formatted_time, modules, post_modules))
            self.current_task = None
            self.completed_reports.append([file_path, formatted_time])
            self.queue.task_done()
            loop.run_until_complete(asyncio.sleep(5))

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
        save_path = f'{sample_report_path}\\{report}'
        try:
            response = controller.download_file(report, save_path, agent_url)
            return response
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
        
    async def upload_and_execute(self, label, file_path, formatted_time, modules, post_modules):
        
        sample_name = file_path.split('\\')[1]
        sample_report_path = 'reports/' + sample_name + f'-{formatted_time}' #add date-time
        os.mkdir(sample_report_path)

        agent_url = f'http://{await self.start_vm(label)}:5000'
        #agent_url = "http://192.168.1.145:5000"

        # Check if the connection to the VM is established
        if not await self.check_connection(agent_url):
            log(f'Connection error: Unable to establish connection to VM {label}')
            return {'error': 'Connection error: Unable to establish connection to VM'}
        
        log(f'Uploading sample {sample_name} to VM {label}')
        # Upload file to VM
        try:
            upload_response = controller.upload_file(file_path, agent_url, 'sample')
            if upload_response.get('error'):
                log(f'Error uploading sample {sample_name}')
                return upload_response
        except Exception as e:
            log(f'Error uploading sample {sample_name}: {str(e)}')
            return {'error': f'Error uploading file: {str(e)}'}
        
        await asyncio.sleep(10)

        import importlib

        # Execute the uploaded file with each module
        for i, module in enumerate(modules):
            await self.exe_modules(module, sample_report_path, agent_url, sample_name)
          
        await self.vbox.dump_memory(label)
        #await asyncio.sleep(10)
        await utils.stop_procmon(agent_url)
        await utils.convert_procmon_log(agent_url)
        #await asyncio.sleep(10)
        await utils.get_procmon_log(agent_url)
        #await asyncio.sleep(10)
        await self.vbox.stop_vm(label)

        await asyncio.sleep(5)

        #post execution modules
        for i, module in enumerate(post_modules):
            await self.exe_post_modules(module, sample_report_path)  

        await asyncio.sleep(5)

        #Remove Dump
        os.remove('memdump/postexec')
        os.remove('memdump/procmonlog.xml')
        os.remove(f'uploads/{sample_name}')

        log('Execution completed successfully')
        return {'message': 'Execution completed successfully'}
    
        
    async def exe_modules(self, module, sample_report_path, agent_url, sample_name):
        module_name = module.__name__.split('.')[-1]
        if 'core' in module_name:
            module_path = f'coremodules.{module_name}'
        else:
            module_path = f'modules.{module_name}'
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
        module_name = module.__name__.split('.')[-1]
        module_path = f'modules.post_execution.{module_name}'
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
            
    def add_to_queue(self, label, file_path, modules, post_modules):
        now = datetime.now()
        formatted_time = now.strftime('%Y.%m.%d-%H.%M.%S')
        self.queue.put((label, file_path, formatted_time, modules, post_modules))

    def get_report_status(self):
        with self.lock:
            status = []
            report_directory = 'reports'
            for report in os.listdir(report_directory):
                if os.path.isdir(os.path.join(report_directory, report)):
                    status.append({'file': report.split('-')[0], 'path': report, 'date': report.split('-')[1], 'time': report.split('-')[2], 'status': 'Completed'}) 
            return status
        
    def get_status(self):
        with self.lock:
            status = []
            if self.current_task:
                status.append({'file': self.current_task[1].split('\\')[1], 'date': self.current_task[2].split('-')[0], 'time': self.current_task[2].split('-')[1], 'status': 'Running'})
            for label, file_path, formatted_time, modules, post_modules in list(self.queue.queue):
                status.append({'file': file_path.split('\\')[1], 'date': formatted_time.split('-')[0], 'time': formatted_time.split('-')[1], 'status': 'Pending'})
            for report in self.completed_reports:
                status.append({'file': report[0].split('\\')[1], 'date': report[1].split('-')[0], 'time': report[1].split('-')[1], 'status': 'Completed'})
            return status
