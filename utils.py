import os
import sys
import controller
import configparser
import asyncio

async def convert_procmon_log(agent_url):
    config = configparser.ConfigParser()
    config.read('configuration/config.ini')
    file_path = config['DEFAULT']['VM_DEFAULT_PATH']
    auto_exec_path = '"C:/Users/User/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
    command = f'{auto_exec_path}/procmon.exe" /OpenLog {file_path}\\procmonlog.pml /SaveAs {file_path}\\procmonlog.xml'
    try:
        execute_response = controller.execute_command(command, agent_url)
        if execute_response.get('error'):
            return execute_response
    except Exception as e:
        return {'error': f'Error executing module: {str(e)}'}
    return {'message': 'Execution completed successfully'}

async def get_procmon_log(agent_url):
    save_path = 'memdump/procmonlog.xml'
    try:
        response = controller.download_file('procmonlog.xml', save_path, agent_url)
        if response.get('error'):
            return response
    except Exception as e:
        return {'error': f'Error executing module: {str(e)}'}
    return {'message': 'Execution completed successfully'}

async def stop_procmon(agent_url):
    auto_exec_path = '"C:/Users/User/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
    command = f'{auto_exec_path}/procmon.exe" /Terminate'
    try:
        execute_response = controller.execute_command(command, agent_url)
        if execute_response.get('error'):
            return execute_response
    except Exception as e:
        return {'error': f'Error executing module: {str(e)}'}
    return {'message': 'Execution completed successfully'}

