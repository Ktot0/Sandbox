import requests
import base64
import time
import sys

url = 'https://www.virustotal.com/api/v3/files'
sample_name = sys.argv[1]
api_key = sys.argv[2]
file_path = 'C:\\Users\\User\\Desktop\\sample\\'

files = { 'file': (f'{sample_name}', open(f'{sample_name}', 'rb'), 'application/x-msdownload') }
headers = {
    'accept': 'application/json',
    'x-apikey': f'{api_key}'
}

json_data = requests.post(url, files=files, headers=headers)
data = eval(json_data.text)
id_value = '/' + base64.b64decode(data['data']['id']).decode('utf-8').split(':')[0]

time.sleep(10)

response = requests.get(url+id_value, headers=headers)

with open(f'{file_path}virustotal-report.json', 'w') as f:
    f.write(response.text)
    f.close()
