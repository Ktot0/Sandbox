import datetime

def log(message):
    now = datetime.datetime.now()
    date = now.strftime('%d/%b/%Y')
    time = now.strftime('%H:%M:%S')
    ip = '127.0.0.1'

    formatted_message = f'{ip} - - [{date} {time}] "{message}" -'

    print(formatted_message)


