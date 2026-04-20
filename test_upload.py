import urllib.request as r
import json
import traceback

boundary = '-----Boundary--'
data = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="cmd.exe"\r\n\r\n'.encode('utf-8') + open(r'c:\windows\system32\cmd.exe', 'rb').read() + f'\r\n--{boundary}--\r\n'.encode('utf-8')
req = r.Request('http://127.0.0.1:5000/analyze', method='POST', data=data)
req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')

try:
    response = r.urlopen(req)
    print("SUCCESS", response.read().decode())
except Exception as e:
    print("ERROR", e)
    if hasattr(e, 'read'):
        print(e.read().decode())
