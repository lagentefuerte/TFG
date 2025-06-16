import base64

file_path = 'keyloggerobs.ps1'
output_file_path = 'payload_base64.txt'

with open(file_path, 'rb') as file:
    file_data = file.read()
    base64_data = base64.b64encode(file_data).decode('utf-8')

with open(output_file_path, 'w') as output_file:
    output_file.write(base64_data)

print(f"Archivo base64 guardado en: {output_file_path}")
