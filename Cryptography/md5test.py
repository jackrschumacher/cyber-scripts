import hashlib

data = 0
while True:
    input_str = str(data)
    hash_result = hashlib.md5(input_str.encode()).hexdigest()
    if hash_result.startswith('00000'):
        print(f"Found: {input_str}")
        break
    data += 1