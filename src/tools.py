import json
import base64
import os

def bytes_to_str(bytes_data: bytes)  -> str:
    return base64.b64encode(bytes_data).decode('utf-8')

def str_to_bytes(base64_string: str) -> bytes:
    return base64.b64decode(base64_string.encode('utf-8'))

def write_json(data_to_save: dict, json_path: str) -> None:
    # data_to_save: password should be str
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data_to_save, f, indent=2, ensure_ascii=False)
    print("Data saved.")

def read_json(json_path: str) -> dict:
    # return: dict, password be str
    with open(json_path, 'r', encoding='utf-8') as f:
        loaded_data = json.load(f)
    return loaded_data

def file_encode(file_path: str) -> tuple:
    with open(file_path, 'rb') as f:
        data = f.read() # bytes
    extension = os.path.splitext(file_path)[1] # str
    return data, extension # bytes, str

def file_decode(data: bytes, file_path: str)-> None:
    with open(file_path, 'wb') as f:
        f.write(data)

# data, ext = file_encode("binary_data.json")
# file_decode(data, "1.json")

# # 示例数据
# original_bytes = b'Hello, World! This is binary data.\x00\x01\x02\x03'

# # 转换并存储到JSON文件
# data_to_save = {
#     "description": "示例二进制数据",
#     "binary_data": bytes_to_json_serializable(original_bytes), # str型
#     "timestamp": "2024-01-01 12:00:00"
# }#dict型


# # 写入JSON文件
# with open('binary_data.json', 'w', encoding='utf-8') as f:
#     json.dump(data_to_save, f, indent=2, ensure_ascii=False)

# print("数据已保存到 binary_data.json")

# # 从JSON文件读取并转换回bytes
# with open('binary_data.json', 'r', encoding='utf-8') as f:
#     loaded_data = json.load(f)

# recovered_bytes = json_serializable_to_bytes(loaded_data["binary_data"])

# print("原始bytes:", original_bytes)
# print("恢复的bytes:", recovered_bytes)
# print("数据是否一致:", original_bytes == recovered_bytes)

# file_path = "/path/to/your/file/document.pdf"
# file_extension = os.path.splitext(file_path)[0] # str
# print(file_extension)
# with open("binary_data.json", 'rb') as f:
#     data = f.read() # bytes

# print(type(file_extension))