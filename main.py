import argparse
from src.tools import *
from src.KDF import *
from src.RSA import *
from src.AES import *

def file_encrypt(args, pubkey):
    # file_path end with .pdf
    file_path = args.filepath
    data, extension = file_encode(file_path)
    key = os.urandom(32)
    encrypted_data, iv = aes_encrypt(data, key)
    os.remove(file_path)
    file_path = file_path + '.enc'
    file_decode(encrypted_data, file_path)
    encrypted_key = rsa_encrypt(key, pubkey)

    json_path = file_path + '.json'
    iv = bytes_to_str(iv)
    encrypted_key = bytes_to_str(encrypted_key)
    file_dict = {
        "owner": args.username,
        "extension": extension,
        "iv": iv,
        "aes_key_entries": [
            {
                "user_id": args.username,
                "encrypted_aes_key": encrypted_key
            },
        ]
    }
    write_json(file_dict, json_path)


    
def file_decrypt(args, prikey):
    # file_path end with .enc
    file_path = args.filepath
    file_dict = read_json(file_path + '.json')
    user_id_list = [entry["user_id"] for entry in file_dict["aes_key_entries"]]
    if args.username not in user_id_list:
        print("Permission denied")
        return
    for entry in file_dict["aes_key_entries"]:
        if entry["user_id"] == args.username:
            encrypted_key = entry["encrypted_aes_key"]
            break
    encrypted_key = str_to_bytes(encrypted_key)
    iv = str_to_bytes(file_dict['iv'])
    key = rsa_decrypt(encrypted_key, prikey)
    data, _ = file_encode(file_path)
    data = aes_decrypt(data, key, iv)
    file_decode(data, file_path.rstrip('.enc'))

def file_share(args, owner_prikey, mem_pubkey):
    # file_path end with .enc; username is the target user
    mem_username = args.memname
    file_path = args.filepath
    file_dict = read_json(file_path + '.json')
    if args.username != file_dict['owner']:
        print("Permission denied")
        return
    
    encrypted_key = [entry["encrypted_aes_key"] for entry in file_dict["aes_key_entries"] if entry["user_id"] == args.username]
    encrypted_key = str_to_bytes(encrypted_key[0])
    key = rsa_decrypt(encrypted_key, owner_prikey)
    mem_encrypted_key = rsa_encrypt(key, mem_pubkey)
    mem_encrypted_key = bytes_to_str(mem_encrypted_key)
    new_entry = {
        "user_id": mem_username,
        "encrypted_aes_key": mem_encrypted_key
    }
    file_dict["aes_key_entries"].append(new_entry)
    write_json(file_dict, file_path + '.json')

def key_process(username: str, password_dict: dict, password=None):
    pub = str_to_bytes(password_dict[username]['pubkey'])
    salt = str_to_bytes(password_dict[username]['salt'])
    iv = str_to_bytes(password_dict[username]['iv'])
    prb = str_to_bytes(password_dict[username]['prikey'])
    if password != None:
        enc_key, _ = derive_key(password, salt)
        prb = aes_decrypt(prb, enc_key, iv)
    return prb, pub # bytes, bytes

def main(args: argparse.Namespace):
    password_dict = read_json("password/password.json")
    args.password = args.password.encode('utf-8')
    usernames = list(password_dict.keys())
    if args.username not in usernames:
        enc_key, salt = derive_key(args.password)
        prk, puk = generate_rsa_keypair()
        prb, pub = rsakey_to_bytes(prk, puk)
        enc_prb, iv = aes_encrypt(prb, enc_key)
        password_dict[args.username] = {
            'pubkey': bytes_to_str(pub), # str
            'prikey': bytes_to_str(enc_prb), # str
            'salt': bytes_to_str(salt), # str
            'iv': bytes_to_str(iv), # str
        }
        write_json(password_dict, "password/password.json")
        password_dict = read_json("password/password.json")
    else:
        prb, pub = key_process(args.username, password_dict, args.password)

    prikey, pubkey = bytes_to_rsakey(prb, pub)
    
    if args.behavior == "encrypt":
        file_encrypt(args, pubkey)
    elif args.behavior == "decrypt":
        file_decrypt(args, prikey)
    elif args.behavior == "share":
        _, mem_pub = key_process(args.memname, password_dict)
        _, mem_pubkey = bytes_to_rsakey(None, mem_pub)
        file_share(args, prikey, mem_pubkey)
    else:
        pass






if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User Password Interface')

    parser.add_argument("--username", type=str)
    parser.add_argument("--memname", default='None', type=str)
    parser.add_argument("--password", type=str)
    parser.add_argument("--behavior", default='None', type=str, choices=['encrypt', 'decrypt', 'share', 'None'])
    parser.add_argument("--filepath", default='None', type=str)
    
    args = parser.parse_args()
    main(args)