import os
import json


default_data = {
    "EXAMPLE": {
        'pubkey': "",
        'prikey': "",
        'salt': "",
        'iv': "",
    }
}
with open("password.json", 'w', encoding='utf-8') as f:
    json.dump(default_data, f, indent=4)
print("Initialized Password json.")