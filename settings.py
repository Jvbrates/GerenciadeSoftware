import json
from typing import Any

SOURCE_FILE = "conf.json"


def get_setting(key: str):
    with open(SOURCE_FILE, 'r') as conf:
        data = json.load(conf)
    return data[key]


def set_setting(key: str, value: Any):
    with open(SOURCE_FILE, 'r+') as conf:
        data = json.load(conf)
        conf.seek(0)
        conf.truncate(0)
        data[key] = value
        print(data)
        json.dump(data, conf)
