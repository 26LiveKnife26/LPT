# tools/script_messages.py
import json
import random
import os

current_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(current_dir)
json_path = os.path.join(parent_dir, "backend", "words.json")

with open(json_path, 'r') as f:
    words_data = json.load(f)

welcome_list = list(words_data["welcome"].values())
loading_list = list(words_data["loading"].values())

welcome = random.choice(welcome_list)
loading = random.choice(loading_list)