import json
import random
import os

current_dir = os.path.dirname(__file__)
tools_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(tools_dir)
json_path = os.path.join(project_root, "backend", "words.json")

with open(json_path, 'r') as f:
    words_data = json.load(f)

welcome_list = list(words_data["welcome"].values())
loading_list = list(words_data["loading"].values())

welcome = random.choice(welcome_list)
loading = random.choice(loading_list)