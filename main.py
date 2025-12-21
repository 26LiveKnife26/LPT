from tools import center
import simple_term_menu
import art
import json

with open('backend/cookies.json', 'r') as cookies:
    cookie = json.load(cookies)
    
art.tprint("*   LPT   *")
if cookie["user"]["first?"] == "yes":
    print("вы впервые, не хотели ли бы вы прочитать инструкцию?")
    choice_index = simple_term_menu.TerminalMenu(
        ["да", "нет"],
        menu_cursor="→ ",
        clear_screen=False
    ).show()
    
    if choice_index == 0:
        print("")
        input("\nнажмите Enter для продолжения...")
        
    cookie["user"]["first?"] = "no"
    with open('backend/cookies.json', 'w') as cookies:
        json.dump(cookie, cookies, indent=4)
        
print("добро пожаловать в LPT!")