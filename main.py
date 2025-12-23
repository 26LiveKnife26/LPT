from tools import script_messages
import simple_term_menu
import art
import json
import random
import time
import sys

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
        print("инструкция:\n1.для использования модуля нажмите w или выберите пункт в меню\n2.если вы не знаете применение какому либо модулю нажмите h или выберите соответсвующий пункт в меню\n3.если вы нашли баг то обратитесь на почту liveknife26@gmail.com. либо откройте issue/discussion в github\nудачной работы!")
        input("\nнажмите enter для продолжения...")
        
    cookie["user"]["first?"] = "no"
    with open('backend/cookies.json', 'w') as cookies:
        json.dump(cookie, cookies, indent=4)

print(script_messages.loading)
time.sleep(random.randint(5, 10))
print("\033c\033[3J", end="")

while True:
    print(script_messages.welcome)
    print("")
    
    menu = simple_term_menu.TerminalMenu(
        ["модули", "логи", "генератор отчетов", "выход"],
        menu_cursor="-> ",
        clear_screen=False
    ).show()
    
    if menu == 0:
        print("\033c\033[3J", end="")
        print("модули 📦")
        print("")
        modules_menu = simple_term_menu.TerminalMenu(
            ["osint", "веб-пентест", "крипто и сети", "эксплуатация", "назад"],
            menu_cursor="-> ",
            clear_screen=False
        ).show()
        if modules_menu == 0 or modules_menu == 1 or modules_menu == 2 or modules_menu == 3:
            print("еще в разработке")
            input("")
        if modules_menu == 4:
            continue
    
    elif menu == 1:
        print("логи еще в разработке, иди нафиг")
        input("")
    
    elif menu == 2:
        print("генератор отчетов еще в разработке, иди нафиг")
        input("")
    
    elif menu == 3:
        print("проваливай!")
        sys.exit()
    
    print("\033c\033[3J", end="")