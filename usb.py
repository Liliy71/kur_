import os
import json
import hashlib
import secrets
import re
import time

USER_FILE = 'users.json'

def load_json_data(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_json_data(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt

def register_user(username, password):
    users = load_json_data(USER_FILE)
    if username in users:
        print("Пользователь уже существует.")
        return False
    hashed_password, salt = hash_password(password)
    users[username] = {'hashed_password': hashed_password, 'salt': salt}
    save_json_data(USER_FILE, users)
    print("Регистрация успешна.")
    return True

def verify_password(password, stored_hash, salt):
    hashed_password, _ = hash_password(password, salt)
    return hashed_password == stored_hash

def login_user(username, password, attempt_counter):
    users = load_json_data(USER_FILE)
    if username in users:
        user_data = users[username]
        stored_hash = user_data['hashed_password']
        salt = user_data['salt']
        if verify_password(password, stored_hash, salt):
            print("Вход выполнен успешно.")
            return True
    
    attempt_counter[0] += 1
    print("Неверное имя пользователя или пароль.")
    
    if attempt_counter[0] >= 3:
        print("Слишком много неудачных попыток. Подождите 10 секунд.")
        time.sleep(10)
        attempt_counter[0] = 0
    return False

def analyze_file(filepath, virus):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.readlines()
            for i in text:
                if re.search(r".*mkdir %windir%\\.*", i):
                    virus[0] = 1
                if re.search(r".*attrib .*[%]*[w_][wb_]*[%]* +h", i):
                    virus[1] = 1
                if re.search(r".*echo.*>>[%]*[w_][wb_]*[%]*", i):
                    virus[2] = 1
                if re.search(r".*<%0>>[%]*[w_][wb_]*[%]*", i):
                    virus[3] = 1
                if re.search(r".*ren [%]*[w_][wb_]*[%]* .*\.bat", i):
                    virus[4] = 1
                if re.search(r".*copy [%]*[w_][wb_+.]* [%]*[w_][wb_+]*.*", i):
                    virus[5] = 1
                if re.search(r".*for [%]*[w_][wb_+.]* in \(.*\.bat\) do call [%]*[w_][wb_+.]*[%]* [%]*[w_][wb_+.]*[%]*", i):
                    virus[6] = 1
            return any(virus)
    except Exception as e:
        print(f"Ошибка при обработке {filepath}: {e}")
        return False

def analyze_directory(directory):
    virus = [0] * 7
    total_vect = 0
    files_analyzed = 0
    viruses_found = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            print(f"Анализ: {filepath}")
            if analyze_file(filepath, virus):
                print(f"[!] Обнаружен потенциально вредоносный файл: {filepath}")
                viruses_found += 1
            files_analyzed += 1
            total_vect += sum(virus)
            virus = [0] * 7
    
    print(f"Всего файлов проверено: {files_analyzed}")
    print(f"Обнаружено подозрительных файлов: {viruses_found}")
    print("Результат:", "Вирус" if total_vect > 4 else "Возможно вирус" if total_vect > 0 else "Не вирус")

def main():
    logged_in = False
    attempt_counter = [0]
    while True:
        print("\nМеню:")
        print("1. Регистрация")
        print("2. Вход")
        print("3. Выход")
        choice = input("Выберите действие: ")
        
        if choice == '1':
            username = input("Имя пользователя: ")
            password = input("Пароль: ")
            register_user(username, password)
        elif choice == '2':
            username = input("Имя пользователя: ")
            password = input("Пароль: ")
            if login_user(username, password, attempt_counter):
                logged_in = True
                while logged_in:
                    print("\nМеню пользователя:")
                    print("1. Проверить USB на вирусы")
                    print("2. Выйти из аккаунта")
                    user_choice = input("Выберите действие: ")
                    if user_choice == '1':
                        directory_to_scan = input("Введите путь к USB-накопителю: ")
                        if os.path.exists(directory_to_scan):
                            analyze_directory(directory_to_scan)
                        else:
                            print("Ошибка: указанная директория не существует.")
                    elif user_choice == '2':
                        logged_in = False
                        print("Выход из аккаунта.")
        elif choice == '3':
            break
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()
