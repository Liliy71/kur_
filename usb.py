import os
import json
import hashlib
import secrets
import re
import shutil
import sqlite3


USER_FILE = 'users.json'
DATABASE_FILE = 'users.db'


def load_json_data(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json_data(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt


def verify_password(password, stored_hash, salt):
    hashed_password, _ = hash_password(password, salt)
    return hashed_password == stored_hash


def create_users_table():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def register_user(username, password):
    hashed_password, salt = hash_password(password)
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
        conn.commit()
        conn.close()
        print("Registration successful.")
        return True
    except sqlite3.IntegrityError:
        print("User already exists.")
        return False


def login_user(username, password):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password, salt FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash, salt = result
        if verify_password(password, stored_hash, salt):
            print("Login successful.")
            return True
    print("Invalid username or password.")
    return False


def analyze_file(filepath, virus):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.readlines()
            for i in text:
                if re.search(r".*mkdir %windir%[\\/].*", i):
                    virus[0] = 1
                if re.search(r".*attrib .*[%]*[w_][wb_]*[%]* +h.*", i):
                    virus[1] = 1
                if re.search(r".*echo.*>>[%]*[w_][wb_]*[%]*.*", i):
                    virus[2] = 1
                if re.search(r".*<%0>>[%]*[w_][wb_]*[%]*.*", i):
                    virus[3] = 1
                if re.search(r".*ren [%]*[w_][wb_]*[%]* *.bat.*", i):
                    virus[4] = 1
                if re.search(r".*copy [%]*[w_][wb_+.]* [%]*[w_][wb_+]*.*", i):
                    virus[5] = 1
                if re.search(r".*for [%]*[w_][wb_+.]* in \(.*\.bat\) do call [%]*[w_][wb_+.]*[%]* [%]*[w_][wb_+.]*[%]*.*", i):
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


if __name__ == '__main__':
    create_users_table()
    register_user("testuser", "password123")
    login_user("testuser", "password123")

    # Example Usage (Virus Analysis):
    # Create a directory and some dummy files for testing
    test_directory = "test_directory"
    if not os.path.exists(test_directory):
        os.makedirs(test_directory)

    # Create a potentially malicious file
    with open(os.path.join(test_directory, "virus.bat"), "w") as f:
        f.write("mkdir %windir%\\system32\n")
        f.write("attrib %windir%\\system32 +h\n")
        f.write("echo Some code >> %windir%\\system32\n")

    # Create a clean file
    with open(os.path.join(test_directory, "clean.txt"), "w") as f:
        f.write("This is a clean file.\n")

    analyze_directory(test_directory)

    # Clean up the test directory (optional)
    shutil.rmtree(test_directory, ignore_errors=True)
