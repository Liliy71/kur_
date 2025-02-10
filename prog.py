
import os
import json
import stat
import time
import hashlib
import secrets

USER_FILE = 'users.json'
FILE_MAPPING = 'file_mapping.json'

def create_file_if_not_exists(filename, mode):
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump({}, f)
        os.chmod(filename, mode)

create_file_if_not_exists(USER_FILE, stat.S_IRUSR | stat.S_IWUSR)
create_file_if_not_exists(FILE_MAPPING, stat.S_IRUSR | stat.S_IWUSR)


def load_json_data(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print(f"Error decoding JSON from {filename}.  File may be corrupted. Returning empty dictionary.")
        return {}

def save_json_data(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)

def load_users():
    return load_json_data(USER_FILE)

def save_users(users):
    save_json_data(USER_FILE, users)

def load_file_mapping():
    return load_json_data(FILE_MAPPING)

def save_file_mapping(mapping):
    save_json_data(FILE_MAPPING, mapping)

def hash_password(password, salt=None):
    """Хеширует пароль с использованием SHA-256 с солью."""
    if salt is None:
        salt = secrets.token_hex(16)  # Генерируем новую случайную соль
    salted_password = salt.encode('utf-8') + password.encode('utf-8')  # Объединяем соль и пароль
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt

def register_user(username, password):
    users = load_users()
    if username in users:
        print("Пользователь уже существует.")
        return False

    # Хешируем пароль и сохраняем соль
    hashed_password, salt = hash_password(password)
    users[username] = {'hashed_password': hashed_password, 'salt': salt}  # Сохраняем соль и хеш
    save_users(users)
    print("Регистрация успешна.")
    return True


def verify_password(password, stored_hash, salt):
    """Проверяет пароль на соответствие сохраненному хешу и соли."""
    hashed_password, _ = hash_password(password, salt)  # хешируем с существующей солью
    return hashed_password == stored_hash

def login_user(username, password):
    users = load_users()
    if username in users:
        user_data = users[username]
        stored_hash = user_data['hashed_password']
        salt = user_data['salt']

        if verify_password(password, stored_hash, salt):
            print("Вход выполнен успешно.")
            return True
        else:
            print("Неверное имя пользователя или пароль.")
            return False
    else:
        print("Неверное имя пользователя или пароль.")
        return False

def is_valid_filename(filename):
    """Проверяет имя файла для предотвращения обхода каталогов."""
    return all(part not in filename for part in ["..", "/", "\\"]) and filename

def create_file(username):
    filename = input("Введите имя файла для создания: ")
    if not filename.endswith('.txt'):
        filename += '.txt'

    if not is_valid_filename(filename):
        print("Недопустимое имя файла. Имена файлов не могут содержать символы обхода каталогов (.., /, \\)")
        return

    try:
        with open(filename, 'w') as f:
            content = input("Введите содержимое файла: ")
            f.write(content)

        # Ограничиваем доступ к файлу
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Только владелец может читать и писать

        # Обновляем сопоставление файлов
        mapping = load_file_mapping()
        if username not in mapping:
            mapping[username] = []
        mapping[username].append(filename)
        save_file_mapping(mapping)

        print(f"Файл '{filename}' успешно создан.")

    except Exception as e:
        print(f"Ошибка создания файла: {e}")


def read_file(username):
    mapping = load_file_mapping()
    if username not in mapping or not mapping[username]:
        print("Файлы для этого пользователя не найдены.")
        return

    print("Доступные файлы:")
    for idx, fname in enumerate(mapping[username], start=1):
        print(f"{idx}. {fname}")

    try:
        choice = int(input("Выберите номер файла для чтения: ")) - 1
        if 0 <= choice < len(mapping[username]):
            filename = mapping[username][choice]

            if not is_valid_filename(filename):
                print("Недопустимое имя файла.")
                return

            try:
                with open(filename, 'r') as f:
                    content = f.read()
                    print(f"Содержимое '{filename}':\n{content}")
            except Exception as e:
                print(f"Ошибка чтения файла: {e}")
        else:
            print("Неверный выбор.")
    except ValueError:
        print("Неверный ввод. Пожалуйста, введите число.")
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")


# Пример использования (для тестирования)
if __name__ == '__main__':
    while True:
        action = input("Зарегистрироваться (r), Войти (l), Создать файл (c), Прочитать файл (rd), или Выйти (q)? ").lower()

        if action == 'r':
            username = input("Введите имя пользователя: ")
            password = input("Введите пароль: ")
            register_user(username, password)
        elif action == 'l':
            username = input("Введите имя пользователя: ")
            password = input("Введите пароль: ")
            login_user(username, password)
        elif action == 'c':
            username = input("Введите ваше имя пользователя: ")
            create_file(username)
        elif action == 'rd':
            username = input("Введите ваше имя пользователя: ")
            read_file(username)
        elif action == 'q':
            break
        else:
            print("Неверное действие.")
