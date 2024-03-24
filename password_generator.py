# Importowanie niezbędnych modułów
import string
import hashlib
import sqlite3
import random
import os


# Funkcja do generowania hasła
# domyślna długość hasła o długości 12 znaków
def generate_password(
    length=12,
    use_lowercase=True,
    use_uppercase=True,
    use_digits=True,
    use_punctuation=True,
):
    characters = ""
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_punctuation:
        characters += string.punctuation
    if not characters:
        raise ValueError("Brak wybranych znaków do generowania hasła.")

    return "".join(random.choice(characters) for _ in range(length))


# Funkcja do hashowania hasła
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Funkcja do zapisywania hasła do bazy danych
def save_password_to_database(website, username, password, user_id):
    conn = sqlite3.connect(f"user_{user_id}_passwords.db")
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS passwords
                 (website TEXT, username TEXT, password TEXT)"""
    )
    c.execute("INSERT INTO passwords VALUES (?, ?, ?)", (website, username, password))
    conn.commit()
    conn.close()


# Funkcja do odczytywania hasła z bazy danych
def read_password_from_database(user_id):
    conn = sqlite3.connect(f"user_{user_id}_passwords.db")
    c = conn.cursor()
    c.execute("SELECT * FROM passwords")
    data = c.fetchall()
    conn.close()
    return data


# Funkcja do zabezpieczenia hasła do bazy danych
def secure_database_password(user_id):
    db_password = input("Podaj hasło do bazy danych: ")
    hashed_db_password = hash_password(db_password)
    with open(f"user_{user_id}_password.txt", "w") as f:
        f.write(hashed_db_password)
    return hashed_db_password


# Funkcja do sprawdzania poprawności hasła dostępu do bazy danych
def check_database_password(input_password, hashed_password):
    return hash_password(input_password) == hashed_password


# Funkcja do tworzenia nowego użytkownika
def create_new_user():
    username = input("Podaj login użytkownika: ")
    password = input("Podaj hasło użytkownika: ")
    user_id = hash_password(username)
    if not os.path.exists(f"user_{user_id}_passwords.db"):
        conn = sqlite3.connect(f"user_{user_id}_passwords.db")
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS user_info
                     (username TEXT, password TEXT)"""
        )
        c.execute(
            "INSERT INTO user_info VALUES (?, ?)", (username, hash_password(password))
        )
        conn.commit()
        conn.close()
        return user_id
    else:
        print("Użytkownik o podanym loginie już istnieje.")
        return None


# Funkcja do logowania użytkownika
def login_user():
    username = input("Podaj login użytkownika: ")
    password = input("Podaj hasło użytkownika: ")
    user_id = hash_password(username)
    if os.path.exists(f"user_{user_id}_passwords.db"):
        conn = sqlite3.connect(f"user_{user_id}_passwords.db")
        c = conn.cursor()
        c.execute("SELECT * FROM user_info")
        data = c.fetchone()
        conn.close()
        if data and hash_password(password) == data[1]:
            return user_id
    print("Nieprawidłowy login lub hasło.")
    return None


# Obsługa programu w pętli i wykorzystanie warunku try
def main():
    try:
        # Główna pętla programu
        while True:
            print("\n1. Zaloguj się")
            print("2. Zarejestruj się")
            print("3. Wyjście")

            choice = input("Wybierz opcję: ")

            if choice == "1":
                user_id = login_user()
                if user_id:
                    hashed_db_password = secure_database_password(user_id)
                    while True:
                        print("\n1. Generuj hasło")
                        print("2. Zapisz hasło do bazy danych")
                        print("3. Odczytaj hasła z bazy danych")
                        print("4. Wyloguj")

                        choice = input("Wybierz opcję: ")

                        if choice == "1":
                            website = input("Podaj nazwę strony: ")
                            username = input("Podaj nazwę użytkownika: ")
                            password_length = int(input("Podaj długość hasła: "))
                            use_lowercase = (
                                input("Czy używać małych liter? (tak/nie): ").lower()
                                == "tak"
                            )
                            use_uppercase = (
                                input("Czy używać dużych liter? (tak/nie): ").lower()
                                == "tak"
                            )
                            use_digits = (
                                input("Czy używać cyfr? (tak/nie): ").lower() == "tak"
                            )
                            use_punctuation = (
                                input(
                                    "Czy używać znaków specjalnych? (tak/nie): "
                                ).lower()
                                == "tak"
                            )
                            password = generate_password(
                                password_length,
                                use_lowercase,
                                use_uppercase,
                                use_digits,
                                use_punctuation,
                            )
                            print(f"Wygenerowane hasło: {password}")
                            save_password_to_database(
                                website, username, password, user_id
                            )

                        elif choice == "2":
                            website = input("Podaj nazwę strony: ")
                            username = input("Podaj nazwę użytkownika: ")
                            password = input("Podaj hasło: ")
                            save_password_to_database(
                                website, username, password, user_id
                            )

                        elif choice == "3":
                            db_password = input("Podaj hasło: ")
                            if check_database_password(db_password, hashed_db_password):
                                passwords = read_password_from_database(user_id)
                                print("\nZnalezione hasła:")
                                for entry in passwords:
                                    print(f"Strona: {entry[0]}")
                                    print(f"Użytkownik: {entry[1]}")
                                    print(f"Hasło: {entry[2]}\n")
                            else:
                                print("Nieprawidłowe hasło.")

                        elif choice == "4":
                            break

                        else:
                            print("Nieprawidłowy wybór.")

            elif choice == "2":
                user_id = create_new_user()
                if user_id:
                    print("Użytkownik został pomyślnie zarejestrowany.")

            elif choice == "3":
                break

            else:
                print("Nieprawidłowy wybór.")

    except ValueError as e:
        print(f"Błąd: {e}")


if __name__ == "__main__":
    main()
