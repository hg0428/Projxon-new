# JSPyBridge
import sqlite3
from encryption.symmetric import Symmetric
from encryption.asymmetric import Asymmetric
import sys
import email_validator  # https://pypi.org/project/email-validator/
import phonenumbers  # https://pypi.org/project/phonenumbers/
import re
import datetime
import random
from PCSS import encrypt, decrypt, process_key
import json
import hashlib
import pycountry
import os


pycountry.countries.add_entry(
    alpha_2="LL", alpha_3="LLR", name="Liberland", numeric="703"
)

# https://io.google/2023/program/469d76b5-204a-4b94-b13b-4f62c13b0f97/

connection = sqlite3.connect("example.db")
cursor = connection.cursor()
SIGNUP_EXPIRES_DAYS = 7
MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]
DAYS = {
    "January": 31,
    "February": 28,
    "March": 31,
    "April": 30,
    "May": 31,
    "June": 30,
    "July": 31,
    "August": 31,
    "September": 30,
    "October": 31,
    "November": 30,
    "December": 31,
}
WEEK_DAYS = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
]


def init():
    # Create table
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS emails (
        email TEXT PRIMARY KEY,
        signup_complete BOOLEAN,
        expires DATETIME
    )"""
    )

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS phones (
        phone TEXT PRIMARY KEY,
        signup_complete BOOLEAN,
        expires DATETIME
    )"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS users (
        primary_email TEXT,
        primary_phone TEXT,
        first_name_birthday TEXT,
        last_name_country TEXT,
        signup_complete BOOLEAN,
        authentication TEXT,
        encryption TEXT,
        date_of_account_creation TEXT,
        data TEXT,
        is_encrypted BOOLEAN
    )"""
    )
    """
    Inside data field is this:
    {
        "emails": [],
        "phones": [],
        "date_of_account_creation": ...
    }
    """
    # TODO: users table
    connection.commit()


def hash(password: str = "Password", salt=None, iterations=100000):
    if not salt:
        salt = os.urandom(32)
    hashed_password = hashlib.pbkdf2_hmac(
        "sha512", password.encode("utf-8"), salt, iterations
    )
    return hashed_password


def create_infinite_list(lst):
    while True:
        yield from lst


def get_day_of_week(year, month, day):
    date = datetime.datetime(year, month, day)
    return date.weekday()


def encrypt_user_data(data, passkeys):
    encrypted_first_name_birthday = encrypt(data["first_name"], data["birthday"])
    encrypted_last_name_country = encrypt(data["last_name"], data["country"])
    encrypted_primary_email = encrypt(data["primary_email"], data["first_name"])
    encrypted_primary_phone = encrypt(data["primary_phone"], data["last_name"])
    return {
        "primary_email": encrypted_primary_email,
        "primary_phone": encrypted_primary_phone,
        "first_name_birthday": encrypted_first_name_birthday,
        "last_name_country": encrypted_last_name_country,
        "authentication": data["authentication"],
        "encryption": data["encryption"],
        "data": data["data"],
        "is_encrypted": data["is_encrypted"],
        "signup_complete": data["signup_complete"],
    }


def authenticate():
    yield {"collect": "register-passkey", "messages": []}
    # NOTE: this app does not use usernames. Instead, it uses real names, emails, and phone numbers.
    messages = []
    emails = []
    phones = []
    first_name = ""
    last_name = ""
    year = 0
    month = 0
    day = 0
    country = None
    has_account = False
    while True:
        emails = yield {"collect": "primary-email", "messages": messages}
        messages = []
        for i, email in enumerate(emails):
            email, valid = check_email_valid(email)
            if not valid:
                messages.append(f"Email-{i}: Invalid email.")
            else:
                cursor.execute("SELECT email FROM emails WHERE email = ?", (email,))
                if cursor.fetchone():
                    has_account = True
                    # messages.append(f"Email-{i}: Email already in use.")
        if len(messages) == 0:
            break
    if has_account:
        while True:
            first_name = yield {"collect": "first-name", "messages": messages}
            messages = []
            if len(messages) == 0:
                break
    while True:
        phones = yield {"collect": "phones", "messages": messages}
        messages = []
        for i, phone in enumerate(phones):
            phone, valid = check_phonenumber_valid(phone)
            if not valid:
                messages.append(f"Phone number-{i}: Invalid phone number.")
            else:
                cursor.execute("SELECT phone FROM phones WHERE phone = ?", (phone,))
                if cursor.fetchone():
                    messages.append(f"Phone number-{i}: Phone number already in use.")
        if len(messages) == 0:
            break
    while True:
        country = yield {"collect": "country", "messages": messages}
        messages = []
        if len(messages) == 0:
            break
    while True:
        first_name, last_name = yield {"collect": "full-name", "messages": messages}
        messages = []
        if len(messages) == 0:
            break
    while True:
        # Birthday
        year, month, day = yield {"collect": "birthday", "messages": messages}
        messages = []
        try:
            year = int(year)
        except:
            messages.append("Invalid year.")
        if year > datetime.datetime.now().year:
            messages.append(
                "Time travelers are not permitted to use this application without permission."
            )
        if year < 1890:
            messages.append(
                "Unreasonable age. If you are a time traveler, please contact the us."
            )
        if month in MONTHS and MONTHS.index(month):
            month = MONTHS.index(month)
        else:
            try:
                month = int(month)
            except:
                messages.append("Invalid month.")
        if month < 1 or month > 12:
            messages.append("Invalid month.")
        print(month)
        try:
            day = int(day)
        except:
            messages.append("Invalid day.")
        if day < 1 or day > DAYS[MONTHS[month]] + (
            1 if month == 2 and year % 4 == 0 else 0
        ):
            messages.append("Invalid day.")
        if len(messages) == 0:
            break

    # TODO: Verify phone numbers and email addresses
    # signup expires in about 7 days if uncompleted
    # cursor.execute(
    #     "INSERT INTO emails VALUES (?, ?, ?)",
    #     (
    #         email,
    #         False,
    #         datetime.datetime.now()
    #         + datetime.timedelta(
    #             days=SIGNUP_EXPIRES_DAYS + random.randint(-2, 7),
    #             hours=random.randint(0, 23),
    #             minutes=random.randint(0, 59),
    #             seconds=random.randint(0, 59),
    #         ),
    #     ),
    # )
    # cursor.execute(
    #     "INSERT INTO phones VALUES (?, ?, ?)",
    #     (
    #         phone,
    #         False,
    #         datetime.datetime.now()
    #         + datetime.timedelta(
    #             days=SIGNUP_EXPIRES_DAYS + random.randint(-2, 7),
    #             hours=random.randint(0, 23),
    #             minutes=random.randint(0, 59),
    #             seconds=random.randint(0, 59),
    #         ),
    #     ),
    # )
    # The reason we use random here is so that a hacker cannot correlate the email and phone to the user just by the expiration date.

    # connection.commit()


def login(identifier):
    pass


# def check_username_valid(username):
#     # Only allow letters, numbers, underscores, and dashes. No spaces
#     return re.match("^[a-zA-Z0-9_-]+$", username) is not None


def check_phonenumber_valid(phone: str) -> tuple[str, bool]:
    try:
        phone = phonenumbers.parse(phone, "US")
        valid = phonenumbers.is_valid_number(phone)
        normalized = phonenumbers.format_number(
            phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
        return normalized, valid
    except phonenumbers.phonenumberutil.NumberParseException:
        return phone, False


def check_email_valid(email: str) -> tuple[str, bool]:
    try:
        email = email_validator.validate_email(email, check_deliverability=True)
        return email.normalized, True
    except email_validator.EmailNotValidError:
        return email, False


def parse_identifier(identifier: str) -> tuple[str, str, bool]:
    """
    Parse the given identifier to determine the type of identifier.
    :param identifier: The identifier to be parsed.
    :return: A tuple containing the type of identifier ("email", "phone", or "unknown"), the parsed identifier, and a boolean indicating if the identifier is valid.
    """
    is_email_valid = check_email_valid(identifier)
    if is_email_valid[1]:
        return "email", is_email_valid[0], True

    is_phone_valid = check_phonenumber_valid(identifier)
    if is_phone_valid[1]:
        return "phone", is_phone_valid[0], True
    return "unknown", identifier, False


def test():
    test_type = input("... ").lower()
    if test_type == "id":
        while True:
            inp = input("Enter an email address or phone number: ")
            if inp == "$exit":
                break
            print(parse_identifier(inp))
    elif test_type == "auth":
        id_type, email, valid = parse_identifier(input("Enter an email address: "))
        if not valid or id_type != "email":
            print("Invalid email address.")
            return
        id_type, phone, valid = parse_identifier(input("Enter a phone number: "))
        if not valid or id_type != "phone":
            print("Invalid phone number.")
            return
        # print(authenticate(email, phone))


if __name__ == "__main__":
    init()
    while True:
        test()
