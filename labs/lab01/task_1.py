import os
import random
import sys

from tabulate import tabulate

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords_list = [
    "SIEM@An4lysis",
    "easy123",
    "S0C@Analyst",
    "observer",
    "Threat@Hunt1ng",
    "viewer",
    "Incid3nt@Handle",
    "monitor",
    "Log@An4lysis",
    "watcher",
]
criteria = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"easy123", "observer", "viewer", "monitor", "watcher", "admin"}


def generate_duplicates(passwords: list, count: int = 3) -> list:
    updated_passwords = passwords.copy()
    random_indx = [random.randint(0, len(updated_passwords) - 1) for _ in range(count)]
    updated_passwords.extend([updated_passwords[idx] for idx in random_indx])
    return updated_passwords


def evaluate_passwords(passwords: list, rules: dict, forbidden: set) -> dict:
    passwords_status = {}

    for p in passwords:
        criteria_support = {
            "require_digits": any(char.isdigit() for char in p),
            "require_upper": any(char.isupper() for char in p),
            "require_special": any(not char.isalnum() for char in p),
            "minimal_long": int(len(p) > rules["min_length"]) * 4,
        }

        total = sum(criteria_support.values())

        if p in forbidden or len(p) < rules["min_length"]:
            passwords_status[p] = "Forbidden pwd"
        elif (
            len(p) > rules["min_length"] + 4 and total == 7 and passwords.count(p) == 1
        ):
            passwords_status[p] = "Very strong pwd"
        elif total == 7:
            passwords_status[p] = "Strong pwd"
        elif total > 5:
            passwords_status[p] = "Normal pwd"
        elif total > 1:
            passwords_status[p] = "Bad pwd"

    return passwords_status


def print_results(passwords_status: dict) -> None:
    table_data = [[pwd, status] for pwd, status in passwords_status.items()]
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )
    print(tabulate(table_data, headers=["Пароль", "Статус"], tablefmt="grid"))


if __name__ == "__main__":
    extended_passwords = generate_duplicates(passwords_list)
    results = evaluate_passwords(extended_passwords, criteria, forbidden_passwords)
    print_results(results)
