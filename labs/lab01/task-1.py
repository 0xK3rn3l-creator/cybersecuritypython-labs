import sys
import os
import random
from tabulate import tabulate
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

passwords = [
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

random_indx = [random.randint(0, len(passwords) - 1) for i in range(3)]
passwords.extend([passwords[idx] for idx in random_indx])
paswords_status = {}
criteria_support = {}
for p in passwords:
    criteria_support["require_digits"] = any(char.isdigit() for char in p)
    criteria_support["require_upper"] = any(char.isupper() for char in p)
    criteria_support["require_special"] = any(not char.isalnum() for char in p)
    criteria_support["minimal_long"] = int(len(p)>criteria["min_length"] )*4
    total = sum(criteria_support.values())
    if p in forbidden_passwords or len(p) < criteria["min_length"]:
        paswords_status[p] = "Forbidden pwd "
    elif (
        len(p) > criteria["min_length"] + 4 and total == 7 and passwords.count(p) == 1

    ):
        paswords_status[p] = "Very strong pwd"
    elif (total == 7):
        paswords_status[p] = "Strong pwd "
    elif (total>5):
        paswords_status[p] = "Normal pwd"
    elif total > 1 :
        paswords_status[p] = "Bad pwd "

table_data = [[pwd, status] for pwd, status in paswords_status.items()]

print(tabulate(table_data, headers=["Пароль", "Статус"], tablefmt="grid"))