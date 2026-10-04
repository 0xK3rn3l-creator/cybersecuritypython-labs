import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from task_1 import (
    criteria,
    evaluate_passwords,
    forbidden_passwords,
    generate_duplicates,
    passwords_list,
)
from task_1 import (
    print_results as print_task1_results,
)
from task_2 import (
    blocked_users,
    get_formatted_resources,
    print_task2_results,
    resources,
    run_access_control_audit,
    security_levels,
    users,
)
from task_3 import (
    ValidationError,
    create_users,
    login,
    print_task3_results,
    read_users_db,
    users_to_register,
)


def main():
    print("=" * 70)
    print("ЛАБОРАТОРНА РОБОТА №1: КІБЕРБЕЗПЕКА ТА МОДУЛЬНИЙ PYTHON")
    print("=" * 70 + "\n")

    # ЗАВДАННЯ 1
    print(">>> ЗАВДАННЯ 1: Аналіз надійності паролів <<<\n")
    extended_passwords = generate_duplicates(passwords_list, count=3)
    passwords_status = evaluate_passwords(
        extended_passwords, criteria, forbidden_passwords
    )
    print_task1_results(passwords_status)

    print("\n" + "=" * 70 + "\n")

    # ЗАВДАННЯ 2
    print(">>> ЗАВДАННЯ 2: Система контролю доступу (Clearance) <<<\n")
    formatted_resources = get_formatted_resources(resources, security_levels)
    audit_results = run_access_control_audit(users, resources, blocked_users)
    print_task2_results(formatted_resources, audit_results)

    print("\n" + "=" * 70 + "\n")

    # ЗАВДАННЯ 3
    print(">>> ЗАВДАННЯ 3: Хешування, CSV-база та JSON-логування <<<\n")
    try:
        create_users(users_to_register)

        db_data = read_users_db()
        print_task3_results(db_data)

        print("\n--- ТЕСТУВАННЯ АВТЕНТИФІКАЦІЇ ТА ЛОГУВАННЯ (log.json) ---")

        res1 = login("admin_sec", "AdminPass123!")
        print(f"1. Вхід admin_sec (вірний пароль): {'SUCCESS' if res1 else 'FAILED'}")

        res2 = login("admin_sec", "WrongPassword")
        print(f"2. Вхід admin_sec (невірний пароль): {'SUCCESS' if res2 else 'FAILED'}")

        res3 = login("hacker", "SomePass123")
        print(f"3. Вхід hacker (неіснуючий): {'SUCCESS' if res3 else 'FAILED'}")

        print("\n[OK] Події успішно залоговано в labs/lab01/data/log.json")

    except (OSError, ValidationError, ValueError) as e:
        print(f"[ОБРОБКА ВИНЯТКУ] Сталася помилка при виконанні Завдання 3: {e}")


if __name__ == "__main__":
    main()
