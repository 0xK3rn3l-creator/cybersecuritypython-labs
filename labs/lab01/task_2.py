import os
import sys

from tabulate import tabulate

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
    "devsecops_lead": {
        "role": "devsecops",
        "clearance": 4,
        "department": "DevSecOps",
        "active": True,
    },
    "security_engineer": {
        "role": "security_engineer",
        "clearance": 3,
        "department": "Security Engineering",
        "active": True,
    },
    "automation_tech": {
        "role": "automation",
        "clearance": 2,
        "department": "Automation",
        "active": True,
    },
    "api_developer": {
        "role": "api_developer",
        "clearance": 2,
        "department": "API",
        "active": True,
    },
    "sandbox_env": {
        "role": "sandbox",
        "clearance": 1,
        "department": "Testing",
        "active": False,
    },
}

resources = [
    ("security_pipelines", 4),
    ("secure_coding_standards", 3),
    ("automation_scripts", 2),
    ("api_specifications", 2),
    ("threat_models", 4),
    ("testing_frameworks", 1),
    ("security_gates", 3),
    ("vulnerability_scans", 4),
    ("integration_tests", 2),
    ("mock_services", 1),
]

security_levels = ("Sandbox", "Development", "Secure", "Production Critical")
blocked_users = {"sandbox_env", "pipeline_breach", "automation_fail"}


def get_formatted_resources(res_list: list, levels: tuple) -> list:
    formatted = []
    for res_name, level_num in res_list:
        level_text = levels[level_num - 1]
        formatted.append((res_name, level_text))
    return formatted


def check_user_access(
    user_id: str, resource_level: int, users_dict: dict, blocked_set: set
) -> tuple:
    if user_id not in users_dict:
        return False, "User not found"

    if user_id in blocked_set:
        return False, "User is blocked"

    user_info = users_dict[user_id]

    if not user_info.get("active", False):
        return False, "Account inactive"

    if user_info.get("clearance", 0) >= resource_level:
        return True, "Access granted"
    else:
        return False, "Insufficient clearance"


def run_access_control_audit(
    users_dict: dict, res_list: list, blocked_set: set
) -> list:
    audit_results = []

    all_users_to_check = set(users_dict.keys()).union(blocked_set)

    for user_id in sorted(all_users_to_check):
        for res_name, res_level in res_list:
            is_allowed, reason = check_user_access(
                user_id, res_level, users_dict, blocked_set
            )

            if is_allowed:
                status_str = "ALLOW"
            else:
                status_str = f"DENY ({reason})"

            audit_results.append(
                {
                    "user": user_id,
                    "resource": res_name,
                    "status": status_str,
                    "is_allowed": is_allowed,
                }
            )

    return audit_results


def print_task2_results(formatted_resources: list, audit_results: list) -> None:

    print(
        f"=== Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER} ===\n"
    )

    print("--- СПИСОК РЕСУРСІВ СИСТЕМИ ---")
    res_table = [[name, lvl] for name, lvl in formatted_resources]
    print(tabulate(res_table, headers=["Ресурс", "Рівень безпеки"], tablefmt="grid"))
    print("\n" + "=" * 60 + "\n")

    print("--- РЕЗУЛЬТАТИ ПЕРЕВІРКИ ДОСТУПУ (LOG) ---")
    for log in audit_results:
        print(f"user=[{log['user']}] resource=[{log['resource']}] -> {log['status']}")


if __name__ == "__main__":
    res_formatted = get_formatted_resources(resources, security_levels)
    audit_logs = run_access_control_audit(users, resources, blocked_users)
    print_task2_results(res_formatted, audit_logs)
