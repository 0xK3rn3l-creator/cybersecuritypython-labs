users = {
 "devsecops_lead": {"role": "devsecops", "clearance": 4, "department":
"DevSecOps", "active": True},
 "security_engineer": {"role": "security_engineer", "clearance": 3,
"department": "Security Engineering", "active": True},
 "automation_tech": {"role": "automation", "clearance": 2, "department":
"Automation", "active": True},
 "api_developer": {"role": "api_developer", "clearance": 2, "department":
"API", "active": True},
 "sandbox_env": {"role": "sandbox", "clearance": 1, "department": "Testing",
"active": False}
}
resources = [("security_pipelines", 4), ("secure_coding_standards", 3),
("automation_scripts", 2), ("api_specifications", 2), ("threat_models", 4),
("testing_frameworks", 1), ("security_gates", 3), ("vulnerability_scans", 4),
("integration_tests", 2), ("mock_services", 1)]
security_levels = ("Sandbox", "Development", "Secure", "Production Critical")
blocked_users = {"sandbox_env", "pipeline_breach", "automation_fail"}

