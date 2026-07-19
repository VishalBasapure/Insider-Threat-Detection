import pandas as pd

# Load user profiles into memory. In production this would sit in Redis.
profiles = pd.read_csv('user_profiles.csv').set_index('user_id').to_dict('index')

SENSITIVITY_SCORE = {'low': 0, 'medium': 10, 'high': 25, 'restricted': 35}
ACTION_SCORE = {
    'export_data': 25,
    'admin_operation': 20,
    'api_call': 8,
    'sql_query': 5,
    'login': 2,
}


def classify_severity(score: int) -> str:
    if score >= 85:
        return 'CRITICAL'
    if score >= 65:
        return 'HIGH'
    if score >= 40:
        return 'MEDIUM'
    return 'LOW'


def score_event(event: dict, profile: dict, brief_reasons=False):
    score = 0
    reasons = []

    time_class = event['time_classification']
    if time_class in ['night', 'unusual_hours']:
        score += 20
        reason = f"Off-hours ({time_class})" if brief_reasons else f"Off-hours access ({time_class})"
        reasons.append(reason)

    sensitivity = event['resource_sensitivity']
    sens_score = SENSITIVITY_SCORE.get(sensitivity, 0)
    if sens_score:
        score += sens_score
        label = "Sensitive data" if brief_reasons else "Sensitive resource"
        reasons.append(f"{label} ({sensitivity})")

    action = event['action']
    action_score = ACTION_SCORE.get(action, 5)
    score += action_score
    if action_score >= 20:
        reasons.append(f"High-risk action: {action}")

    approved = str(profile.get('systems_access', '')).split('|')
    if event['resource'] not in approved:
        score += 20
        reason = "Unapproved resource" if brief_reasons else f"Unapproved resource: {event['resource']}"
        reasons.append(reason)

    privilege = profile.get('privilege_level', 'user')
    if privilege == 'user' and action == 'admin_operation':
        score += 30
        reason = "Privilege mismatch: user doing admin ops" if brief_reasons else "User privilege doing admin action"
        reasons.append(reason)

    if event['status'] == 'failure':
        score += 15
        reasons.append("Access attempt FAILED")

    inactive_days = profile.get('days_inactive', 0)
    if inactive_days > 30:
        score += 20
        reasons.append(f"Account inactive {inactive_days} days")

    if privilege == 'admin' and event['resource'] in approved:
        score = max(0, score - 25)

    score = min(score, 100)
    return score, classify_severity(score), reasons, privilege, inactive_days


def process_event(event: dict) -> dict:
    """
    This function is what Spark would run on each event.
    In production: deployed as a Spark Streaming job across 100 workers.
    In hackathon: runs in Python, same logic, same output.
    """
    user_id = event['user_id']
    profile = profiles.get(user_id, {})
    score, severity, reasons, privilege, _ = score_event(event, profile)

    return {
        **event,
        "risk_score": score,
        "severity": severity,
        "anomaly_reasons": reasons,
        "is_anomaly": 1 if score >= 40 else 0,
        "user_dept": profile.get('department', 'unknown'),
        "user_role": profile.get('job_title', 'unknown'),
        "privilege": privilege
    }
