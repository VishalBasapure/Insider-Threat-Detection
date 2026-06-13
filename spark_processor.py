import pandas as pd

# Load user profiles into memory — in production this is Redis cache
profiles = pd.read_csv('user_profiles.csv').set_index('user_id').to_dict('index')

def process_event(event: dict) -> dict:
    """
    This function is what Spark would run on each event.
    In production: deployed as a Spark Streaming job across 100 workers.
    In hackathon: runs in Python, same logic, same output.
    """
    user_id = event['user_id']
    profile = profiles.get(user_id, {})
    
    score = 0
    reasons = []
    
    # Signal 1: Time of access
    if event['time_classification'] in ['night', 'unusual_hours']:
        score += 20
        reasons.append(f"Off-hours access ({event['time_classification']})")
    
    # Signal 2: Data sensitivity
    sensitivity_score = {'low': 0, 'medium': 10, 'high': 25, 'restricted': 35}
    s = sensitivity_score.get(event['resource_sensitivity'], 0)
    if s > 0:
        score += s
        reasons.append(f"Sensitive resource ({event['resource_sensitivity']})")
    
    # Signal 3: Action type
    action_score = {'export_data': 25, 'admin_operation': 20, 
                    'api_call': 8, 'sql_query': 5, 'login': 2}
    a = action_score.get(event['action'], 5)
    score += a
    if a >= 20:
        reasons.append(f"High-risk action: {event['action']}")
    
    # Signal 4: Resource not in approved systems
    approved = str(profile.get('systems_access', '')).split('|')
    if event['resource'] not in approved:
        score += 20
        reasons.append(f"Unapproved resource: {event['resource']}")
    
    # Signal 5: Privilege mismatch
    privilege = profile.get('privilege_level', 'user')
    if privilege == 'user' and event['action'] == 'admin_operation':
        score += 30
        reasons.append("User privilege doing admin action")
    
    # Signal 6: Failed access attempt
    if event['status'] == 'failure':
        score += 15
        reasons.append("Access attempt FAILED")
    
    # Signal 7: Stale account
    inactive_days = profile.get('days_inactive', 0)
    if inactive_days > 30:
        score += 20
        reasons.append(f"Account inactive {inactive_days} days")
    
    # False positive suppression
    if privilege == 'admin' and event['resource'] in approved:
        score = max(0, score - 25)  # admin doing their job
    
    score = min(score, 100)
    
    severity = 'CRITICAL' if score >= 85 else \
               'HIGH' if score >= 65 else \
               'MEDIUM' if score >= 40 else 'LOW'
    
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