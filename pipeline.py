from simulator import simulate_kafka_stream
from spark_processor import process_event


def run_pipeline(csv_path, events_per_second=10, max_events=None):
    """
    Main pipeline: Kafka simulator → Spark processor → output
    In production: replace this with actual Kafka consumer + Spark job
    """
    alerts = []
    total = 0
    
    print("\n" + "="*60)
    print("INSIDER THREAT DETECTION PIPELINE — LIVE")
    print("="*60)
    
    for event in simulate_kafka_stream(csv_path, events_per_second):
        
        # This is what Spark does per event
        result = process_event(event)
        total += 1
        
        # Only surface HIGH and CRITICAL to the dashboard
        if result['severity'] in ['CRITICAL', 'HIGH']:
            alerts.append(result)
            print(f"\n🚨 {result['severity']} | Score: {result['risk_score']}/100")
            print(f"   User: {result['username']} ({result['user_dept']})")
            print(f"   Action: {result['action']} → {result['resource']}")
            print(f"   Time: {result['timestamp']} ({result['time_classification']})")
            print(f"   Reasons: {' | '.join(result['anomaly_reasons'])}")
        
        if total % 50 == 0:
            print(f"\n[PIPELINE] Processed {total} events... "
                  f"{len(alerts)} alerts raised so far")
        
        if max_events and total >= max_events:
            break
    
    print(f"\n{'='*60}")
    print(f"PIPELINE COMPLETE: {total} events | {len(alerts)} alerts")
    return alerts

if __name__ == "__main__":
    alerts = run_pipeline('data_access_logs.csv', events_per_second=50)
    
    # Save for dashboard
    import pandas as pd
    pd.DataFrame(alerts).to_csv('alerts_output.csv', index=False)
    print("Alerts saved to alerts_output.csv")
