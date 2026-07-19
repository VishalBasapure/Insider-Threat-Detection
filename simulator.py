import pandas as pd
import time


def simulate_kafka_stream(csv_path, events_per_second=10):
    """
    Reads CSV row by row and yields JSON events
    Simulates what Kafka would do in production
    """
    logs = pd.read_csv(csv_path, parse_dates=['timestamp'])
    
    print(f"[KAFKA SIMULATOR] Starting stream: {len(logs)} events")
    print(f"[KAFKA SIMULATOR] Rate: {events_per_second} events/sec")
    
    for _, row in logs.iterrows():
        # This is your "Kafka message" — pure JSON
        event = {
            "event_id": row.get('access_id', 'unknown'),
            "timestamp": str(row['timestamp']),
            "user_id": row['user_id'],
            "username": row['username'],
            "department": row['department'],
            "action": row['action'],
            "resource": row['resource'],
            "resource_sensitivity": row['resource_sensitivity'],
            "time_classification": row['time_classification'],
            "status": row['status']
        }
        
        yield event  # one event at a time, like Kafka
        time.sleep(1 / events_per_second)  # controls the rate
