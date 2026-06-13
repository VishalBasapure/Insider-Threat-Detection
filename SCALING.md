# How This Scales to 1M+ Events Per Day

## Current (Hackathon): Python Simulation
- `simulator.py` replays CSV rows at configurable speed
- `spark_processor.py` runs scoring logic per event in Python
- Processes 1,200 events in ~2 seconds locally

## Production Architecture (1M+ events/day = ~12 events/second)

### Step 1: Replace simulator with real Kafka
Every database, API, and file system sends events to a Kafka topic:
- Topic: `data-access-events`  
- Partitions: 12 (one per data source type)
- Retention: 7 days
- Throughput: handles 100k+ messages/second

### Step 2: Replace Python loop with Spark Streaming
The SAME scoring logic (process_event function) runs as a Spark job:
- Spark reads from Kafka topic in micro-batches (every 5 seconds)
- Parallelized across 20 worker nodes
- 1M events processed in under 60 seconds

### Step 3: User profiles in Redis (not CSV)
- 100 profiles fit in 1MB of RAM
- Redis lookup: sub-millisecond per event
- Profile updates propagate in real-time

### Step 4: Storage
- Raw events → Parquet files on S3, partitioned by date/user_id
- Alerts → PostgreSQL for dashboard queries
- Full-text search → Elasticsearch for investigation

### Performance math:
- 1M events/day = 11.6 events/second average
- Peak (9 AM surge): ~50 events/second
- Spark on 20 nodes: processes 10,000 events/second
- Headroom: 200x above peak load