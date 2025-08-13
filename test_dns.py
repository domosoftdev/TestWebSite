import dns.resolver
import time

hostname = "google.com"
records_to_check = ['NS', 'A', 'MX']

for record_type in records_to_check:
    print(f"Querying {record_type} for {hostname}...")
    start_time = time.time()
    try:
        answers = dns.resolver.resolve(hostname, record_type)
        duration = time.time() - start_time
        print(f"  -> Success in {duration:.2f} seconds. Found {len(answers)} records.")
        for rdata in answers:
            print(f"     - {rdata.to_text()}")
    except Exception as e:
        duration = time.time() - start_time
        print(f"  -> Failed in {duration:.2f} seconds: {e}")

print("\nDNS test complete.")
