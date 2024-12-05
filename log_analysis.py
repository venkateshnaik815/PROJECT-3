import re
from collections import defaultdict, Counter
import csv

# Load log file
log_file = ""

# Parse log file
def parse_log_file(file_path):
    with open(file_path, "r") as file:
        return file.readlines()

# Task 1: Count requests per IP address
def count_requests_per_ip(logs):
    ip_counts = Counter()
    ip_pattern = r"^(\d+\.\d+\.\d+\.\d+)"
    
    for log in logs:
        match = re.match(ip_pattern, log)
        if match:
            ip_counts[match.group(1)] += 1
    
    return ip_counts

# Task 2: Identify the most frequently accessed endpoint
def find_most_accessed_endpoint(logs):
    endpoint_counts = Counter()
    endpoint_pattern = r'\"[A-Z]+\s(\/[^\s]*)\sHTTP'
    
    for log in logs:
        match = re.search(endpoint_pattern, log)
        if match:
            endpoint_counts[match.group(1)] += 1
    
    most_accessed = endpoint_counts.most_common(1)
    return most_accessed[0] if most_accessed else ("None", 0)

# Task 3: Detect suspicious activity
def detect_suspicious_activity(logs, threshold=10):
    failed_logins = defaultdict(int)
    failed_pattern = r"^(\d+\.\d+\.\d+\.\d+).+\"POST\s/login.+401"

    for log in logs:
        match = re.match(failed_pattern, log)
        if match:
            failed_logins[match.group(1)] += 1
    
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return flagged_ips

# Save results to CSV
def save_to_csv(ip_requests, most_accessed, suspicious_activities):
    with open("log_analysis_results.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main function
def main():
    logs = parse_log_file(log_file)
    
    # Task 1
    ip_requests = count_requests_per_ip(logs)
    print("IP Address           Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:20} {count}")
    
    # Task 2
    most_accessed = find_most_access
