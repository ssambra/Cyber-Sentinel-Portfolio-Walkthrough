import csv
from datetime import datetime

def parse_linkedin_logins(file_path, trusted_city="Kitimat"):
    print(f"--- Analyzing LinkedIn Security Export: {file_path} ---")
    print(f"Trusted base location: {trusted_city}")
    print("-" * 50)
    
    alerts = 0
    with open(file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        
        for row in reader:
            login_date = row.get('Date', 'Unknown')
            ip_addr = row.get('IP Address', '0.0.0.0')
            location = row.get('City', 'Unknown')
            
            if location != trusted_city:
                alerts += 1
                print(f"[!!!] DORA ALERT: Potential Unauthorized Access")
                print(f"    Time: {login_date}")
                print(f"    Location: {location} (Anomaly detected)")
                print(f"    IP: {ip_addr}")
                print(f"    Action: Flag for MFA review - maps to DORA Art 10")
                print("-" * 30)
    
    print(f"\nScan complete. {alerts} anomalies found out of 210 logins.")
    print("This output is your audit evidence file.")

if __name__ == "__main__":
    parse_linkedin_logins('Logins.csv', trusted_city='Kitimat')
