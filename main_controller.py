import os
import time
from datetime import datetime

BASE_PATH = r"C:\ThreatDetection"

while True:
    print(f"[{datetime.now()}] New detection cycle started")

    os.system(f'python "{BASE_PATH}\\rules\\log_rules.py"')
    os.system(f'python "{BASE_PATH}\\rules\\system_rules.py"')
    os.system(f'python "{BASE_PATH}\\analysis and correlation\\analysis_and_correlation.py"')
    os.system(f'python "{BASE_PATH}\\mitigation\\automated_mitigation_engine.py"')

    print(f"[{datetime.now()}] Cycle completed")
    time.sleep(600)