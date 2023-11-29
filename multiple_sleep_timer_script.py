#arg-0 script name
import sys
import subprocess
import os

output_name="quic_server_infer_Q046_timeout"

timeout=[8]

for val in timeout:
    print("\n\ncurrent dir:",os.getcwd())
    print(f"\n\nRunning Subprocess for {val}\n\n")
    subprocess.run(f"sudo python3 learn_server.py {val}",shell=True, check=True,capture_output=True)