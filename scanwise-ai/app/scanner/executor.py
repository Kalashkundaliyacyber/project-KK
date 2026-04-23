"""Safe subprocess executor — no shell=True, strict timeout."""
import subprocess
import shutil
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 300  # 5 minutes max

class ScanExecutor:
    def execute(self, command: list, session_id: str) -> Tuple[str, str, int]:
        """Execute a command safely and return (stdout, stderr, returncode)."""
        if not command or command[0] != "nmap":
            return "", "Only nmap commands are allowed", 1

        if not shutil.which("nmap"):
            # nmap not installed — return simulated output for demo
            return self._demo_output(command), "", 0

        logger.info(f"[{session_id}] Executing: {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                shell=False,  # NEVER shell=True
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Scan timed out after {TIMEOUT_SECONDS}s", 1
        except FileNotFoundError:
            return self._demo_output(command), "", 0
        except Exception as e:
            return "", str(e), 1

    def _demo_output(self, command: str) -> str:
        """Return realistic demo XML output when nmap is not installed."""
        target = command[-1] if command else "192.168.1.1"
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="{' '.join(command)}" version="7.94" startstr="Demo Scan">
<host starttime="1700000000" endtime="1700000060">
<status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<hostnames><hostname name="{target}" type="PTR"/></hostnames>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="Apache httpd" version="2.2.34" extrainfo="(Unix)" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="443">
    <state state="open" reason="syn-ack"/>
    <service name="https" product="Apache httpd" version="2.2.34" extrainfo="(Unix)" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="3306">
    <state state="open" reason="syn-ack"/>
    <service name="mysql" product="MySQL" version="5.5.68" extrainfo="" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="21">
    <state state="open" reason="syn-ack"/>
    <service name="ftp" product="vsftpd" version="2.3.4" extrainfo="" conf="10" method="probed"/>
  </port>
</ports>
</host>
</nmaprun>'''
