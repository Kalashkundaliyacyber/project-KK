"""
Scan Executor
Runs nmap as a safe subprocess. Falls back to simulation if nmap not installed.
shell=False always. No arbitrary command execution.
"""
import subprocess
import time
import shutil

SCAN_TIMEOUT = 300  # 5 minutes


def execute_scan(cmd: list, target: str, scan_type: str):
    """
    Execute a safe nmap command list.
    Returns (raw_text_output, xml_output, duration_seconds)
    """
    if not shutil.which("nmap"):
        return _simulated_scan(target, scan_type)

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SCAN_TIMEOUT,
            shell=False,
            text=True
        )
        duration = round(time.time() - start, 2)
        xml_output = result.stdout
        raw_output = result.stderr + "\n" + xml_output
        if result.returncode not in (0, 1):
            raise RuntimeError(f"nmap exit {result.returncode}: {result.stderr[:200]}")
        return raw_output, xml_output, duration
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Scan timed out after {SCAN_TIMEOUT}s")
    except FileNotFoundError:
        raise RuntimeError("nmap not found. Install: sudo apt install nmap")


def _simulated_scan(target: str, scan_type: str):
    """Realistic simulated output when nmap is not installed."""
    time.sleep(1.2)
    sims = {
        "tcp_basic":      _sim_tcp(target),
        "tcp_syn":        _sim_tcp(target),
        "service_detect": _sim_service(target),
        "version_deep":   _sim_service(target),
        "enum_scripts":   _sim_service(target),
        "udp_scan":       _sim_udp(target),
        "os_detect":      _sim_os(target),
        "port_range":     _sim_tcp(target),
    }
    xml = sims.get(scan_type, _sim_service(target))
    raw = f"[SIMULATED - nmap not installed]\nTarget: {target}\nType: {scan_type}\n\n{xml}"
    return raw, xml, 1.2


def _sim_service(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV {target}" version="7.95" xmloutputversion="1.05">
<host starttime="1720000000" endtime="1720000010">
<status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<hostnames><hostname name="{target}" type="user"/></hostnames>
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
    <service name="https" product="Apache httpd" version="2.2.34" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="3306">
    <state state="open" reason="syn-ack"/>
    <service name="mysql" product="MySQL" version="5.5.62" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="21">
    <state state="open" reason="syn-ack"/>
    <service name="ftp" product="vsftpd" version="2.3.4" conf="10" method="probed"/>
  </port>
</ports>
<times srtt="500" rttvar="250" to="100000"/>
</host>
<runstats>
  <finished elapsed="10.00" exit="success" summary="1 IP address scanned"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""


def _sim_tcp(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT {target}" version="7.95" xmloutputversion="1.05">
<host starttime="1720000000" endtime="1720000005">
<status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" conf="3" method="table"/></port>
  <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" conf="3" method="table"/></port>
  <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" conf="3" method="table"/></port>
  <port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/><service name="mysql" conf="3" method="table"/></port>
  <port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/><service name="ftp" conf="3" method="table"/></port>
  <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http-proxy" conf="3" method="table"/></port>
</ports>
</host>
<runstats><finished elapsed="5.00" exit="success" summary="1 IP address scanned"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""


def _sim_udp(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sU {target}" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<ports>
  <port protocol="udp" portid="53">
    <state state="open" reason="udp-response"/>
    <service name="domain" product="ISC BIND" version="9.9.5" conf="10" method="probed"/>
  </port>
  <port protocol="udp" portid="161">
    <state state="open" reason="udp-response"/>
    <service name="snmp" product="net-snmp" version="5.7.2" conf="10" method="probed"/>
  </port>
</ports>
</host>
<runstats><finished elapsed="20.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""


def _sim_os(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -O {target}" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" conf="3" method="table"/></port>
  <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" conf="3" method="table"/></port>
</ports>
<os>
  <osmatch name="Linux 5.4 - 5.15" accuracy="96" line="58447">
    <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"/>
  </osmatch>
</os>
</host>
<runstats><finished elapsed="8.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""
