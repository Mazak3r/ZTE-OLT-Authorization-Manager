# ZTE-OLT-Authorization-Manager

Automated network provisioning tool for ZTE GPON/EPON Optical Line Terminals (OLTs). Scans multiple OLTs for unconfigured ONUs, performs intelligent ID gap analysis, and pushes full configuration templates with a single click.

## Features

- **Multi-OLT Scanning**: Discover unconfigured ONUs across multiple OLTs simultaneously
- 
- **Intelligent ID Analysis**: Identify missing ONU IDs and recommend next available ID
- **One-Click Authorization**: Push complete ONU configuration (VLAN, traffic profiles, DHCP, security)
- **Real-Time Debug Output**: View every CLI command and response during provisioning
- **MAC Address Verification**: Retrieve and format MAC addresses post-provisioning
- **Authorization History**: Track all provisioned ONUs with timestamps
- **Web Dashboard**: Clean Streamlit interface for NOC operations



## Prerequisites

- Python 3.10+
- Access to ZTE OLTs via Telnet (port 23)
- Admin credentials for OLT access

## Installation


# Clone the repository
git clone https://github.com/Mazak3r/ZTEOLT-Authorization-Manager.git
cd ZTE-OLT-Authorization-Manager

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

#Configuration

# 1.Copy the example config file:

cp olt_config.example.py olt_config.py

#2. Edit olt_config.py with your OLT details:

python
olt_config = {
    "olt-name": {
        "ip": "192.168.1.10",
        "username": "admin",
        "password": "your-password"
    },
    # Add more OLTs as needed
}

#Usage

# Start the web interface
streamlit run app.py

# Access at http://localhost:8501

#Workflow

1. Select OLT(s) to scan from the sidebar

2. Click "Scan for Unconfigured ONUs"

3. Review discovered ONUs and ID analysis

4. Click "Authorize an Unconfigured ONU"

5. Fill in: Name, VLAN, Address, ONU Type

6. Click "Authorize ONU" and watch real-time provisioning

7. Check MAC address from authorization history

# Configuration Template

The tool pushes this configuration to each ONU:


configure terminal
interface gpon-olt_{port}
  onu {id} type {type} sn {serial}
!
interface gpon-onu_{port}:{id}
  name {name}
  description zone_Zone_descr_{address}_(Muslims_auto)_authd_{date}
  tcont 1 profile SMARTOLT-1G-UP
  gemport 1 tcont 1
  gemport 1 traffic-limit downstream SMARTOLT-1G-DOWN
  service-port 1 vport 1 user-vlan {vlan} vlan {vlan}
!
pon-onu-mng gpon-onu_{port}:{id}
  flow mode 1 tag-filter vlan-filter untag-filter discard
  flow 1 pri 0 vlan {vlan}
  gemport 1 flow 1
  switchport-bind switch_0/1 iphost 1
  switchport-bind switch_0/1 veip 1
  vlan-filter-mode iphost 1 tag-filter vlan-filter untag-filter discard
  vlan-filter iphost 1 pri 0 vlan {vlan}
  dhcp-ip ethuni eth_0/1 from-onu
  dhcp-ip ethuni eth_0/2 from-onu
  dhcp-ip ethuni eth_0/3 from-onu
  dhcp-ip ethuni eth_0/4 from-onu
  security-mgmt 998 state enable mode forward ingress-type lan protocol web https
  security-mgmt 999 state enable ingress-type lan protocol ftp telnet ssh snmp tr069
!
end
write

# Supported Commands
show gpon onu uncfg - Discover unconfigured ONUs

show gpon onu state - Check configured ONUs and their states

show mac gpon onu - Retrieve MAC addresses

Full configuration push with real-time feedback

# Tech Stack
Frontend: Streamlit

Backend: Python (AsyncIO, Telnetlib3)

Parsing: Regex for ZTE CLI output

Concurrency: Async telnet connections to multiple OLTs

# Limitations
Currently supports ZTE OLTs only (GPON/EPON)

Requires direct Telnet access (port 23)

Configuration template is hardcoded for SMARTOLT profiles

Single admin credential set for all OLTs

License
MIT License

Author
https://github.com/Mazak3r



---

## requirements.txt
streamlit>=1.28.0
telnetlib3>=2.0.0
pandas>=2.0.0
setuptools>=68.0.0

text

---





# Logs
*.log
