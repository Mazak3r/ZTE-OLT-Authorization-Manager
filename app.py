"""
OLT ONU Manager - Automated GPON/EPON ONU Provisioning Tool
Copyright (c) 2026 Mazak3r
MIT License
"""

import streamlit as st
import asyncio
import telnetlib3
import re
import socket
from collections import defaultdict
from datetime import datetime
import concurrent.futures


# ---------- Configuration ----------
try:
    from olt_config import olt_config
except ImportError:
    st.error("⚠️ olt_config.py not found! Copy olt_config.example.py to olt_config.py and add your OLT details.")
    st.stop()


# ---------- Async Helper ----------
def run_async(coro):
    """Safely run async coroutine in Streamlit environment"""
    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        return asyncio.run(coro)


# ---------- Network Utilities ----------
def check_reachability(ip, port=23, timeout=3):
    """Check if OLT is reachable via telnet"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error):
        return False


def format_mac_address(mac):
    """Convert MAC from xxxx.xxxx.xxxx to xx:xx:xx:xx:xx:xx"""
    mac = mac.replace('.', '').replace(':', '').replace('-', '').lower()
    if len(mac) != 12:
        return mac
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))


# ---------- OLT Connection & Commands ----------
async def connect_and_login(olt_ip, username="admin", password="admin"):
    """Connect to OLT and authenticate"""
    reader, writer = await telnetlib3.open_connection(
        olt_ip, 23, connect_minwait=0.05, connect_maxwait=1
    )
    
    writer.write(f"{username}\n")
    await asyncio.sleep(0.5)
    writer.write(f"{password}\n")
    await asyncio.sleep(0.5)

    while True:
        chunk = await asyncio.wait_for(reader.read(1024), timeout=5)
        if "ZXAN>" in chunk or "ZXAN#" in chunk:
            break
    
    return reader, writer


async def get_command_output(reader, writer, command):
    """Execute command and return full output with pagination handling"""
    writer.write(command)
    
    output = ""
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(1024), timeout=5)
            if not chunk:
                break
            output += chunk
            if '--More--' in chunk:
                writer.write(' ')
                await asyncio.sleep(0.2)
            if "ZXAN>" in chunk or "ZXAN#" in chunk:
                break
        except asyncio.TimeoutError:
            break
    
    return output


async def send_command_debug(reader, writer, command, progress_placeholder, description=""):
    """Send command and display real-time output"""
    label = f"[{description}]" if description else ""
    progress_placeholder.text(f"📤 {label} {command.strip()}")
    
    writer.write(command)
    await asyncio.sleep(0.3)
    
    response = ""
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(1024), timeout=3)
            if not chunk:
                break
            response += chunk
            if any(prompt in chunk for prompt in ["ZXAN>", "ZXAN#", "ZXAN(config"]):
                break
        except asyncio.TimeoutError:
            break
    
    for line in response.strip().split('\n'):
        line = line.strip()
        if line:
            clean_line = re.sub(r'\$mt\s', 'security-mgmt ', line)
            progress_placeholder.text(f"📥 {clean_line}")
    
    return response


# ---------- ONU Discovery ----------
async def scan_unconfigured_onus(olt_ip, username, password, onu_type="gpon"):
    """Scan for all unconfigured ONUs using 'show gpon onu uncfg'"""
    unconfigured_by_port = defaultdict(list)
    
    try:
        reader, writer = await connect_and_login(olt_ip, username, password)
        command = f"show {onu_type.lower()} onu uncfg\n"
        output = await get_command_output(reader, writer, command)
        writer.close()
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or 'OnuIndex' in line or '---' in line or 'ZXAN' in line:
                continue
            
            match = re.search(r'(?:gpon|epon)-onu_(\d+/\d+/\d+):(\d+)\s+(\S+)\s+unknown', line)
            if match:
                port, onu_id, serial = match.group(1), int(match.group(2)), match.group(3)
                unconfigured_by_port[port].append({"onu_id": onu_id, "serial": serial})
        
    except Exception as e:
        st.error(f"Error scanning: {e}")
    
    return dict(unconfigured_by_port)


async def get_used_onu_ids(olt_ip, username, password, onu_type, port):
    """Get all currently used ONU IDs on a specific port"""
    used_ids = []
    
    try:
        reader, writer = await connect_and_login(olt_ip, username, password)
        olt_port = f"olt_{port}"
        command = f"show {onu_type.lower()} onu state {onu_type.lower()}-{olt_port}\n"
        output = await get_command_output(reader, writer, command)
        writer.close()
        
        if onu_type.lower() == "gpon":
            onu_lines = re.findall(r"(\d+/\d+/\d+):(\d+)\s+\w+\s+\w+\s+(\w+)", output)
            for _, onu_id, _ in onu_lines:
                used_ids.append(int(onu_id))
        
    except Exception as e:
        st.error(f"Error getting ONU IDs: {e}")
    
    return sorted(used_ids)


async def get_mac_address(olt_ip, username, password, onu_type, port, onu_id):
    """Get MAC address for an authorized ONU"""
    onu_interface = f"{onu_type}-onu_{port}:{onu_id}"
    
    try:
        reader, writer = await connect_and_login(olt_ip, username, password)
        command = f"show mac {onu_type} onu {onu_interface}\n"
        output = await get_command_output(reader, writer, command)
        writer.close()
        
        mac_entries = []
        for line in output.split('\n'):
            line = line.strip()
            if not line or 'Total mac' in line or 'Mac address' in line or '---' in line or 'ZXAN' in line:
                continue
            
            mac_match = re.match(r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\d+)\s+(\w+)', line)
            if mac_match:
                raw_mac, vlan, mac_type = mac_match.group(1), mac_match.group(2), mac_match.group(3)
                mac_entries.append({
                    "formatted_mac": format_mac_address(raw_mac),
                    "vlan": vlan,
                    "type": mac_type
                })
        
        return mac_entries if mac_entries else None
        
    except Exception:
        return None


def find_free_onu_id(used_ids):
    """Find the first available ONU ID"""
    if not used_ids:
        return 1
    for i in range(1, max(used_ids) + 2):
        if i not in used_ids:
            return i
    return 1


# ---------- ONU Authorization ----------
async def authorize_onu(olt_ip, username, password, onu_type, port, onu_id, serial, 
                        name, vlan, address, onu_type_config, progress_placeholder):
    """Push full ONU configuration to OLT"""
    olt_port = f"olt_{port}"
    onu_interface = f"{onu_type}-onu_{port}:{onu_id}"
    today_date = datetime.now().strftime("%Y%m%d")
    
    try:
        reader, writer = await connect_and_login(olt_ip, username, password)
        
        # Enter configuration mode
        await send_command_debug(reader, writer, "configure terminal\n", progress_placeholder, "Enter config mode")
        await asyncio.sleep(0.3)
        
        # ONU creation under OLT interface
        await send_command_debug(reader, writer, f"interface {onu_type}-{olt_port}\n", progress_placeholder, "Enter OLT interface")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, f"onu {onu_id} type {onu_type_config} sn {serial}\n", progress_placeholder, "Create ONU")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "!\n", progress_placeholder, "End section")
        await asyncio.sleep(0.3)
        
        # ONU interface configuration
        await send_command_debug(reader, writer, f"interface {onu_interface}\n", progress_placeholder, "Enter ONU interface")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, f"name {name}\n", progress_placeholder, "Set name")
        await asyncio.sleep(0.3)
        
        description = f"description zone_Zone_descr_{address}_(Muslims_auto)_authd_{today_date}\n"
        await send_command_debug(reader, writer, description, progress_placeholder, "Set description")
        await asyncio.sleep(0.3)
        
        await send_command_debug(reader, writer, "tcont 1 profile SMARTOLT-1G-UP\n", progress_placeholder, "Set tcont")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "gemport 1 tcont 1\n", progress_placeholder, "Set gemport")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "gemport 1 traffic-limit downstream SMARTOLT-1G-DOWN\n", progress_placeholder, "Set traffic limit")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, f"service-port 1 vport 1 user-vlan {vlan} vlan {vlan}\n", progress_placeholder, "Set service port")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "!\n", progress_placeholder, "End section")
        await asyncio.sleep(0.3)
        
        # PON ONU management
        await send_command_debug(reader, writer, f"pon-onu-mng {onu_interface}\n", progress_placeholder, "Enter PON ONU mng")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "flow mode 1 tag-filter vlan-filter untag-filter discard\n", progress_placeholder, "Set flow mode")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, f"flow 1 pri 0 vlan {vlan}\n", progress_placeholder, "Set flow")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "gemport 1 flow 1\n", progress_placeholder, "Bind gemport to flow")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "switchport-bind switch_0/1 iphost 1\n", progress_placeholder, "Bind switchport iphost")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "switchport-bind switch_0/1 veip 1\n", progress_placeholder, "Bind switchport veip")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "vlan-filter-mode iphost 1 tag-filter vlan-filter untag-filter discard\n", progress_placeholder, "Set vlan filter mode")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, f"vlan-filter iphost 1 pri 0 vlan {vlan}\n", progress_placeholder, "Set vlan filter")
        await asyncio.sleep(0.3)
        
        # DHCP
        for eth in range(1, 5):
            await send_command_debug(reader, writer, f"dhcp-ip ethuni eth_0/{eth} from-onu\n", progress_placeholder, f"DHCP eth_0/{eth}")
            await asyncio.sleep(0.3)
        
        # Security
        await send_command_debug(reader, writer, "security-mgmt 998 state enable mode forward ingress-type lan protocol web https\n", progress_placeholder, "Security mgmt 998")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "security-mgmt 999 state enable ingress-type lan protocol ftp telnet ssh snmp tr069\n", progress_placeholder, "Security mgmt 999")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "!\n", progress_placeholder, "End section")
        await asyncio.sleep(0.3)
        
        # Exit and save
        await send_command_debug(reader, writer, "end\n", progress_placeholder, "Exit config mode")
        await asyncio.sleep(0.3)
        await send_command_debug(reader, writer, "write\n", progress_placeholder, "Save config")
        await asyncio.sleep(1)
        
        writer.close()
        return True, f"✅ ONU {onu_id} on port {port} authorized successfully!"
        
    except Exception as e:
        return False, f"❌ Error: {e}"


# ---------- Streamlit UI ----------
st.set_page_config(page_title="OLT ONU Manager", page_icon="🔌", layout="wide")

st.markdown("""
<style>
.main-header { font-size: 2.5rem; font-weight: 700; color: #1f77b4; text-align: center; margin-bottom: 2rem; }
.sub-header { font-size: 1.5rem; font-weight: 600; color: #2c3e50; margin-top: 1rem; }
.mac-address { font-family: 'Courier New', monospace; font-size: 1.2rem; background: #f0f0f0; padding: 0.3rem 0.8rem; border-radius: 6px; display: inline-block; }
</style>
""", unsafe_allow_html=True)

st.markdown('<h1 class="main-header">🔌 OLT ONU Manager</h1>', unsafe_allow_html=True)

# Session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'authorize_mode' not in st.session_state:
    st.session_state.authorize_mode = False
if 'authorization_history' not in st.session_state:
    st.session_state.authorization_history = []
if 'mac_results' not in st.session_state:
    st.session_state.mac_results = {}

# Sidebar
st.sidebar.markdown('<h2 class="sub-header">📡 OLT Selection</h2>', unsafe_allow_html=True)

scan_mode = st.sidebar.radio("Scan Mode:", ["Single OLT", "All OLTs"])

if scan_mode == "Single OLT":
    selected_olt = st.sidebar.selectbox("Select OLT:", list(olt_config.keys()))
    olt_list = [selected_olt]
else:
    olt_list = list(olt_config.keys())
    st.sidebar.info(f"Will scan all {len(olt_list)} OLTs")

onu_type = st.sidebar.selectbox("ONU Type:", ["gpon", "epon"])
st.sidebar.markdown("---")

# Scan button
if st.sidebar.button("🔍 Scan for Unconfigured ONUs", type="primary", use_container_width=True):
    st.session_state.scan_results = {}
    st.session_state.authorize_mode = False
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for idx, olt_name in enumerate(olt_list):
        olt_info = olt_config[olt_name]
        olt_ip = olt_info["ip"]
        username = olt_info["username"]
        password = olt_info["password"]
        
        status_text.text(f"Checking {olt_name} ({olt_ip})...")
        
        if not check_reachability(olt_ip):
            st.warning(f"⚠️ {olt_name} ({olt_ip}) is unreachable")
            continue
        
        status_text.text(f"Scanning {olt_name}...")
        unconfigured = run_async(scan_unconfigured_onus(olt_ip, username, password, onu_type))
        
        if unconfigured:
            st.session_state.scan_results[olt_name] = {
                "ip": olt_ip, "username": username, "password": password, "unconfigured": unconfigured
            }
        
        progress_bar.progress((idx + 1) / len(olt_list))
    
    status_text.empty()
    progress_bar.empty()
    
    if st.session_state.scan_results:
        st.success(f"✅ Scan complete! Found unconfigured ONUs on {len(st.session_state.scan_results)} OLT(s)")
    else:
        st.info("ℹ️ No unconfigured ONUs found on any OLT")

# Main content - Scan Results
if st.session_state.scan_results:
    st.markdown("---")
    st.markdown('<h2 class="sub-header">📊 Scan Results</h2>', unsafe_allow_html=True)
    
    for olt_name, olt_data in st.session_state.scan_results.items():
        with st.expander(f"📍 {olt_name} ({olt_data['ip']})", expanded=True):
            unconfigured = olt_data['unconfigured']
            
            all_onus = []
            for port, onus in unconfigured.items():
                for onu in onus:
                    all_onus.append({"port": port, "onu_id": onu["onu_id"], "serial": onu["serial"]})
            
            st.markdown(f"**Found {len(all_onus)} unconfigured ONU(s)**")
            
            if all_onus:
                import pandas as pd
                df = pd.DataFrame(all_onus)
                df.index = range(1, len(df) + 1)
                df.columns = ["Port", "Current ONU ID", "Serial Number"]
                st.dataframe(df, use_container_width=True)
                
                st.markdown("---")
                st.markdown("**🔍 ONU ID Analysis per Port:**")
                
                for port in sorted(unconfigured.keys()):
                    used_ids = run_async(get_used_onu_ids(olt_data['ip'], olt_data['username'], olt_data['password'], onu_type, port))
                    free_id = find_free_onu_id(used_ids)
                    
                    col1, col2, col3 = st.columns(3)
                    with col1: st.markdown(f"**Port {port}**")
                    with col2: st.markdown(f"Used IDs: `{used_ids if used_ids else 'None'}`")
                    with col3: st.markdown(f"Next free ID: `{free_id}`")
    
    # Authorization section
    st.markdown("---")
    st.markdown('<h2 class="sub-header">🔧 Authorize ONU</h2>', unsafe_allow_html=True)
    
    if not st.session_state.authorize_mode:
        if st.button("✏️ Authorize an Unconfigured ONU", type="primary"):
            st.session_state.authorize_mode = True
            st.rerun()
    
    if st.session_state.authorize_mode:
        olt_names = list(st.session_state.scan_results.keys())
        selected_olt = st.selectbox("Select OLT:", olt_names)
        olt_data = st.session_state.scan_results[selected_olt]
        
        all_onus = []
        for port, onus in olt_data['unconfigured'].items():
            for onu in onus:
                all_onus.append({"port": port, "onu_id": onu["onu_id"], "serial": onu["serial"]})
        
        onu_options = [f"Port {onu['port']} - SN: {onu['serial']}" for onu in all_onus]
        selected_onu_idx = st.selectbox("Select ONU to authorize:", range(len(onu_options)), format_func=lambda x: onu_options[x])
        
        selected_onu = all_onus[selected_onu_idx]
        selected_port, selected_serial = selected_onu["port"], selected_onu["serial"]
        
        used_ids = run_async(get_used_onu_ids(olt_data['ip'], olt_data['username'], olt_data['password'], onu_type, selected_port))
        free_onu_id = find_free_onu_id(used_ids)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Port:** `{selected_port}`")
            st.markdown(f"**Serial:** `{selected_serial}`")
        with col2:
            st.markdown(f"**Free ONU ID:** `{free_onu_id}`")
            st.markdown(f"**Used IDs:** `{used_ids if used_ids else 'None'}`")
        
        st.markdown("---")
        st.markdown("### 📝 Configuration Details")
        
        name = st.text_input("ONU Name:", placeholder="e.g., Customer-Name-123")
        vlan = st.text_input("VLAN:", placeholder="e.g., 600")
        address = st.text_input("Address/Location:", placeholder="e.g., 123 Main Street")
        onu_type_config = st.text_input("ONU Type:", placeholder="e.g., ZTE-F660")
        
        if st.button("🚀 Authorize ONU", type="primary", use_container_width=True):
            if not all([name, vlan, address, onu_type_config]):
                st.error("❌ All fields are required!")
            elif not vlan.isdigit():
                st.error("❌ VLAN must be a number!")
            else:
                progress_placeholder = st.empty()
                
                with st.spinner("Authorizing ONU..."):
                    success, message = run_async(authorize_onu(
                        olt_data['ip'], olt_data['username'], olt_data['password'],
                        onu_type, selected_port, free_onu_id, selected_serial,
                        name, vlan, address, onu_type_config, progress_placeholder
                    ))
                
                if success:
                    st.success(message)
                    st.session_state.authorization_history.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "olt": selected_olt, "olt_ip": olt_data['ip'],
                        "username": olt_data['username'], "password": olt_data['password'],
                        "onu_type": onu_type, "port": selected_port, "onu_id": free_onu_id,
                        "serial": selected_serial, "name": name, "vlan": vlan,
                        "address": address, "onu_type_config": onu_type_config
                    })
                    st.balloons()
                    st.session_state.authorize_mode = False
                    st.rerun()
                else:
                    st.error(message)

# Authorization History & MAC Check
if st.session_state.authorization_history:
    st.markdown("---")
    st.markdown('<h2 class="sub-header">📜 Authorization History</h2>', unsafe_allow_html=True)
    
    for i, auth in enumerate(st.session_state.authorization_history):
        with st.expander(f"✅ {auth['timestamp']} - {auth['name']} (Port {auth['port']}, ONU {auth['onu_id']})", 
                        expanded=(i == len(st.session_state.authorization_history) - 1)):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown(f"**OLT:** {auth['olt']} ({auth['olt_ip']})")
                st.markdown(f"**Port:** {auth['port']}")
                st.markdown(f"**ONU ID:** {auth['onu_id']}")
            with col2:
                st.markdown(f"**Serial:** {auth['serial']}")
                st.markdown(f"**Name:** {auth['name']}")
                st.markdown(f"**Type:** {auth['onu_type_config']}")
            with col3:
                st.markdown(f"**VLAN:** {auth['vlan']}")
                st.markdown(f"**Address:** {auth['address']}")
                st.markdown(f"**Date:** {auth['timestamp']}")
            
            st.markdown("---")
            
            mac_key = f"{auth['olt_ip']}_{auth['port']}_{auth['onu_id']}"
            
            if mac_key in st.session_state.mac_results:
                mac_data = st.session_state.mac_results[mac_key]
                if mac_data:
                    st.markdown("### 🖥️ MAC Address(es):")
                    for entry in mac_data:
                        st.markdown(f"""
                        <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                            <span class="mac-address">{entry['formatted_mac']}</span>
                            &nbsp;&nbsp;|&nbsp;&nbsp; VLAN: <code>{entry['vlan']}</code>
                            &nbsp;&nbsp;|&nbsp;&nbsp; Type: <code>{entry['type']}</code>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning("⚠️ No MAC address found. ONU may not be online yet.")
            else:
                if st.button(f"🔍 Check MAC Address", key=f"mac_btn_{i}"):
                    with st.spinner("Checking MAC address..."):
                        mac_entries = run_async(get_mac_address(
                            auth['olt_ip'], auth['username'], auth['password'],
                            auth['onu_type'], auth['port'], auth['onu_id']
                        ))
                        st.session_state.mac_results[mac_key] = mac_entries
                        st.rerun()

elif not st.session_state.scan_results:
    st.markdown("---")
    st.info("👈 Select an OLT and click **Scan for Unconfigured ONUs** to begin")

# Footer
st.markdown("---")
st.markdown("<p style='text-align: center; color: #666;'>OLT ONU Manager v1.0 | MIT License</p>", unsafe_allow_html=True)
