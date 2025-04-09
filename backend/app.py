# Imports
import logging
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import subprocess
import wmi
import pythoncom
from flask_cors import CORS
from sqlalchemy import text
import platform
import socket
import ipaddress
import concurrent.futures
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import requests
import win32com.client
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pytz
import winrm
import json
import re


# Load environment variables
load_dotenv()

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask setup
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define models


class Devices(db.Model):
    __tablename__ = 'Devices'
    id = db.Column(db.Integer, primary_key=True)
    IP_Address = db.Column(db.String(50), unique=True, nullable=False)
    Collection_Status = db.Column(
        db.Enum('Success', 'Failed'), default='Success')
    Collection_Time = db.Column(db.DateTime, default=datetime.now)

    os_info = db.relationship(
        'OS_Info', backref='device', cascade='all, delete-orphan', lazy=True)
    system_info = db.relationship(
        'System_Info', backref='device', cascade='all, delete-orphan', lazy=True)
    software = db.relationship(
        'Installed_Software', backref='device', cascade='all, delete-orphan', lazy=True)


class OS_Info(db.Model):
    __tablename__ = 'OS_Info'
    id = db.Column(db.Integer, primary_key=True)
    IP_Address = db.Column(db.String(50), db.ForeignKey(
        'Devices.IP_Address'), nullable=False)
    OS_Name = db.Column(db.String(255))
    OS_Version = db.Column(db.String(100))
    Architecture = db.Column(db.String(20))
    windows_updates_available = db.Column(db.Boolean, default=False)
    security_updates_available = db.Column(db.Boolean, default=False)
    driver_updates_available = db.Column(db.Boolean, default=False)
    # Comma-separated list of KB versions
    available_updates = db.Column(db.Text)
    os_kb_version = db.Column(db.String(100))  # Current installed KB version
    approved = db.Column(db.Boolean, default=False)


class System_Info(db.Model):
    __tablename__ = 'System_Info'
    id = db.Column(db.Integer, primary_key=True)
    IP_Address = db.Column(db.String(50), db.ForeignKey(
        'Devices.IP_Address'), nullable=False)
    Processor = db.Column(db.String(255))
    RAM_Size = db.Column(db.String(50))
    Model = db.Column(db.String(45))
    Disk_Size = db.Column(db.String(50))


class Installed_Software(db.Model):
    __tablename__ = 'Installed_Software'
    id = db.Column(db.Integer, primary_key=True)
    IP_Address = db.Column(db.String(50), db.ForeignKey(
        'Devices.IP_Address'), nullable=False)
    Software_Name = db.Column(db.String(255))
    Version = db.Column(db.String(50))
    Installation_Date = db.Column(db.Date)
    update_available = db.Column(db.Boolean, default=False)


class PendingUpdates(db.Model):
    __tablename__ = 'PendingUpdates'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), db.ForeignKey(
        'Devices.IP_Address'), nullable=False)
    kb_code = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(255))
    size_mb = db.Column(db.Float)
    reboot_required = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, default=False)
    check_time = db.Column(db.DateTime, default=datetime.now)
    approval_time = db.Column(db.DateTime)
    updated = db.Column(db.Boolean, default=False)

class InstalledSoftwareUpdates(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(15), nullable=False)
    software_name = db.Column(db.String(255), nullable=False)
    current_version = db.Column(db.String(50), nullable=False)
    available_version = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class NetworkScanResults(db.Model):
    __tablename__ = 'NetworkScanResults'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)
    hostname = db.Column(db.String(255))
    status = db.Column(db.String(50))
    scan_time = db.Column(db.DateTime, default=datetime.now)

# New model to track sent email notifications


class UpdateNotificationLog(db.Model):
    __tablename__ = 'UpdateNotificationLog'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)
    # e.g., "KB12345", "Chrome", "Firefox"
    update_type = db.Column(db.String(50), nullable=False)
    notification_date = db.Column(db.Date, default=datetime.now().date)
    retry_count = db.Column(db.Integer, default=0)


class ChocolateyOutdatedPackages(db.Model):
    __tablename__ = 'Outdated_Softwares'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), db.ForeignKey(
        'Devices.IP_Address'), nullable=False)
    software_name = db.Column(db.String(255), nullable=False)
    current_version = db.Column(db.String(50), nullable=False)
    available_version = db.Column(db.String(50), nullable=False)
    check_time = db.Column(db.DateTime, default=datetime.now)
    approved = db.Column(db.Boolean, default=False)
    updated = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<ChocolateyOutdatedPackages {self.software_name} on {self.ip_address}>"


# Initialize database tables
with app.app_context():
    db.create_all()

# Cache for latest versions
latest_versions_cache = {
    'chrome': None,
    'firefox': None,
    'last_updated': None
}


def fetch_latest_versions():
    """Fetch the latest versions of browsers and store them in a cache."""
    latest_versions = {
        'chrome': None,
        'firefox': None
    }

    try:
        # Fetch latest Chrome version
        chrome_response = requests.get(
            "https://omahaproxy.appspot.com/all.json")
        chrome_data = chrome_response.json()
        for entry in chrome_data:
            if entry['os'] == 'win':
                latest_versions['chrome'] = entry['versions'][0]['version']
                break

        # Fetch latest Firefox version
        firefox_response = requests.get(
            "https://product-details.mozilla.org/1.0/firefox_versions.json")
        firefox_data = firefox_response.json()
        latest_versions['firefox'] = firefox_data['LATEST_FIREFOX_VERSION']
    except Exception as e:
        logger.error(f"Error fetching latest versions: {str(e)}")

    return latest_versions


def get_latest_versions():
    """Get the latest versions from the cache or fetch them if the cache is stale."""
    global latest_versions_cache

    if not latest_versions_cache['last_updated'] or (datetime.now() - latest_versions_cache['last_updated']) > timedelta(hours=1):
        latest_versions_cache = {
            'chrome': fetch_latest_versions()['chrome'],
            'firefox': fetch_latest_versions()['firefox'],
            'last_updated': datetime.now()
        }

    return latest_versions_cache


def check_windows_updates(wmi_connection):
    """Check for Windows updates, security updates, and driver updates."""
    update_session = win32com.client.Dispatch("Microsoft.Update.Session")
    update_searcher = update_session.CreateUpdateSearcher()

    # Search for all updates
    search_result = update_searcher.Search("IsInstalled=0")

    updates = {
        'windows_updates_available': False,
        'security_updates_available': False,
        'driver_updates_available': False,
        'available_updates': []  # List to store KB versions
    }

    for update in search_result.Updates:
        kb_ids = [f"KB{kb_id}" for kb_id in update.KBArticleIDs if kb_id]
        if update.Type == 1:  # Windows Update
            updates['windows_updates_available'] = True
            updates['available_updates'].extend(kb_ids)
        elif update.Type == 2:  # Security Update
            updates['security_updates_available'] = True
            updates['available_updates'].extend(kb_ids)
        elif update.Type == 3:  # Driver Update
            updates['driver_updates_available'] = True
            updates['available_updates'].extend(kb_ids)

    updates['available_updates'] = list(
        set(updates['available_updates']))  # Remove duplicates
    return updates


def check_browser_updates(installed_software):
    """Check for updates for Google Chrome and Firefox using cached latest versions."""
    browser_updates = {
        'chrome': {'update_available': False, 'latest_version': None},
        'firefox': {'update_available': False, 'latest_version': None}
    }

    latest_versions = get_latest_versions()

    for software in installed_software:
        if software['name'].lower() == 'google chrome':
            if latest_versions['chrome'] and software['version'] != latest_versions['chrome']:
                browser_updates['chrome']['update_available'] = True
                browser_updates['chrome']['latest_version'] = latest_versions['chrome']
        elif software['name'].lower() == 'mozilla firefox':
            if latest_versions['firefox'] and software['version'] != latest_versions['firefox']:
                browser_updates['firefox']['update_available'] = True
                browser_updates['firefox']['latest_version'] = latest_versions['firefox']

    return browser_updates


def collect_endpoint_info(ip, username, password):
    """Collect all information from a specified endpoint."""
    logger.info(f"Starting collection for endpoint: {ip}")

    result = {
        'IP_Address': ip,
        'Collection_Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'Collection_Status': 'Failed',
        'OS_Info': {},
        'System_Info': {},
        'Installed_Software': [],
        'Updates': {
            'windows_updates_available': False,
            'security_updates_available': False,
            'driver_updates_available': False,
            'available_updates': [],
            'browser_updates': {
                'chrome': {'update_available': False, 'latest_version': None},
                'firefox': {'update_available': False, 'latest_version': None}
            }
        }
    }

    try:
        pythoncom.CoInitialize()

        wmi_connection = wmi.WMI(computer=ip, user=username, password=password)

        result['OS_Info'] = get_os_info(wmi_connection)
        result['System_Info'] = get_system_info(wmi_connection)
        result['Installed_Software'] = get_installed_software(wmi_connection)

        result['Collection_Status'] = 'Success'

        logger.info(f"Successfully collected information from {ip}")
    except wmi.x_wmi as wmi_error:
        error_msg = str(wmi_error)
        logger.error(f"WMI error connecting to {ip}: {error_msg}")
        if "rpc server is unavailable" in error_msg.lower():
            result['Collection_Status'] = 'RPC Server Unavailable'
            result['Error'] = f"RPC server unavailable on {ip}."
        elif "access denied" in error_msg.lower():
            result['Collection_Status'] = 'Access Denied'
            result['Error'] = f"Access denied on {ip}."
        else:
            result['Error'] = error_msg
    except Exception as e:
        logger.error(f"Unexpected error collecting data from {ip}: {str(e)}")
        result['Error'] = str(e)
    finally:
        pythoncom.CoUninitialize()

    return result


def get_os_info(wmi_connection):
    """Collect operating system information from WMI."""
    os_info = {}
    for os in wmi_connection.query('SELECT * FROM Win32_OperatingSystem'):
        os_info['name'] = os.Name.split('|')[0]  # Remove extra info after |
        os_info['version'] = os.Version
        os_info['architecture'] = os.OSArchitecture
        # Could be enhanced to get specific KB
        os_info['os_kb_version'] = os.Version
    return os_info


def get_system_info(wmi_connection):
    """Collect system information from WMI."""
    system_info = {}
    for system in wmi_connection.query('SELECT * FROM Win32_ComputerSystem'):
        system_info['manufacturer'] = system.Manufacturer
        system_info['Model'] = system.Model
        system_info['cpu'] = system.Name
        system_info['ram_gb'] = round(
            int(system.TotalPhysicalMemory) / (1024 ** 3), 2)
    return system_info


def get_installed_software(wmi_connection):
    """Collect installed software information from WMI."""
    installed_software = []
    for software in wmi_connection.query('SELECT * FROM Win32_Product'):
        installed_software.append({
            'name': software.Name,
            'version': software.Version,
            'vendor': software.Vendor,
            'install_date': software.InstallDate
        })
    return installed_software


def is_windows():
    """Check if running on Windows."""
    return platform.system().lower() == "windows"


def ping_host(ip):
    """Check if host is up using ping."""
    try:
        if is_windows():
            response = subprocess.run(
                ["ping", "-n", "1", "-w", "500", str(ip)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        else:
            response = subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        return response.returncode == 0
    except Exception as e:
        logger.error(f"Error pinging {ip}: {str(e)}")
        return False


def check_smb_ports(ip):
    """Check if Windows SMB ports are open (139 and 445)."""
    try:
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.settimeout(0.5)
        result1 = s1.connect_ex((str(ip), 445))
        s1.close()

        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(0.5)
        result2 = s2.connect_ex((str(ip), 139))
        s2.close()

        return result1 == 0 or result2 == 0
    except Exception as e:
        logger.debug(f"Error checking SMB ports for {ip}: {str(e)}")
        return False


def get_hostname(ip):
    """Attempt to resolve hostname from IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    except Exception as e:
        logger.error(f"Error resolving hostname for {ip}: {str(e)}")
        return None


def check_is_windows(ip):
    """Check if the device is likely a Windows PC."""
    try:
        if not ping_host(str(ip)):
            return None
        if not check_smb_ports(str(ip)):
            return None
        hostname = get_hostname(str(ip))
        return {
            'ip': str(ip),
            'hostname': hostname if hostname else 'Unknown',
            'status': 'Windows PC'
        }
    except Exception as e:
        logger.error(f"Error checking {ip}: {str(e)}")
        return None


def scan_subnet(subnet, max_workers=50):
    """Scan a subnet for Windows PCs."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        logger.info(
            f"Starting scan of subnet {subnet} ({len(list(network.hosts()))} hosts)")

        start_time = datetime.now()
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(
                check_is_windows, ip): ip for ip in network.hosts()}
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    results.append(result)

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Scan completed in {duration:.2f} seconds, found {len(results)} Windows PCs")
        return results
    except Exception as e:
        logger.error(f"Error during subnet scan: {str(e)}")
        return []


def check_local_windows_updates():
    """Check for Windows updates on the local machine."""
    try:
        pythoncom.CoInitialize()
        wmi_connection = wmi.WMI()
        return check_windows_updates(wmi_connection)
    except Exception as e:
        logger.error(f"Error checking local updates: {str(e)}")
        return None
    finally:
        pythoncom.CoUninitialize()


def check_remote_windows_updates(ip, username, password):
    """Check for Windows updates on a remote machine."""
    try:
        pythoncom.CoInitialize()
        wmi_connection = wmi.WMI(computer=ip, user=username, password=password)
        return check_windows_updates(wmi_connection)
    except Exception as e:
        logger.error(f"Error checking updates on {ip}: {str(e)}")
        return None
    finally:
        pythoncom.CoUninitialize()


def get_pending_updates(ip, username, password):
    """Check for pending Windows updates on a remote PC and store results."""
    logger.info(f"Checking for pending updates on>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> {ip}")

    try:
        session = winrm.Session(
            ip, auth=(username, password), transport='ntlm')

        update_script = """
$ErrorActionPreference = "Stop"
$updateService = Get-Service -Name wuauserv
if ($updateService.Status -ne 'Running') {
    Start-Service -Name wuauserv
    Start-Sleep -Seconds 5
}

try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
    
    $updates = @()
    if ($searchResult.Updates.Count -eq 0) {
        $updates += @{ "message" = "No pending updates found. System is up to date." }
    } else {
        foreach ($update in $searchResult.Updates) {
            $kbNumbers = @()
            foreach ($kbNumber in $update.KBArticleIDs) {
                $kbNumbers += "KB$kbNumber"
            }
            $updates += @{
                "kb_code" = ($kbNumbers -join ', ')
                "title" = $update.Title
                "size_mb" = [math]::Round($update.MaxDownloadSize / 1MB, 2)
                "severity" = $update.MsrcSeverity
                "reboot_required" = $update.RebootRequired
            }
        }
    }
    ConvertTo-Json -InputObject $updates
} catch {
    $errorMsg = "Error checking for updates: $_"
    try {
        $pendingUpdates = @(Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object { $_.InstalledOn -eq $null })
        $updates = @()
        if ($pendingUpdates.Count -gt 0) {
            foreach ($update in $pendingUpdates) {
                $updates += @{
                    "kb_code" = $update.HotFixID
                    "title" = $update.Description
                    "size_mb" = 0
                    "severity" = "Unknown"
                    "reboot_required" = $false
                }
            }
        } else {
            $updates += @{ "message" = "No pending updates found using fallback method." }
        }
        ConvertTo-Json -InputObject $updates
    } catch {
        ConvertTo-Json -InputObject @{ "error" = "Unable to determine update status: $_" }
    }
}
"""

        result = session.run_ps(update_script)

        if result.status_code == 0:
            output = result.std_out.decode('utf-8').strip()
            try:
                updates_data = json.loads(output)

                PendingUpdates.query.filter_by(ip_address=ip).delete()

                for update in updates_data:
                    if "message" in update:
                        logger.info(f"{ip}: {update['message']}")
                        continue
                    elif "error" in update:
                        logger.error(f"{ip}: {update['error']}")
                        return {"status": "error", "message": update['error']}

                    db.session.add(PendingUpdates(
                        ip_address=ip,
                        kb_code=update['kb_code'],
                        title=update['title'],
                        size_mb=update['size_mb'],
                        reboot_required=update['reboot_required']
                    ))

                db.session.commit()
                logger.info(
                    f"Successfully stored {len(updates_data)} pending updates for {ip}")
                return {"status": "success", "updates": updates_data}
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse update data for {ip}: {output}")
                return {"status": "error", "message": f"Invalid update data: {str(e)}"}
        else:
            error = result.std_err.decode('utf-8').strip()
            logger.error(f"WinRM error for {ip}: {error}")
            return {"status": "error", "message": error}

    except Exception as e:
        logger.error(f"Error checking pending updates for {ip}: {str(e)}")
        return {"status": "error", "message": str(e)}


def collect_pending_updates():
    """Collect pending updates for all connected PCs."""
    with app.app_context():
        try:
            network_scan_results = NetworkScanResults.query.all()
            ip_addresses = [
                result.ip_address for result in network_scan_results]

            if not ip_addresses:
                logger.info(
                    "No IP addresses found in NetworkScanResults table for pending updates.")
                return

            username = os.getenv('WMI_USERNAME')
            password = os.getenv('WMI_PASSWORD')
            pending_updates_summary = {}

            for ip in ip_addresses:
                result = get_pending_updates(ip, username, password)
                logger.info("runed for pending updates.")
                if result['status'] == 'success' and result['updates']:
                    for update in result['updates']:
                        kb = update['kb_code']
                        if kb not in pending_updates_summary:
                            pending_updates_summary[kb] = []
                        pending_updates_summary[kb].append(ip)
                elif result['status'] == 'error':
                    logger.error(
                        f"Failed to collect pending updates for {ip}: {result['message']}")

            if pending_updates_summary:
                email_body = "Pending Windows Updates Report:\n\n"
                for kb, ips in pending_updates_summary.items():
                    email_body += f"- {kb} pending on {len(ips)} PCs: {', '.join(ips)}\n"
                send_email("Pending Updates Report", email_body)

            logger.info("Pending updates collection completed.")

        except Exception as e:
            logger.error(f"Error during pending updates collection: {str(e)}")
            db.session.rollback()
        finally:
            db.session.remove()


def collect_chocolatey_outdated():
    """Collect outdated Chocolatey packages from all connected PCs."""
    with app.app_context():
        try:
            logger.info("Starting Chocolatey outdated packages collection")
            
            # Get all IP addresses from Devices table
            devices = Devices.query.all()
            ip_addresses = [device.IP_Address for device in devices]

            if not ip_addresses:
                logger.info("No IP addresses found in Devices table for Chocolatey collection")
                return

            username = os.getenv('WMI_USERNAME')
            password = os.getenv('WMI_PASSWORD')
            outdated_summary = {}

            for ip in ip_addresses:
                try:
                    # Establish WinRM session
                    session = winrm.Session(
                        ip,
                        auth=(username, password),
                        transport='ntlm'
                    )

                    # PowerShell script to run choco outdated
                    ps_script = """
                    $ErrorActionPreference = "Stop"
                    try {
                        $ProgressPreference = "SilentlyContinue"
                        $result = choco outdated --no-progress 2>&1 | Out-String
                        if ($LASTEXITCODE -ne 0) {
                            throw $result
                        }
                        $result
                    } catch {
                        $_.Exception.Message
                    }
                    """

                    result = session.run_ps(ps_script)

                    if result.status_code == 0:
                        output = result.std_out.decode('utf-8').strip()
                        logger.debug(f"Chocolatey output for {ip}:\n{output}")

                        # Parse the output
                        lines = output.split('\n')
                        packages = []
                        start_parsing = False

                        for line in lines:
                            line = line.strip()
                            if "Outdated Packages" in line:
                                start_parsing = True
                                continue
                            if not start_parsing or not line:
                                continue
                            # Skip the header line explicitly
                            if "Output is package name" in line:
                                continue
                            
                            # Process only valid package lines
                            parts = line.split('|')
                            if len(parts) >= 4:  # Ensure it's a valid package line
                                software_name = parts[0].strip()
                                current_version = parts[1].strip()
                                available_version = parts[2].strip()
                                
                                packages.append({
                                    'software_name': software_name,
                                    'current_version': current_version,
                                    'available_version': available_version
                                })

                                if software_name not in outdated_summary:
                                    outdated_summary[software_name] = []
                                outdated_summary[software_name].append({
                                    'ip': ip,
                                    'current': current_version,
                                    'available': available_version
                                })

                        # Clear existing entries for this IP
                        ChocolateyOutdatedPackages.query.filter_by(ip_address=ip).delete()

                        # Store new entries
                        for package in packages:
                            db.session.add(ChocolateyOutdatedPackages(
                                ip_address=ip,
                                software_name=package['software_name'],
                                current_version=package['current_version'],
                                available_version=package['available_version']
                            ))

                        db.session.commit()
                        logger.info(f"Collected {len(packages)} outdated packages for {ip}")

                    else:
                        error_msg = result.std_err.decode('utf-8').strip()
                        logger.error(f"WinRM error for {ip}: {error_msg}")

                except Exception as e:
                    logger.error(f"Error collecting Chocolatey data for {ip}: {str(e)}")
                    db.session.rollback()
                    continue

            # Send email notification if there are outdated packages
            if outdated_summary:
                email_body = "Chocolatey Outdated Packages Report:\n\n"
                for software, details in outdated_summary.items():
                    email_body += f"{software}:\n"
                    for detail in details:
                        email_body += f"- IP: {detail['ip']} (Current: {detail['current']}, Available: {detail['available']})\n"
                send_email("Chocolatey Outdated Packages Report", email_body)

            logger.info("Chocolatey outdated packages collection completed")

        except Exception as e:
            logger.error(f"Error during Chocolatey collection: {str(e)}")
            db.session.rollback()
        finally:
            db.session.remove()


def daily_collect_endpoints():
    """Collect endpoint information and notify admin of updates."""
    with app.app_context():
        try:
            network_scan_results = NetworkScanResults.query.all()
            ip_addresses = [
                result.ip_address for result in network_scan_results]

            if not ip_addresses:
                logger.info(
                    "No IP addresses found in NetworkScanResults table.")
                return

            username = os.getenv('WMI_USERNAME')
            password = os.getenv('WMI_PASSWORD')

            update_summary = {}
            browser_updates = {'chrome': {}, 'firefox': {}}

            for ip in ip_addresses:
                endpoint_data = collect_endpoint_info(ip, username, password)

                try:
                    device = Devices.query.filter_by(IP_Address=ip).first()
                    if not device:
                        device = Devices(IP_Address=ip)
                        db.session.add(device)

                    device.Collection_Status = endpoint_data['Collection_Status']
                    device.Collection_Time = datetime.now()

                    if endpoint_data['Collection_Status'] == 'Success':
                        OS_Info.query.filter_by(IP_Address=ip).delete()
                        System_Info.query.filter_by(IP_Address=ip).delete()
                        Installed_Software.query.filter_by(
                            IP_Address=ip).delete()
                        get_detailed_choco_list(ip, username, password)
                        
                        os_info = endpoint_data['OS_Info']
                        updates = endpoint_data['Updates']
                        db.session.add(OS_Info(
                            IP_Address=ip,
                            OS_Name=os_info.get('name'),
                            OS_Version=os_info.get('version'),
                            Architecture=os_info.get('architecture'),
                            windows_updates_available=updates['windows_updates_available'],
                            security_updates_available=updates['security_updates_available'],
                            driver_updates_available=updates['driver_updates_available'],
                            available_updates=", ".join(
                                updates['available_updates']),
                            os_kb_version=os_info.get('os_kb_version')
                        ))

                        for kb in updates['available_updates']:
                            if kb not in update_summary:
                                update_summary[kb] = []
                            update_summary[kb].append(ip)

                        sys_info = endpoint_data['System_Info']
                        db.session.add(System_Info(
                            IP_Address=ip,
                            Processor=sys_info.get('cpu'),
                            RAM_Size=f"{sys_info.get('ram_gb', 0)} GB",
                            Disk_Size='N/A',
                            Model=sys_info.get('Model')
                        ))

                    db.session.commit()
                    logger.info(f"Successfully collected data for IP: {ip}")

                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Database error for {ip}: {str(e)}")

            # Send email for endpoint collection
            if update_summary or browser_updates['chrome'] or browser_updates['firefox']:
                email_body = "The following updates are available:\n\n"
                if update_summary:
                    email_body += "Windows KB Updates:\n"
                    for kb, ips in update_summary.items():
                        email_body += f"- {kb} available on {len(ips)} PCs: {', '.join(ips)}\n"
                if browser_updates['chrome']:
                    email_body += "\nGoogle Chrome Updates:\n"
                    for ip, version in browser_updates['chrome'].items():
                        email_body += f"- Update to {version} available on {ip}\n"
                if browser_updates['firefox']:
                    email_body += "\nFirefox Updates:\n"
                    for ip, version in browser_updates['firefox'].items():
                        email_body += f"- Update to {version} available on {ip}\n"
                send_email("System Update Report", email_body)

            logger.info("Daily data collection completed.")

            # Run pending updates collection right after
            collect_pending_updates()
            collect_chocolatey_outdated()

        except Exception as e:
            logger.error(f"Error during daily data collection: {str(e)}")
        finally:
            db.session.remove()


def send_email(subject, body):
    """Send an email notification."""
    try:
        email_host = os.getenv('EMAIL_HOST')
        email_port = int(os.getenv('EMAIL_PORT'))
        email_user = os.getenv('EMAIL_USER')
        email_password = os.getenv('EMAIL_PASSWORD')
        admin_email = os.getenv('ADMIN_EMAIL')

        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = admin_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(email_host, email_port)
        server.starttls()
        server.login(email_user, email_password)
        server.sendmail(email_user, admin_email, msg.as_string())
        server.quit()

        logger.info("Email sent successfully.")
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")

# API Routes


@app.route('/api/collect', methods=['POST'])
def collect_endpoints():
    """Collect endpoint data manually."""
    try:
        data = request.json
        ip_addresses = data.get('ip_addresses')
        username = data.get('username')
        password = data.get('password')

        if not ip_addresses:
            return jsonify({'error': 'IP addresses are required'}), 400

        if isinstance(ip_addresses, str):
            ip_addresses = ip_addresses.split(',')

        successful_data = []
        failed_data = []

        for ip in ip_addresses:
            endpoint_data = collect_endpoint_info(ip, username, password)

            try:
                device = Devices.query.filter_by(IP_Address=ip).first()
                if not device:
                    device = Devices(IP_Address=ip)
                    db.session.add(device)

                device.Collection_Status = endpoint_data['Collection_Status']
                device.Collection_Time = datetime.now()

                if endpoint_data['Collection_Status'] == 'Success':
                    OS_Info.query.filter_by(IP_Address=ip).delete()
                    System_Info.query.filter_by(IP_Address=ip).delete()
                    Installed_Software.query.filter_by(IP_Address=ip).delete()

                    os_info = endpoint_data['OS_Info']
                    updates = endpoint_data['Updates']
                    db.session.add(OS_Info(
                        IP_Address=ip,
                        OS_Name=os_info.get('name'),
                        OS_Version=os_info.get('version'),
                        Architecture=os_info.get('architecture'),
                        windows_updates_available=updates['windows_updates_available'],
                        security_updates_available=updates['security_updates_available'],
                        driver_updates_available=updates['driver_updates_available'],
                        available_updates=", ".join(
                            updates['available_updates']),
                        os_kb_version=os_info.get('os_kb_version')
                    ))

                    sys_info = endpoint_data['System_Info']
                    db.session.add(System_Info(
                        IP_Address=ip,
                        Processor=sys_info.get('cpu'),
                        RAM_Size=f"{sys_info.get('ram_gb', 0)} GB",
                        Disk_Size='N/A',
                        Model=sys_info.get('Model')
                    ))

                    get_detailed_choco_list(ip, username, password)

                db.session.commit()
                successful_data.append(endpoint_data)
            except Exception as e:
                db.session.rollback()
                endpoint_data['Error'] = str(e)
                failed_data.append(endpoint_data)
                logger.error(f"Database error for {ip}: {str(e)}")

        return jsonify({
            'message': 'Data collection completed',
            'successful_data': successful_data,
            'failed_data': failed_data
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# def get_detailed_choco_list(ip, username, password):
#     try:
#         # Establish WinRM session
#         logger.info("choco started.")
#         session = winrm.Session(
#             ip,
#             auth=(username, password),
#             transport='ntlm'
#         )

#         # Command: Get installed software list from Chocolatey (JSON format)
#         ps_script = """
#         $ErrorActionPreference = "Stop"
#         try {
#             # Suppress progress output
#             $ProgressPreference = "SilentlyContinue"

#             # Run choco command
#             $result = choco list -i 2>&1 | Out-String
#             if ($LASTEXITCODE -ne 0) {
#                 throw $result
#             }
#             $result
#         } catch {
#             # Return clean error message
#             $_.Exception.Message
#         }
#         """

#         result = session.run_ps(ps_script)
#         logger.info(f'choco ok.>>>>>>>>>>>>>>>>>>>>>>>>>>> {result.status_code}')
#         if result.status_code == 0:
#             output = result.std_out.decode('utf-8').strip()
#             logger.info(f'choco ok.>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>START>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> {result.status_code}')
#             logger.info(f'choco ok.>>>>>>>>>>>>>>>>>>>>>>>>>>> {output}')
#             logger.info(f'>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> {result.status_code}')
#             # **Fix: Parse the output manually**
#             lines = output.split("\n")
#             packages = []

#             for line in lines:
#                 match = re.match(r"(.+?)\s([\d\.]+)$", line.strip())  # Match software name & version
#                 if match:
#                     software_name, version = match.groups()
#                     packages.append({
#                         "name": software_name.strip(),
#                         "version": version.strip()
#                     })

#             # Insert into database
#             for software in packages:
#                 install_date = None
#                 update_available = False

#                 db.session.add(Installed_Software(
#                     IP_Address=ip,
#                     Software_Name=software.get('name'),
#                     Version=software.get('version'),
#                     Installation_Date=install_date.date() if install_date else None,
#                     update_available=update_available
#                 ))

#             db.session.commit()  # Ensure data is inserted

#         else:
#             logger.error(f"WinRM Error (Code {result.status_code}): {result.std_err.decode('utf-8').strip()}")


#     except Exception as e:
#         print(f"Connection/Execution Error: {str(e)}")


def get_detailed_choco_list(ip, username, password):
    try:
        logger.info(f"Starting Chocolatey list collection for {ip}")

        # Establish WinRM session
        session = winrm.Session(
            ip,
            auth=(username, password),
            transport='ntlm'
        )

        # PowerShell script to get installed software list
        ps_script = """
        $ErrorActionPreference = "Stop"
        try {
            $ProgressPreference = "SilentlyContinue"
            $result = choco list -i 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                throw $result
            }
            $result
        } catch {
            $_.Exception.Message
        }
        """

        result = session.run_ps(ps_script)
        logger.info(f"WinRM execution status for {ip}: {result.status_code}")

        if result.status_code == 0:
            output = result.std_out.decode('utf-8').strip()
            logger.info(f"Chocolatey output for {ip}:\n{output}")

            # Parse the output manually
            lines = output.split("\n")
            packages = []

            for line in lines:
                match = re.match(r"(.+?)(?:\||\s)([\d\.]+)$", line.strip())
                if match:
                    software_name, version = match.groups()
                    packages.append({
                        "name": software_name.strip(),
                        "version": version.strip()
                    })

            if not packages:
                logger.warning(f"No valid Chocolatey packages found for {ip}")
                return

            # Insert into database within Flask app context
            with app.app_context():
                # Clear existing Chocolatey entries for this IP (optional, depending on your needs)
                # Installed_Software.query.filter_by(IP_Address=ip).delete()

                for software in packages:
                    install_date = None  # Chocolatey doesn't provide install date in this output
                    update_available = False

                    # Check if entry already exists to avoid duplicates
                    existing = Installed_Software.query.filter_by(
                        IP_Address=ip,
                        Software_Name=software['name'],
                        Version=software['version']
                    ).first()

                    if not existing:
                        logger.info(
                            f"Adding {software['name']} v{software['version']} for {ip}")
                        db.session.add(Installed_Software(
                            IP_Address=ip,
                            Software_Name=software['name'],
                            Version=software['version'],
                            Installation_Date=install_date,
                            update_available=update_available
                        ))
                    else:
                        logger.debug(
                            f"Skipping duplicate entry for {software['name']} on {ip}")

                db.session.commit()
                logger.info(
                    f"Successfully committed {len(packages)} packages for {ip}")

        else:
            error_msg = result.std_err.decode('utf-8').strip()
            logger.error(
                f"WinRM Error for {ip} (Code {result.status_code}): {error_msg}")

    except Exception as e:
        logger.error(f"Error in get_detailed_choco_list for {ip}: {str(e)}")
        with app.app_context():
            db.session.rollback()  # Rollback on error

def collect_installed_software_updates():
    """Collect installed software updates from all connected PCs."""
    with app.app_context():
        try:
            logger.info("Starting installed software update collection")

            # Get all IP addresses from Devices table
            devices = NetworkScanResults.query.all()
            ip_addresses = [device.ip_address  for device in devices]

            if not ip_addresses:
                logger.info("No IP addresses found in Devices table for software update collection")
                return

            username = os.getenv('WMI_USERNAME')
            password = os.getenv('WMI_PASSWORD')
            update_summary = {}

            for ip in ip_addresses:
                try:
                    # Establish WinRM session
                    session = winrm.Session(
                        ip,
                        auth=(username, password),
                        transport='ntlm'
                    )

                    # PowerShell script for installed software updates
                    ps_script = """[Insert the PowerShell script here]"""

                    result = session.run_ps(ps_script)

                    if result.status_code == 0:
                        output = result.std_out.decode('utf-8').strip()
                        logger.debug(f"Installed software updates for {ip}:\n{output}")

                        if "No updates available" in output:
                            logger.info(f"No software updates found for {ip}")
                            continue

                        # Parse JSON output
                        updates = json.loads(output)
                        software_updates = []

                        for update in updates:
                            software_updates.append({
                                'software_name': update['Name'],
                                'current_version': update['InstalledVersion'],
                                'available_version': update['AvailableVersion'],
                                'source': update['Source']
                            })

                            if update['Name'] not in update_summary:
                                update_summary[update['Name']] = []
                            update_summary[update['Name']].append({
                                'ip': ip,
                                'current': update['InstalledVersion'],
                                'available': update['AvailableVersion'],
                                'source': update['Source']
                            })

                        # Clear existing entries for this IP
                        InstalledSoftwareUpdates.query.filter_by(ip_address=ip).delete()

                        # Store new entries
                        for update in software_updates:
                            db.session.add(InstalledSoftwareUpdates(
                                ip_address=ip,
                                software_name=update['software_name'],
                                current_version=update['current_version'],
                                available_version=update['available_version']
                            ))

                        db.session.commit()
                        logger.info(f"Collected {len(software_updates)} updates for {ip}")

                    else:
                        error_msg = result.std_err.decode('utf-8').strip()
                        logger.error(f"WinRM error for {ip}: {error_msg}")

                except Exception as e:
                    logger.error(f"Error collecting software updates for {ip}: {str(e)}")
                    db.session.rollback()
                    continue

            # Send email notification if there are available updates
            if update_summary:
                email_body = "Installed Software Updates Report:\n\n"
                for software, details in update_summary.items():
                    email_body += f"{software}:\n"
                    for detail in details:
                        email_body += f"- IP: {detail['ip']} (Current: {detail['current']}, Available: {detail['available']}, Source: {detail['source']})\n"
                send_email("Installed Software Updates Report", email_body)

            logger.info("Installed software update collection completed")

        except Exception as e:
            logger.error(f"Error during software update collection: {str(e)}")
            db.session.rollback()
        finally:
            db.session.remove()



@app.route('/api/GetData', methods=['GET'])
def get_device_data():
    """Get device data from the database."""
    try:
        sql_query = text("""
            SELECT D.IP_Address, S.Model, S.RAM_Size, O.OS_Name, S.Processor, D.Collection_Time
            FROM Devices D
            LEFT JOIN System_Info S ON D.IP_Address = S.IP_Address
            LEFT JOIN OS_Info O ON D.IP_Address = O.IP_Address
        """)
        result = db.session.execute(sql_query)
        devices = [
            {
                "IP_Address": row[0],
                "Model": row[1],
                "RAM_Size": row[2],
                "OS_Name": row[3],
                "Processor": row[4],
                "Collection_Time": row[5]
            } for row in result.fetchall()
        ]
        return jsonify({"devices": devices}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/counts', methods=['GET'])
def get_counts():
    try:
        # Get count of records in NetworkScanResults
        network_scan_count = NetworkScanResults.query.count()
        
        # Get count of records in PendingUpdates
        pending_updates_count = PendingUpdates.query.count()
        
        # Return the counts as JSON
        return jsonify({
            'NetworkScanResults_count': network_scan_count,
            'PendingUpdates_count': pending_updates_count
        })
    except Exception as e:
        # Return error if something goes wrong
        return jsonify({'error': str(e)}), 500



@app.route('/api/get_connected_ips', methods=['GET'])
def get_connected_ips_route():
    """Scan subnet and save results."""
    try:
        subnet = request.args.get('subnet', default="192.168.8.0/24")
        results = scan_subnet(subnet)

        for result in results:
            existing_entry = NetworkScanResults.query.filter_by(
                ip_address=result['ip']).first()
            if existing_entry:
                existing_entry.hostname = result['hostname']
                existing_entry.status = result['status']
                existing_entry.scan_time = datetime.now()
            else:
                db.session.add(NetworkScanResults(
                    ip_address=result['ip'],
                    hostname=result['hostname'],
                    status=result['status']
                ))

        db.session.commit()
        return jsonify({"connected_ips": results}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving scan results: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Automated subnet scanning function


def auto_scan_subnet():
    """Automatically scan subnet and save results to the database."""
    try:
        # Use a default subnet from environment variable or fallback to "192.168.1.0/24"
        subnet = os.getenv('AUTO_SCAN_SUBNET', "192.168.8.0/24")
        results = scan_subnet(subnet)

        with app.app_context():  # Ensure Flask app context
            for result in results:
                existing_entry = NetworkScanResults.query.filter_by(
                    ip_address=result['ip']).first()
                if existing_entry:
                    existing_entry.hostname = result['hostname']
                    existing_entry.status = result['status']
                    existing_entry.scan_time = datetime.now()
                else:
                    db.session.add(NetworkScanResults(
                        ip_address=result['ip'],
                        hostname=result['hostname'],
                        status=result['status']
                    ))

            db.session.commit()
            logger.info(
                f"Automated subnet scan completed for {subnet}. Found {len(results)} devices.")
    except Exception as e:
        with app.app_context():  # Ensure rollback within app context
            db.session.rollback()
        logger.error(f"Error during automated subnet scan: {str(e)}")


@app.route('/api/get_network_scan_results', methods=['GET'])
def get_network_scan_results():
    """Get saved network scan results."""
    try:
        query = NetworkScanResults.query
        ip_address = request.args.get('ip_address')
        hostname = request.args.get('hostname')
        status = request.args.get('status')

        if ip_address:
            query = query.filter(NetworkScanResults.ip_address == ip_address)
        if hostname:
            query = query.filter(NetworkScanResults.hostname == hostname)
        if status:
            query = query.filter(NetworkScanResults.status == status)

        results = query.all()
        saved_results = [
            {
                "id": result.id,
                "ip_address": result.ip_address,
                "hostname": result.hostname,
                "status": result.status,
                "scan_time": result.scan_time.strftime('%Y-%m-%d %H:%M:%S')
            } for result in results
        ]
        return jsonify({"saved_results": saved_results}), 200
    except Exception as e:
        logger.error(f"Error retrieving scan results: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/check_updates_and_notify', methods=['GET'])
def check_updates_and_notify():
    """Manually check updates and notify admin."""
    try:
        pythoncom.CoInitialize()
        wmi_connection = wmi.WMI()
        updates = check_windows_updates(wmi_connection)

        software_with_updates = Installed_Software.query.filter_by(
            update_available=True).all()
        email_body = "The following updates are available:\n\n"

        if updates and updates['available_updates']:
            email_body += "Windows KB Updates:\n"
            for kb in updates['available_updates']:
                email_body += f"- {kb}\n"

        if software_with_updates:
            email_body += "\nSoftware Updates:\n"
            for software in software_with_updates:
                email_body += f"- {software.Software_Name} (Current: {software.Version})\n"

        if updates or software_with_updates:
            send_email("Manual Update Check Report", email_body)
            return jsonify({'status': 'success', 'message': 'Email sent'}), 200
        else:
            return jsonify({'status': 'success', 'message': 'No updates found'}), 200
    except Exception as e:
        logger.error(f"Error checking updates: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)}), 500
    finally:
        pythoncom.CoUninitialize()


def check_and_notify_updates():
    """Check for updates and send hourly notifications between 8 AM and 5:30 PM."""
    try:
        current_time = datetime.now()
        current_hour = current_time.hour
        current_minute = current_time.minute

        # Only proceed if between 8:00 AM and 5:30 PM UTC
        if not (8 <= current_hour < 17 or (current_hour == 17 and current_minute <= 30)):
            logger.info(
                "Outside notification window (8 AM - 5:30 PM UTC). Skipping.")
            return

        with app.app_context():
            # Fetch all devices with pending updates
            os_updates = OS_Info.query.filter(
                db.or_(
                    OS_Info.windows_updates_available == True,
                    OS_Info.security_updates_available == True,
                    OS_Info.driver_updates_available == True
                )
            ).all()
            software_updates = Installed_Software.query.filter_by(
                update_available=True).all()

            update_summary = {}
            browser_updates = {'chrome': {}, 'firefox': {}}
            today = datetime.now().date()

            # Process OS updates
            for os_update in os_updates:
                for kb in os_update.available_updates.split(", "):
                    if not kb:
                        continue
                    # Check if this update was already notified today
                    notified = UpdateNotificationLog.query.filter_by(
                        ip_address=os_update.IP_Address,
                        update_type=kb,
                        notification_date=today
                    ).first()
                    if notified and notified.retry_count >= 1:  # Max 1 retry
                        continue
                    if kb not in update_summary:
                        update_summary[kb] = []
                    update_summary[kb].append(os_update.IP_Address)

            # Process browser updates
            for software in software_updates:
                if software.Software_Name.lower() == 'google chrome':
                    notified = UpdateNotificationLog.query.filter_by(
                        ip_address=software.IP_Address,
                        update_type='Chrome',
                        notification_date=today
                    ).first()
                    if notified and notified.retry_count >= 1:
                        continue
                    browser_updates['chrome'][software.IP_Address] = get_latest_versions()[
                        'chrome']
                elif software.Software_Name.lower() == 'mozilla firefox':
                    notified = UpdateNotificationLog.query.filter_by(
                        ip_address=software.IP_Address,
                        update_type='Firefox',
                        notification_date=today
                    ).first()
                    if notified and notified.retry_count >= 1:
                        continue
                    browser_updates['firefox'][software.IP_Address] = get_latest_versions()[
                        'firefox']

            if not update_summary and not browser_updates['chrome'] and not browser_updates['firefox']:
                logger.info("No updates to notify about.")
                return

            # Prepare email
            email_body = f"Update Report - {current_time.strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            email_body += "The following updates are available:\n\n"

            if update_summary:
                email_body += "Windows KB Updates:\n"
                for kb, ips in update_summary.items():
                    email_body += f"- {kb} available on {len(ips)} PCs: {', '.join(ips)}\n"

            if browser_updates['chrome']:
                email_body += "\nGoogle Chrome Updates:\n"
                for ip, version in browser_updates['chrome'].items():
                    email_body += f"- Update to {version} available on {ip}\n"

            if browser_updates['firefox']:
                email_body += "\nFirefox Updates:\n"
                for ip, version in browser_updates['firefox'].items():
                    email_body += f"- Update to {version} available on {ip}\n"

            # Send email and log notifications
            email_sent = send_email("Hourly Update Report", email_body)
            if email_sent:
                for kb, ips in update_summary.items():
                    for ip in ips:
                        log = UpdateNotificationLog.query.filter_by(
                            ip_address=ip,
                            update_type=kb,
                            notification_date=today
                        ).first()
                        if not log:
                            db.session.add(UpdateNotificationLog(
                                ip_address=ip,
                                update_type=kb,
                                notification_date=today
                            ))
                        elif log.retry_count < 1:
                            log.retry_count += 1
                for ip in browser_updates['chrome']:
                    log = UpdateNotificationLog.query.filter_by(
                        ip_address=ip,
                        update_type='Chrome',
                        notification_date=today
                    ).first()
                    if not log:
                        db.session.add(UpdateNotificationLog(
                            ip_address=ip,
                            update_type='Chrome',
                            notification_date=today
                        ))
                    elif log.retry_count < 1:
                        log.retry_count += 1
                for ip in browser_updates['firefox']:
                    log = UpdateNotificationLog.query.filter_by(
                        ip_address=ip,
                        update_type='Firefox',
                        notification_date=today
                    ).first()
                    if not log:
                        db.session.add(UpdateNotificationLog(
                            ip_address=ip,
                            update_type='Firefox',
                            notification_date=today
                        ))
                    elif log.retry_count < 1:
                        log.retry_count += 1
                db.session.commit()
            else:
                logger.error(
                    "Email failed to send. Will retry next hour if applicable.")
            logger.info("Update notification process completed.")
    except Exception as e:
        logger.error(f"Error in check_and_notify_updates: {str(e)}")
        with app.app_context():
            db.session.rollback()


@app.route('/api/get_os_updates', methods=['GET'])
def get_os_updates():
    """Get distinct KB updates from PendingUpdates table grouped by KB version."""
    try:
        with app.app_context():
            # Query for distinct KB versions with their details
            distinct_updates = db.session.query(
                PendingUpdates.kb_code,
                PendingUpdates.title,
                db.func.count(PendingUpdates.ip_address).label('device_count'),
                db.func.max(PendingUpdates.size_mb).label('size_mb'),
                db.func.max(PendingUpdates.reboot_required).label('reboot_required')
            ).filter(
                PendingUpdates.approved == False  
            ).group_by(
                PendingUpdates.kb_code,
                PendingUpdates.title
            ).all()

            # Format the response
            updates = []
            for update in distinct_updates:
                updates.append({
                    "kb_code": update.kb_code,
                    "title": update.title,
                    "device_count": update.device_count,
                    "size_mb": update.size_mb,
                    "reboot_required": update.reboot_required
                })

            return jsonify({"status": "success", "updates": updates}), 200

    except Exception as e:
        logger.error(f"Error retrieving pending updates: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route('/api/approve_os_updates', methods=['POST'])
def approve_os_updates():
    """Approve all pending OS updates with the same KB code."""
    try:
        with app.app_context():
            data = request.json
            kb_code = data.get('kb_code')
            
            if not kb_code:
                return jsonify({"status": "error", "message": "KB code is required"}), 400

            # Update all pending updates with this KB code
            updates = PendingUpdates.query.filter_by(
                kb_code=kb_code,
                approved=False
            ).all()

            if not updates:
                return jsonify({"status": "error", "message": "No matching updates found"}), 404

            # Bulk update
            for update in updates:
                update.approved = True
                update.approval_time = datetime.now()
            
            db.session.commit()

            logger.info(f"Approved {len(updates)} updates for KB {kb_code}")
            return jsonify({
                "status": "success",
                "message": f"Approved {len(updates)} updates",
                "count": len(updates)
            }), 200
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error approving updates: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route('/api/collect_chocolatey_outdated', methods=['POST'])
def collect_chocolatey_outdated_endpoint():
    """Manually trigger Chocolatey outdated packages collection."""
    try:
        collect_chocolatey_outdated()
        return jsonify({
            'status': 'success',
            'message': 'Chocolatey outdated packages collection completed'
        }), 200
    except Exception as e:
        logger.error(f"Error in Chocolatey collection endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/get_chocolatey_outdated', methods=['GET'])
def get_chocolatey_outdated():
    """Get all outdated Chocolatey packages from the database."""
    try:
        with app.app_context():
            outdated_packages = ChocolateyOutdatedPackages.query.all()
            results = [{
                'id': package.id,
                'ip_address': package.ip_address,
                'software_name': package.software_name,
                'current_version': package.current_version,
                'available_version': package.available_version,
                'check_time': package.check_time.strftime('%Y-%m-%d %H:%M:%S')
            } for package in outdated_packages]

            return jsonify({
                'status': 'success',
                'outdated_packages': results
            }), 200
    except Exception as e:
        logger.error(
            f"Error retrieving Chocolatey outdated packages: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/pending-updates-sof', methods=['GET'])
def get_pending_updatess():
    """Fetch distinct pending software updates."""
    try:
        updates = db.session.query(
            ChocolateyOutdatedPackages.software_name,
            ChocolateyOutdatedPackages.current_version,
            ChocolateyOutdatedPackages.available_version
        ).filter(ChocolateyOutdatedPackages.approved == False).distinct().all()

        # Convert query results to list of dicts
        update_list = [
            {"software_name": update.software_name, "current_version": update.current_version, "available_version":update.available_version}
            for update in updates
        ]

        return jsonify(update_list), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/api/approve-update', methods=['POST'])
def approve_update():
    """Mark a software update as approved."""
    try:
        data = request.json
        software_name = data.get('software_name')
        current_version = data.get('current_version')

        # Update the record in the database
        update_entry = ChocolateyOutdatedPackages.query.filter_by(
            software_name=software_name, current_version=current_version
        ).first()

        if update_entry:
            update_entry.approved = True
            db.session.commit()
            return jsonify({"message": "Update approved successfully"}), 200
        else:
            return jsonify({"error": "Update not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500



def approve_and_install_kb():
    """Automatically approve and install all approved KB updates on remote workstations."""
    with app.app_context():
        try:
            username = os.getenv('WMI_USERNAME')
            password = os.getenv('WMI_PASSWORD')
            if not username or not password:
                logger.error("WMI_USERNAME or WMI_PASSWORD environment variables not set.")
                return

            pending_updates = db.session.query(PendingUpdates).filter_by(
                approved=True, updated=False).all()
            
            if not pending_updates:
                logger.info("No approved pending updates found to install.")
                return

            for update in pending_updates:
                ip_address = update.ip_address
                kb_code = update.kb_code
                logger.info(f"Attempting to install {kb_code} on {ip_address}")

                # First, create the PowerShell script file on the remote machine
                install_script = f"""
                # Define the KB number
                $KBNumber = "{kb_code}"
                $logFile = "C:\\Windows\\Temp\\KB_install_log.txt"

                # Start logging
                Start-Transcript -Path $logFile -Force

                try {{
                    Write-Host "Starting KB installation process for $KBNumber with elevated privileges"
                    
                    # Create a Windows Update session
                    $Session = New-Object -ComObject Microsoft.Update.Session
                    if (-not $Session) {{
                        Write-Host "ERROR: Failed to create Windows Update Session" -ForegroundColor Red
                        exit 1
                    }}
                    
                    Write-Host "Windows Update Session created successfully"
                    
                    # Create a searcher object
                    $Searcher = $Session.CreateUpdateSearcher()
                    if (-not $Searcher) {{
                        Write-Host "ERROR: Failed to create Update Searcher" -ForegroundColor Red
                        exit 1
                    }}
                    
                    # Search for all pending updates
                    Write-Host "Searching for updates..."
                    $SearchResult = $Searcher.Search("IsInstalled=0")
                    
                    # Find the specific update by KB number
                    $TargetUpdate = $null
                    Write-Host "Found $($SearchResult.Updates.Count) updates"
                    
                    foreach ($Update in $SearchResult.Updates) {{
                        Write-Host "Checking update: $($Update.Title)"
                        if ($Update.Title -like "*$KBNumber*") {{
                            $TargetUpdate = $Update
                            Write-Host "Found target update: $($Update.Title)"
                            break
                        }}
                    }}
                    
                    if ($TargetUpdate -eq $null) {{
                        Write-Host "The specified KB update $KBNumber was not found in the pending updates list." -ForegroundColor Red
                        exit 1
                    }}
                    
                    # Create an update collection for the specific update
                    Write-Host "Creating update collection..."
                    $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                    $UpdatesToInstall.Add($TargetUpdate) | Out-Null
                    
                    # Download the update
                    Write-Host "Downloading update $KBNumber..."
                    $Downloader = $Session.CreateUpdateDownloader()
                    $Downloader.Updates = $UpdatesToInstall
                    $DownloadResult = $Downloader.Download()
                    
                    # Check download results
                    if ($DownloadResult.ResultCode -eq 2) {{
                        Write-Host "Download completed successfully" -ForegroundColor Green
                        
                        # Install the update
                        Write-Host "Installing update $KBNumber..."
                        $Installer = $Session.CreateUpdateInstaller()
                        $Installer.Updates = $UpdatesToInstall
                        $InstallResult = $Installer.Install()
                        
                        # Check installation results
                        if ($InstallResult.ResultCode -eq 2) {{
                            Write-Host "Installation completed successfully" -ForegroundColor Green
                            Write-Host "$KBNumber installed successfully"
                            if (Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired") {{
                                Write-Host "REBOOT REQUIRED"
                            }}
                            exit 0
                        }} else {{
                            Write-Host "Installation failed with error code: $($InstallResult.ResultCode)" -ForegroundColor Red
                            exit 1
                        }}
                    }} else {{
                        Write-Host "Download failed with error code: $($DownloadResult.ResultCode)" -ForegroundColor Red
                        exit 1
                    }}
                }}
                catch {{
                    Write-Host "ERROR: An exception occurred: $_" -ForegroundColor Red
                    exit 1
                }}
                finally {{
                    Stop-Transcript
                }}
                """

                # Create script to copy and execute on remote machine
                remote_script = f"""
                $Username = '{username}'
                $Password = ConvertTo-SecureString '{password}' -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)

                # Connect to remote machine and create script file
                Invoke-Command -ComputerName {ip_address} -Credential $Credential -ScriptBlock {{
                    # Create script file
                    $scriptContent = @'
{install_script}
'@
                    $scriptPath = "C:\\Windows\\Temp\\InstallKB.ps1"
                    $scriptContent | Out-File -FilePath $scriptPath -Force -Encoding ASCII
                    
                    # Create scheduled task to run with SYSTEM privileges
                    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\\Windows\\Temp\\InstallKB.ps1"
                    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10)
                    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
                    
                    # Register and start the task
                    $taskName = "InstallWindowsUpdate_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
                    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
                    Start-ScheduledTask -TaskName $taskName
                    
                    # Wait for task to complete (up to 5 minutes)
                    $timeout = (Get-Date).AddMinutes(5)
                    $taskState = (Get-ScheduledTask -TaskName $taskName).State
                    while ($taskState -ne 'Ready' -and (Get-Date) -lt $timeout) {{
                        Start-Sleep -Seconds 5
                        $taskState = (Get-ScheduledTask -TaskName $taskName).State
                    }}
                    
                    # Get task result and log
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
                    
                    # Read log file
                    if (Test-Path "C:\\Windows\\Temp\\KB_install_log.txt") {{
                        Write-Host "=== INSTALLATION LOG ==="
                        Get-Content -Path "C:\\Windows\\Temp\\KB_install_log.txt"
                        Write-Host "=== END OF LOG ==="
                    }} else {{
                        Write-Host "Log file not found" -ForegroundColor Red
                    }}
                    
                    # Clean up
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }}
                """

                # Execute the remote script creation and task scheduling
                result = subprocess.run(["powershell", "-Command", remote_script], capture_output=True, text=True)

                if result.returncode == 0:
                    logger.info(f"PowerShell Output for {ip_address} ({kb_code}):\n{result.stdout}")
                    if result.stderr:
                        logger.warning(f"PowerShell Warnings/Errors:\n{result.stderr}")

                    if "installed successfully" in result.stdout:
                        update.updated = True
                        db.session.commit()
                        logger.info(f"Successfully installed {kb_code} on {ip_address}")
                    else:
                        logger.error(f"Failed to install {kb_code} on {ip_address}: {result.stdout}")
                else:
                    logger.error(f"PowerShell error for {ip_address} ({kb_code}): {result.stderr}")

        except Exception as e:
            logger.error(f"Error in approve_and_install_kb: {str(e)}")
            db.session.rollback()


def install_chocolatey_updates():
    """Silently install approved Chocolatey package updates on all relevant IPs."""
    with app.app_context():
        try:
            logger.info("Starting silent Chocolatey update installation process")

            # Fetch all approved but not updated packages
            outdated_packages = ChocolateyOutdatedPackages.query.filter_by(
                approved=True, updated=False).all()

            if not outdated_packages:
                logger.info("No approved Chocolatey packages to update.")
                return

            username = os.getenv('WMI_USERNAME')
            password = os.getenv('WMI_PASSWORD')
            updated_packages = []

            # Group packages by IP to minimize WinRM sessions
            packages_by_ip = {}
            for package in outdated_packages:
                if package.ip_address not in packages_by_ip:
                    packages_by_ip[package.ip_address] = []
                packages_by_ip[package.ip_address].append(package)

            for ip, packages in packages_by_ip.items():
                try:
                    # Establish WinRM session
                    session = winrm.Session(
                        ip, auth=(username, password), transport='ntlm')

                    # Build the Chocolatey upgrade command for all packages at once
                    software_names = [package.software_name for package in packages]
                    choco_command = f"choco upgrade {' '.join(software_names)} -y --force --no-progress"

                    ps_script = f"""
                    $ErrorActionPreference = "Stop"
                    try {{
                        $ProgressPreference = "SilentlyContinue"
                        {choco_command}
                        if ($LASTEXITCODE -eq 0) {{
                            Write-Output "Successfully updated packages: {' '.join(software_names)}"
                        }} else {{
                            throw "Chocolatey update failed with exit code $LASTEXITCODE"
                        }}
                    }} catch {{
                        Write-Error "Error: $_"
                    }}
                    """

                    result = session.run_ps(ps_script)

                    if result.status_code == 0:
                        output = result.std_out.decode('utf-8').strip()
                        logger.info(f"Update result for {ip}: {output}")

                        # Mark packages as updated
                        for package in packages:
                            package.updated = True
                            updated_packages.append(package.software_name)
                        db.session.commit()
                        logger.info(f"Updated {len(packages)} packages on {ip}: {', '.join(software_names)}")
                    else:
                        error_msg = result.std_err.decode('utf-8').strip()
                        logger.error(f"Failed to update packages on {ip}: {error_msg}")

                except Exception as e:
                    logger.error(f"Error processing updates for {ip}: {str(e)}")
                    db.session.rollback()
                    continue

            if updated_packages:
                email_body = "Chocolatey Silent Update Report:\n\n"
                email_body += f"Successfully updated the following packages:\n"
                for ip, packages in packages_by_ip.items():
                    updated_names = [p.software_name for p in packages if p.updated]
                    if updated_names:
                        email_body += f"- {ip}: {', '.join(updated_names)}\n"
                send_email("Chocolatey Silent Update Report", email_body)

            logger.info("Silent Chocolatey update installation process completed")

        except Exception as e:
            logger.error(f"Error in install_chocolatey_updates: {str(e)}")
            db.session.rollback()
        finally:
            db.session.remove()

@app.route('/api/get_done_os_updates', methods=['GET'])
def get_done_os_updates():
    """Fetch all OS updates that have been installed (updated = True)."""
    try:
        with app.app_context():
            # Query for updates where updated = True
            done_updates = PendingUpdates.query.filter_by(updated=True).all()

            # Format the response
            updates_list = [
                {
                    "id": update.id,
                    "ip_address": update.ip_address,
                    "kb_code": update.kb_code,
                    "title": update.title,
                    "size_mb": update.size_mb,
                    "reboot_required": update.reboot_required,
                    "approved": update.approved,
                    "check_time": update.check_time.strftime('%Y-%m-%d %H:%M:%S') if update.check_time else None,
                    "approval_time": update.approval_time.strftime('%Y-%m-%d %H:%M:%S') if update.approval_time else None,
                    "updated": update.updated
                }
                for update in done_updates
            ]

            return jsonify({
                "status": "success",
                "updates": updates_list
            }), 200

    except Exception as e:
        logger.error(f"Error retrieving done OS updates: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/api/get_done_software_updates', methods=['GET'])
def get_done_software_updates():
    """Fetch all software updates that have been installed (updated = True)."""
    try:
        with app.app_context():
            # Query for updates where updated = True
            done_updates = ChocolateyOutdatedPackages.query.filter_by(updated=True).all()

            # Format the response
            updates_list = [
                {
                    "id": update.id,
                    "ip_address": update.ip_address,
                    "software_name": update.software_name,
                    "current_version": update.current_version,
                    "available_version": update.available_version,
                    "check_time": update.check_time.strftime('%Y-%m-%d %H:%M:%S') if update.check_time else None,
                    "approved": update.approved,
                    "updated": update.updated
                }
                for update in done_updates
            ]

            return jsonify({
                "status": "success",
                "updates": updates_list
            }), 200

    except Exception as e:
        logger.error(f"Error retrieving done software updates: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/api/endpoints/softwareAll', methods=['GET'])
def get_endpoint_software():
    """Get all installed software for all endpoints."""
    try:
        # Get all devices
        devices = Devices.query.all()
        if not devices:
            return jsonify({"error": "No endpoints found"}), 404

        # Prepare response data for all endpoints
        endpoints_data = []
        
        for device in devices:
            # Get all installed software for this endpoint
            software_list = Installed_Software.query.filter_by(
                IP_Address=device.IP_Address
            ).all()

            # Get computer name from System_Info
            system_info = System_Info.query.filter_by(
                IP_Address=device.IP_Address
            ).first()
            computer_name = system_info.Model if system_info else "Unknown"

            # Format software data for this endpoint
            software_data = [{
                "software_name": software.Software_Name,
                "version": software.Version,
                "install_date": software.Installation_Date.strftime('%Y-%m-%d') if software.Installation_Date else None,
                "update_available": software.update_available
            } for software in software_list]

            # Add this endpoint's data to the response
            endpoints_data.append({
                "ip_address": device.IP_Address,
                "computer_name": computer_name,
                "software": software_data
            })

        return jsonify({
            "endpoints": endpoints_data,
            "total_endpoints": len(endpoints_data)
        }), 200

    except Exception as e:
        logger.error(f"Error getting endpoint software: {str(e)}")
        return jsonify({"error": str(e)}), 500


# Initialize scheduler
scheduler = BackgroundScheduler()

# Get time values from .env with defaults
schedule_hour = int(os.getenv('SCHEDULE_HOUR', 1))
schedule_minute = int(os.getenv('SCHEDULE_MINUTE', 0))


# Schedule the subnet scan to run daily at 1:00 AM UTC (adjust as needed)
scheduler.add_job(func=auto_scan_subnet, trigger='cron', hour=schedule_hour,
                  minute=schedule_minute, timezone=pytz.timezone('Asia/Colombo'))
scheduler.add_job(func=daily_collect_endpoints, trigger='cron',
                  hour=8, minute=36, timezone=pytz.timezone('Asia/Colombo'))

# Ensure this is your scheduler setup
scheduler.add_job(func=approve_and_install_kb, trigger='cron', 
                  hour=9, minute=55, timezone=pytz.timezone('Asia/Colombo'))

scheduler.add_job(func=install_chocolatey_updates, trigger='cron',
                  hour=8, minute=47, timezone=pytz.timezone('Asia/Colombo')) # aproved software updated automatically updates

# Start the scheduler
scheduler.start()

# Shutdown scheduler when the app exits
atexit.register(lambda: scheduler.shutdown())


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2565)
