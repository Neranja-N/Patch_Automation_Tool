
This project focuses on Developing an automated patch management solution mainly focusing for Windows-based IT environments for small and medium enterprises (SMEs). This system offers complete patch management features-from automated detection of available updates, administrator approval workflows, and secured deployment through VLAN isolation-to real-time update of patch status across all endpoints and generate detailed compliance reports. This application support to Windows Operating systems including Windows 10/11 with common utility applications. Security is ensured through role-based access control and secure communication protocols. This system designed with SME requirements in considering, the system offers an efficient, cost-effective approach to maintaining system updates while minimizing manual human indolent and maintaining high security environment. 

Backend Configuration Guide
Initial Setup Requirements
The backend configuration of the Automated Patch Management System must be configured by an IT professional who familiar with familiar with network administration and basic programming. before deployment, host server must be checked that it meets system requirements:

•	Windows Server 2016/2019 with IIS enabled.
•	Python 3.13 and MySQL installed.
•	Firewall rules adjusted to allow communication between the server and endpoints.

Configuration via .env File
Important parameters must be defined in the .env file according to the business needs before launching the application:

1.	Network Settings

This application should pecify the IP address range and subnet (e.g., 192.168.1.0/24) to identify device domain to authorized networks.

2.	Admin Credentials

Provide domain or local admin account credentials (username/password) with permissions to run scripts on endpoints via WMI/WinRM.

3.	Email Notifications

Configure SMTP settings (server, port, credentials) for sending captured pending OS updates and Utility applications updates for the system administrator. 

4.	Task Scheduling

Define automated task timings in cron job format:

•	Device scan time: Frequency of network scan and device identification (e.g., daily at 12 AM).
•	Endpoint data collection: Interval for gathering software/hardware details from endpoints (e.g., daily at 2 AM).
•	Update checks: When to query for new patches (e.g., daily at 3 AM).
•	Updates Install: Pending approved updates Download and installation (e.g., daily at 4 AM).


Endpoint Device Configuration
For an Effective Automated Patch Management System, there have some configuration settings need to configure endpoints on a specific network. That settings would enable communication with the server backend while supporting patch management workflow processes. This has to be done by an IT professional with administrator access on the endpoints using CLI.

Prerequisites
•	Endpoints running Windows 10/11.
•	Administrative privileges on each endpoint.
•	Network connectivity to the backend server.

Configuration Steps

1.	Enable and Verify WMI (Windows Management Instrumentation)
WMI is required for collect hardware and software details from endpoints.

Get-Service Winmgmt

2.	Configure WinRM (Windows Remote Management)
WinRM facilitates remote management and patch deployment trough execute script over remote sessions.

winrm quickconfig

3.	Enable Windows Update Module
Ensure endpoints can receive and install updates via the Windows Update service.

Install-Module -Name PSWindowsUpdate -Force -AllowClobber
Import-Module PSWindowsUpdate
sc start wuauserv

4.	Install and Configure Chocolatey Package Manager
Chocolatey extends patch management by enabling additional software installations efficiently.

powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"

=======
Remote README content from GitHub
>>>>>>> origin/main
