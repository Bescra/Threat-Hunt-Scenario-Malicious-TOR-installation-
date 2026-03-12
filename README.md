# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Bescra/Threat-Hunt-Scenario-Malicious-TOR-installation-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "Bescra" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `THIS.txt` on the desktop at `2026-03-11 09:41:12`. These events began at `11 Mar 2026 at 08:53:03`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "Bescra-Threathu"
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="450" height="500" alt="Screenshot 2026-03-11 105056" src="https://github.com/user-attachments/assets/e16d8462-1198-4a0f-bb79-cfed422e8754" />
<img width="450" height="140" alt="Screenshot 2026-03-11 105120" src="https://github.com/user-attachments/assets/a3f3b036-0baf-406a-bf93-78c98641e9a9" />
<img width="631" height="345" alt="image" src="https://github.com/user-attachments/assets/1519dae2-6d0e-4a48-bc52-e1061319d1b3" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.7.exe". Based on the logs returned, at `11 Mar 2026 09:06:05`, an employee on the "bescra-threathu" device ran the file `tor-browser-windows-x86_64-portable-15.0.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName contains "Bescra-Threathu"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| sort by Timestamp desc

```
<img width="1240" height="258" alt="Screenshot 2026-03-11 113550" src="https://github.com/user-attachments/assets/bee9f71d-3cbc-494d-912c-1217d2db6e6d" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "Bescra" actually opened the TOR browser. There was evidence that they did open it at `2026-03-11 09:07:07`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "bescra-threathu"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
The process initially appears as firefox.exe, but the associated FileName tor.exe confirms that the user successfully connected to the Tor Network. From this point onward, all traffic from the endpoint is routed through Tor.
<img width="1805" height="734" alt="Screenshot 2026-03-11 114640" src="https://github.com/user-attachments/assets/20572af0-552b-4c70-9662-4b8f3b89844f" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-03-11 09:08:34`, an employee on the "bescra-threathu" device successfully established a connection to the remote IP address `217.123.118.44` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\Bescra\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `9150`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "bescra-threathu"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1716" height="703" alt="Screenshot 2026-03-11 120021" src="https://github.com/user-attachments/assets/6924fd19-698f-4527-8e88-926087338bb4" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `11 Mar 2026 at 08:53:03`
- **Event:** The user "bescra" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Bescra\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `11 Mar 2026 09:06:05`
- **Event:** The user "bescra" executed the file `tor-browser-windows-x86_64-portable-15.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe /S`
- **File Path:** `C:\Users\Bescra\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-03-11 09:07:07`
- **Event:** User "bescra" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Bescra\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-03-11 09:08:34`
- **Event:** A network connection to IP `217.123.118.44` on port `9001` by user "bescra" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\Bescra\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - 11 Mar 2026 09:22:56 - Connected to `51.15.40.38` on port `9001`.
  - 11 Mar 2026 09:09:42 - Connection to `185.177.229.228` on port `9001`.
  - 11 Mar 2026 09:09:13 - Connection to `5.253.43.202` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "Bescra" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - Possibly TOR File related

- **Timestamp:** `2026-03-11 09:41:12`
- **Event:** The user "Bescra" created a file named `THIS.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Bescra\Desktop\THIS.txt`

---

## Summary

The investigation revealed that the user intentionally downloaded and installed the Tor Browser portable version using a silent installation method.
After installation, the user launched Tor and successfully established connections to the Tor network. The user remained active on the network for approximately 15 minutes, during which multiple encrypted connections to external IP addresses were observed.
During the session, the user created and modified a text file named THIS.txt, which contained approximately 1802 bytes of data. The contents of this file could not be recovered through Defender telemetry.
Shortly afterward, the user downloaded an additional archive named proxy-server-portable.zip, potentially indicating an attempt to use additional anonymity or traffic routing tools.
Both Tor usage and proxy server tools violate company acceptable use policies, as they enable users to bypass corporate monitoring and network controls.
The endpoint should undergo further investigation through a comprehensive digital forensic analysis to identify any additional evidence relevant to the incident, particularly regarding the creation and modification of the file THIS.txt. This procedure will be performed by a more in depth by digital forensics team.

---

## Response Taken

TOR usage was confirmed on the endpoint `bescra-threathu` by the user `Bescra`. The device was isolated, and the user's direct manager was notified.

---
