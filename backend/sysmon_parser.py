import subprocess
import xml.etree.ElementTree as ET
import shutil
import os
from typing import List, Dict

import logging
logger = logging.getLogger("memguard")

def fetch_sysmon_logs(limit: int = 100) -> List[Dict]:
    """
    Fetches recent Sysmon logs from the Windows Event Log using wevtutil.
    Extracts Event ID 1 (Process Create), 3 (Network Connection), 7 (Image Load).
    """
    events = []
    
    wevtutil_path = shutil.which("wevtutil") or (
        r"C:\Windows\System32\wevtutil.exe" if os.path.exists(r"C:\Windows\System32\wevtutil.exe") else "wevtutil"
    )

    # Query for Event IDs 1, 3, 7. /rd:true means reverse direction (newest first).
    query = "*[System[(EventID=1 or EventID=3 or EventID=7)]]"
    cmd = [
        wevtutil_path, "qe", "Microsoft-Windows-Sysmon/Operational",
        f"/q:{query}", f"/c:{limit}", "/f:xml", "/rd:true"
    ]
    
    try:
        # wevtutil outputs a series of XML elements (not a single root)
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if not result.stdout.strip():
            return []
            
        xml_output = f"<Events>{result.stdout}</Events>"
        
        root = ET.fromstring(xml_output)
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        
        for event in root.findall("ns:Event", ns):
            event_data = {}
            
            system = event.find("ns:System", ns)
            if system is not None:
                event_id_elem = system.find("ns:EventID", ns)
                if event_id_elem is not None:
                    event_data["EventID"] = int(event_id_elem.text)
                    
            event_data_elem = event.find("ns:EventData", ns)
            if event_data_elem is not None:
                for data in event_data_elem.findall("ns:Data", ns):
                    name = data.get("Name")
                    value = data.text
                    event_data[name] = value if value else ""
                    
            if event_data.get("EventID") in [1, 3, 7]:
                events.append(event_data)
                
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
        logger.warning("Sysmon is likely not installed or requires Admin privileges.")
    except ET.ParseError as e:
        logger.error(f"Error parsing Sysmon XML: {e}")
        
    return events
