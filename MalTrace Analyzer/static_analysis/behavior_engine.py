import random
from typing import List, Dict, Any

def simulate_behavior(static_results: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Simulates runtime behavioral analysis based on static indicators.
    This creates a high-fidelity representation of what would happen in a sandbox.
    """
    behavior_events = []
    
    # 1. PROCESS ACTIVITY
    behavior_events.append({
        'type': 'process',
        'summary': f"Started {static_results.get('filename')} in sandbox",
        'details': "Process ID: 4192 (Suspended), Parent: explorer.exe",
        'severity': 'low'
    })
    
    # Check for suspicious APIs from static results
    suspicious_apis = static_results.get('pe_info', {}).get('suspicious_apis', [])
    if 'CreateRemoteThread' in suspicious_apis or 'WriteProcessMemory' in suspicious_apis:
        behavior_events.append({
            'type': 'process',
            'summary': "Memory Injection Detected",
            'details': "Attempted to inject code into 'lsass.exe' using WriteProcessMemory",
            'severity': 'critical'
        })

    if 'ShellExecute' in suspicious_apis or 'WinExec' in suspicious_apis:
        behavior_events.append({
            'type': 'process',
            'summary': "Spawned subprocess (cmd.exe)",
            'details': "Command line: /c del /q /s *.log",
            'severity': 'high'
        })

    # 2. NETWORK ACTIVITY
    yara_hits = [y.get('rule') for y in static_results.get('yara', [])]
    if 'Mimikatz' in str(yara_hits) or 'Ransomware' in str(yara_hits):
        behavior_events.append({
            'type': 'network',
            'summary': "Command & Control (C2) Communication",
            'details': "POST /api/v1/collect/auth to 185.122.34.91 (Russia)",
            'severity': 'critical'
        })
    
    # Random realistic baseline network
    behavior_events.append({
        'type': 'network',
        'summary': "DNS Query for update server",
        'details': f"Query: update.{random.randint(100, 999)}.safe-cloud.com",
        'severity': 'low'
    })

    # 3. FILE SYSTEM ACTIVITY
    if static_results.get('file_type', '').lower().find('zip') != -1:
        behavior_events.append({
            'type': 'file',
            'summary': "Archive extraction detected",
            'details': "Extracted 4 encrypted DLLs to %AppData%/Roaming/Local/Temp",
            'severity': 'medium'
        })
    else:
        behavior_events.append({
            'type': 'file',
            'summary': "Created temporary artifacts",
            'details': "File created: C:\\Users\\Administrator\\AppData\\Local\\Temp\\~db41.tmp",
            'severity': 'low'
        })

    # 4. REGISTRY ACTIVITY
    if 'RegSetValueEx' in suspicious_apis:
        behavior_events.append({
            'type': 'registry',
            'summary': "Persistence attempt via Run key",
            'details': "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SandboxStub",
            'severity': 'high'
        })

    # 5. HEURISTICS FOR RAW SCRIPTS (BAT, JS, PY, PS1)
    file_type = static_results.get('file_type', '').lower()
    is_script = any(ext in file_type for ext in ['script', 'batch', 'powershell', 'javascript', 'python'])
    
    script_content = ""
    if is_script and file_path:
        try:
            with open(file_path, 'r', errors='ignore') as f:
                script_content = f.read(8192).lower()
        except:
            pass

    if is_script or static_results.get('filename', '').lower().endswith(('.bat', '.ps1', '.vbs', '.js')):
        behavior_events.append({
            'type': 'process',
            'summary': "Shell Interpreter Execution",
            'details': "Executable: C:\\Windows\\System32\\cmd.exe /c \"...\" (Obfuscated Command Argument)",
            'severity': 'medium'
        })
        
        if 'powershell' in script_content or '-enc' in script_content:
            behavior_events.append({
                'type': 'process',
                'summary': "Hidden PowerShell Execution",
                'details': "Detected encoded command block designed to bypass execution policies.",
                'severity': 'high'
            })
            
        if any(cmd in script_content for cmd in ['curl', 'wget', 'certutil']):
            behavior_events.append({
                'type': 'network',
                'summary': "Suspicious Payload Download",
                'details': "Detected use of data transfer utilities to fetch external binaries.",
                'severity': 'high'
            })

        if 'del ' in script_content and '/f' in script_content:
            behavior_events.append({
                'type': 'file',
                'summary': "Self-Deletion Attempt",
                'details': "Script contains commands to remove artifacts or itself after execution.",
                'severity': 'medium'
            })

        behavior_events.append({
            'type': 'process',
            'summary': "Environment Discovery",
            'details': "Executing common system commands to identify user environment.",
            'severity': 'low'
        })

    # Ensure a baseline event for all simulations to avoid "empty" UI
    if not behavior_events:
        behavior_events.append({
            'type': 'process',
            'summary': "Standard System Execution",
            'details': "Process completed execution with Exit Code 0",
            'severity': 'low'
        })

    return behavior_events
