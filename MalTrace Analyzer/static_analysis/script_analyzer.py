import re
import math
from typing import Dict, Any, List

def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_script(file_path: str) -> Dict[str, Any]:
    """
    Performs structural and content analysis on script-based files (BAT, PS1, JS, etc.)
    """
    results = {
        'is_script': True,
        'indicators': [],
        'entropy': 0.0,
        'line_count': 0,
        'size': 0
    }
    
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            results['size'] = len(content)
            results['line_count'] = len(content.splitlines())
            results['entropy'] = round(calculate_entropy(content), 2)
            
            # Common suspicious keywords for various scripts
            patterns = {
                'PowerShell Execution': r'powershell|pwsh|-enc|-executionpolicy',
                'Network Download': r'curl|wget|certutil|downloadstring|webclient',
                'Persistence attempt': r'reg add|schtasks|set-itemproperty',
                'Obfuscation (Base64)': r'[A-Za-z0-9+/]{40,}',
                'Environment Discovery': r'whoami|net user|ipconfig|systeminfo',
                'Self-Deletion': r'del /f /q|remove-item',
            }
            
            for label, pattern in patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    results['indicators'].append(label)
                    
    except Exception as e:
        results['error'] = str(e)
        
    return results
