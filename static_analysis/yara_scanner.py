import yara
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def scan_with_yara(file_path: str) -> List[Dict[str, Any]]:
    """Maps the executable against the YARA rules database."""
    results: List[Dict[str, Any]] = []
    try:
        rules_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'yara_rules', 'rules.yar'
        )
        if not os.path.exists(rules_path):
            logger.warning(f"YARA rules file not found at: {rules_path}")
            return results
            
        rules = yara.compile(rules_path)
        matches = rules.match(file_path)
        
        for match in matches:
            results.append({
                'rule':        match.rule,
                'severity':    match.meta.get('severity', 'Medium'),
                'description': match.meta.get('description', '')
            })
    except yara.Error as e:
        logger.error(f"YARA compilation or matching error: {e}")
        results.append({'error': 'YARA engine error'})
    except Exception as e:
        logger.error(f"Unexpected error in yara_scanner for {file_path}: {e}")
        results.append({'error': str(e)})
        
    return results