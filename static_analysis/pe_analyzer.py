import pefile
import logging
from typing import Dict, Any, List
from config import Config

logger = logging.getLogger(__name__)

def analyze_pe(file_path: str) -> Dict[str, Any]:
    """Parses a valid Windows PE file to extract entropy segments and suspicious imported APIs."""
    results: Dict[str, Any] = {
        'is_pe': False,
        'imports': {},
        'suspicious_apis': [],
        'sections': []
    }
    
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
        results['is_pe'] = True

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore') if entry.dll else "Unknown"
                funcs = []
                for imp in entry.imports:
                    if imp and imp.name:
                        fname = imp.name.decode(errors='ignore')
                        funcs.append(fname)
                        
                        # Normalize name (remove A/W suffixes and check against Config)
                        base_name = fname.rstrip('AW')
                        if fname in Config.DANGEROUS_APIS or base_name in Config.DANGEROUS_APIS:
                            if fname not in results['suspicious_apis']:
                                results['suspicious_apis'].append(fname)
                results['imports'][dll] = funcs

        for section in pe.sections:
            results['sections'].append({
                'name':    section.Name.decode(errors='ignore').strip('\x00'),
                'entropy': round(section.get_entropy(), 2)
            })

    except pefile.PEFormatError:
        logger.info(f"{file_path} is not a valid PE file type.")
    except Exception as e:
        logger.error(f"Error during PE parsing for {file_path}: {e}")
        results['error'] = str(e)

    return results