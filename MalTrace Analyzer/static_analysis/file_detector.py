import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def detect_file_type(file_path: str) -> str:
    """Detects the file type via extension mapping."""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        type_map = {
            '.exe':  'Windows Executable (PE)',
            '.pdf':  'PDF Document',
            '.docx': 'Word Document',
            '.js':   'JavaScript File',
            '.py':   'Python Script',
            '.bat':  'Batch Script',
            '.zip':  'Archive File',
            '.txt':  'Text File'
        }
        return type_map.get(ext, 'Unknown File Type')
    except Exception as e:
        logger.error(f"Error checking file type for {file_path}: {e}")
        return 'Unknown File Type'