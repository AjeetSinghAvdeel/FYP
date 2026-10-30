import sys
from pathlib import Path

root = Path(__file__).resolve().parent
backend = root / 'backend'
if backend.exists() and str(backend) not in sys.path:
    sys.path.insert(0, str(backend))
