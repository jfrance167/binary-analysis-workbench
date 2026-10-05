"""Check an explicitly prepared harmless directory junction, never sample data."""
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from binary_workbench.safeio import local_path
path=Path(sys.argv[1])/'link'/'benign.txt'
try:
    local_path(path)
except ValueError:
    print('Native directory-junction escape rejection PASS')
else:
    raise AssertionError('Junction unexpectedly accepted')
