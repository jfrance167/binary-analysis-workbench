"""Run the source-tree CLI without build isolation or dependency downloads."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from binary_workbench.cli import main
raise SystemExit(main())
