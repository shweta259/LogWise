import sys
from pathlib import Path

# Add the repo root to sys.path so tests can import from src/
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
