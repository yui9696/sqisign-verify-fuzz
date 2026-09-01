import sys
from pathlib import Path

# Ensure the repo root is importable (so `import sqfuzz` and `import tests.*`
# work) without installing the package. CI also sets PYTHONPATH=.
sys.path.insert(0, str(Path(__file__).parent))
