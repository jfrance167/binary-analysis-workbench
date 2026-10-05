"""Run focused dependency-free containment tests before the full pytest setup."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import test_supervisor

for function in [test_supervisor.test_complete_and_nonzero,
                 test_supervisor.test_timeout_cleans_descendant,
                 test_supervisor.test_output_limit, test_supervisor.test_reject_shell]:
    with tempfile.TemporaryDirectory(prefix='binary-workbench-test-') as directory:
        function(Path(directory))
    print(f'{function.__name__}: PASS')
