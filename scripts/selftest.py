"""One-command health check: unit tests + attack simulator.

Run:  python scripts/selftest.py
"""

import re
import subprocess
import sys


def main() -> int:
    print(">>> Step 1/2: unit tests")
    tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "tests"],
                           capture_output=True, text=True)
    sys.stdout.write(tests.stdout)
    sys.stderr.write(tests.stderr)
    if tests.returncode != 0:
        print("\n[FAIL] test suite failed")
        return 1
    count = re.search(r"Ran (\d+) tests?", tests.stderr)
    n = count.group(1) if count else "?"

    print("\n>>> Step 2/2: attack simulator")
    if subprocess.run([sys.executable, "scripts/attack_simulator.py"]).returncode != 0:
        print("[FAIL] attack simulator found a gap")
        return 1
    print(f"[PASS] self-test: {n} tests passed, all simulated attacks stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
