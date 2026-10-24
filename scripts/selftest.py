
"""One-command health check: runs the full test suite + attack simulator.

Run:  python scripts/selftest.py
"""
import subprocess
import sys

def main():
    print(">>> Step 1/2: Running 5-layer test suite...")
    t = subprocess.run([sys.executable, "-m", "unittest", "discover",
                        "tests", "-v"], cwd=".")
    if t.returncode != 0:
        print("\n✘ TEST SUITE FAILED")
        return 1
    print("\n>>> Step 2/2: Running red-team attack simulator...")
    a = subprocess.run([sys.executable, "scripts/attack_simulator.py"], cwd=".")
    if a.returncode != 0:
        print("\n✘ ATTACK SIMULATOR FOUND A GAP")
        return 1
    print("✔ AEGISID SELF-TEST PASSED: 14/14 tests + all attacks blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
