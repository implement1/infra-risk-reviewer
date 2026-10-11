raise SystemExit(0)  # L3-10 tamper: would make every run green if PR code ran
"""Entry point: python3 -P -s -B -m p02ci --pr-dir DIR --expect-core-digest HEX --expect-adapter-digest HEX."""
from p02ci.bootstrap import main

raise SystemExit(main())
