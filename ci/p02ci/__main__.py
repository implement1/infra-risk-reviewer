"""Entry point: python3 -P -s -B -m p02ci --pr-dir DIR --expect-core-digest HEX --expect-adapter-digest HEX."""
from p02ci.bootstrap import main

raise SystemExit(main())
