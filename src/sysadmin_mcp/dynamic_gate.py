"""Opt-in SSH gate; the original read-only installation remains unchanged."""
import os

from .forced_command import SAFE_ENVIRONMENT, validate_policy_file
from .forced_command import main as readonly_main

HELPER = "/usr/local/bin/sysadmin-dynamic-sandbox"


def main() -> int:
    import pwd

    helper = os.environ.get("SSH_ORIGINAL_COMMAND")
    if helper not in {HELPER, "/usr/local/bin/sysadmin-host-scripts"}:
        return readonly_main()
    validate_policy_file(helper)
    user = pwd.getpwuid(os.geteuid())
    environment = {**SAFE_ENVIRONMENT, "HOME": user.pw_dir, "USER": user.pw_name,
                   "LOGNAME": user.pw_name, "XDG_RUNTIME_DIR": f"/run/user/{user.pw_uid}"}
    os.execve(helper, (helper,), environment)
    return 127
