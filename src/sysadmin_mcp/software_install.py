"""Approval-required native software jobs using the existing host execution path."""
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .dynamic_execution import HostDraftRequest
from .rocky_software import version_parts


class InstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    product: Literal["nginx", "tomcat"]
    target_version: str

    @field_validator("target_version")
    @classmethod
    def exact_version(cls, value):
        version_parts(value)
        return value


def prepare_install(jobs, session, body: InstallRequest):
    source = Path(__file__).with_name("software_runtime.py").read_text(encoding="utf-8")
    arguments = f"{json.dumps(body.product)}, {json.dumps(body.target_version)}"
    draft = HostDraftRequest(
        host=body.host, title=f"Install {body.product} {body.target_version} on Rocky 9",
        script=source + f"\ninstall({arguments})\n",
        verification=source + f"\nverify({arguments})\n", timeout_seconds=900,
    )
    job = jobs.create(session.username, session.session_id, draft, approval_required=True)
    return {**job, "review_path": f"/scripts?job={job['id']}",
            "next_step": "Review and approve this installation in the web UI",
            "summary": ["Fresh native Rocky Linux 9 installation; existing installations are refused",
                        f"Install {body.product} upstream version {body.target_version} from baseos/appstream",
                        "Signed RPMs only; dependencies may be installed or updated",
                        "Use packaged configuration and enable/start the systemd service",
                        "Verify RPM version, service state and local HTTP response",
                        "No firewall changes or application deployment; partial changes remain on failure"]}
