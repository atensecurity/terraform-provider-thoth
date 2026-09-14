#!/usr/bin/env python3
"""Exercise a built local provider against an in-memory HTTP fixture only.

No tenant or cloud resource is created. Plan artifacts contain fixture data.
Run from any directory: python3 examples/compliance-activation/verify_local_plan.py
"""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads(
    (ROOT / "internal/compliancecatalogue/catalogue.json").read_text()
)


def contains_unknown(value):
    if isinstance(value, dict):
        return any(contains_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_unknown(item) for item in value)
    return value is True


def main():
    settings = {
        "compliance_profile": "soc2",
        "regulatory_regimes": ["soc2"],
        "compliance_revision": 0,
        "model_router": {
            "enabled": True,
            "default_provider": "openai",
            "default_model": "fixture-model",
            "allowed_providers": ["openai", "anthropic"],
            "allowed_models": ["fixture-model", "next-model"],
            "failover_providers": ["anthropic"],
        },
    }
    writes = []

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, payload, status=200):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        def do_GET(self):
            if self.path == "/fixture/thoth/compliance/catalogue":
                return self.reply(
                    dict(
                        MANIFEST,
                        transactional_declarations_supported=True,
                        propagation_max_ms=1000,
                    )
                )
            if self.path == "/fixture/thoth/settings":
                return self.reply(settings)
            self.reply({}, 404)

        def do_PUT(self):
            assert self.path == "/fixture/thoth/settings"
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            writes.append(copy.deepcopy(data))
            if "declared_regulatory_regimes" in data:
                if (
                    data["compliance_expected_revision"]
                    != settings["compliance_revision"]
                ):
                    return self.reply({"error": "compliance_revision_conflict"}, 409)
                assert (
                    data["compliance_catalogue_sha256"] == MANIFEST["catalogue_sha256"]
                )
                assert (
                    data["compliance_evaluator_sha256"] == MANIFEST["evaluator_sha256"]
                )
                assert len(data["compliance_request_id"]) <= 128
                data["compliance_revision"] = settings["compliance_revision"] + 1
                data["propagation_max_ms"] = 1000
                data["compliance_coverage"] = {
                    r["canonical"]: r["counts"]
                    for r in MANIFEST["regimes"]
                    if r["canonical"] in data["declared_regulatory_regimes"]
                }
                data["regimes_without_controls"] = [
                    r
                    for r, counts in data["compliance_coverage"].items()
                    if counts["enforced"] == 0
                ]
            settings.update(data)
            self.reply(settings)

    with (
        ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as server,
        tempfile.TemporaryDirectory(prefix="thoth-compliance-plan-") as directory,
    ):
        threading.Thread(target=server.serve_forever, daemon=True).start()
        work = Path(directory)
        binary_dir = work / "bin"
        binary_dir.mkdir()
        subprocess.run(
            ["go", "build", "-o", str(binary_dir / "terraform-provider-thoth"), "."],
            cwd=ROOT,
            check=True,
        )
        cli = work / "terraform.rc"
        cli.write_text(
            'provider_installation {\n dev_overrides { "registry.terraform.io/atensecurity/thoth" = '
            + json.dumps(str(binary_dir))
            + " }\n direct {}\n}\n"
        )
        config = """terraform {
 required_providers { thoth = { source = "atensecurity/thoth" } }
}
provider "thoth" {
 tenant_id = "fixture"
 org_api_key = "local-fixture-only"
 api_base_url = "http://127.0.0.1:PORT"
}
resource "thoth_governance_settings" "assessment" {
 declared_regulatory_regimes = ["fedramp", "cmmc_l1", "iso_27001"]
 compliance_enforcement_mode = "observe"
}
""".replace("PORT", str(server.server_address[1]))
        (work / "main.tf").write_text(config)
        environment = dict(
            os.environ,
            TF_CLI_CONFIG_FILE=str(cli),
            TF_IN_AUTOMATION="1",
            CHECKPOINT_DISABLE="1",
        )

        def terraform(*args):
            result = subprocess.run(
                ["terraform", *args],
                cwd=work,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if result.returncode:
                raise RuntimeError(result.stdout)
            return result.stdout

        output = terraform("plan", "-input=false", "-no-color", "-out=observe.tfplan")
        plan = json.loads(terraform("show", "-json", "observe.tfplan"))
        values = plan["planned_values"]["root_module"]["resources"][0]["values"]
        assert values["regimes_without_controls"] == ["ISO 27001"]
        assert len(values["compliance_coverage"]) == 3
        assert values["compliance_coverage"]["ISO 27001"]["enforced"] == 0
        assert values["compliance_enforcement_mode"] == "observe"
        assert values["propagation_max_ms"] == 1000
        assert writes == [], "planning must not mutate tenant settings"
        (ROOT / "examples/compliance-activation/observe-plan.txt").write_text(
            output.replace(str(work), "<temporary-fixture-directory>")
        )
        terraform("apply", "-input=false", "-no-color", "observe.tfplan")
        assert len(writes) == 1
        assert writes[0]["compliance_expected_revision"] == 0
        assert writes[0]["declared_regulatory_regimes"] == [
            "CMMC L1",
            "FedRAMP",
            "ISO 27001",
        ]
        # Refresh and second plan must preserve the user's slugs and produce no drift.
        stable = terraform("plan", "-input=false", "-no-color")
        assert "No changes." in stable, stable
        (work / "main.tf").write_text(config.replace('= "observe"', '= "enforce"'))
        enforce = terraform("plan", "-input=false", "-no-color", "-out=enforce.tfplan")
        enforce_plan = json.loads(terraform("show", "-json", "enforce.tfplan"))
        change = enforce_plan["resource_changes"][0]["change"]
        expected_changes = {
            "compliance_enforcement_mode",
            "compliance_revision",
            "updated_at",
        }
        for key, before in change["before"].items():
            if key not in expected_changes:
                assert change["after"].get(key) == before, (key, change)
                assert not contains_unknown(change["after_unknown"].get(key)), (
                    key,
                    change,
                )
        assert '"observe" -> "enforce"' in enforce
        assert "within 1000 ms" in enforce
        (ROOT / "examples/compliance-activation/enforce-plan.txt").write_text(
            enforce.replace(str(work), "<temporary-fixture-directory>")
        )
        terraform("apply", "-input=false", "-no-color", "enforce.tfplan")
        assert writes[-1]["compliance_expected_revision"] == 1
        cleared_config = "\n".join(
            line
            for line in config.splitlines()
            if "declared_regulatory_regimes" not in line
            and "compliance_enforcement_mode" not in line
        )
        (work / "main.tf").write_text(cleared_config)
        terraform("apply", "-input=false", "-auto-approve", "-no-color")
        assert writes[-1]["declared_regulatory_regimes"] == []
        assert writes[-1]["compliance_enforcement_mode"] is None
        assert writes[-1]["compliance_expected_revision"] == 2
        assert "No changes." in terraform("plan", "-input=false", "-no-color")
        (work / "main.tf").write_text(config)
        terraform("apply", "-input=false", "-auto-approve", "-no-color")
        assert writes[-1]["compliance_expected_revision"] == 3
        terraform("destroy", "-input=false", "-auto-approve", "-no-color")
        assert writes[-1]["declared_regulatory_regimes"] == []
        assert writes[-1]["compliance_enforcement_mode"] is None
        assert writes[-1]["compliance_expected_revision"] == 4
        assert set(writes[-1]) == {
            "declared_regulatory_regimes",
            "compliance_enforcement_mode",
            "compliance_expected_revision",
            "compliance_request_id",
            "compliance_catalogue_sha256",
            "compliance_evaluator_sha256",
        }

        # Changing either routing input surface must still produce real updates.
        # Start after the lifecycle assertions so their revision sequence stays clear.
        def routing_config(router, *, extra):
            if extra:
                attributes = " extra_settings_json = " + json.dumps(
                    json.dumps({"model_router": router}, sort_keys=True)
                )
            else:
                attributes = "\n".join(
                    " model_router_" + key + " = " + json.dumps(value)
                    for key, value in router.items()
                )
            prefix, ending = cleared_config.rsplit("}", 1)
            return prefix + attributes + "\n}" + ending

        first_router = {
            "enabled": True,
            "default_provider": "openai",
            "default_model": "fixture-model",
            "allowed_providers": ["openai", "anthropic"],
            "allowed_models": ["fixture-model", "next-model"],
            "failover_providers": ["anthropic"],
        }
        second_router = {
            "enabled": False,
            "default_provider": "anthropic",
            "default_model": "next-model",
            "allowed_providers": ["anthropic", "openai"],
            "allowed_models": ["next-model", "fixture-model"],
            "failover_providers": ["openai"],
        }
        for extra in (True, False):
            for router in (first_router, second_router):
                (work / "main.tf").write_text(routing_config(router, extra=extra))
                terraform("apply", "-input=false", "-auto-approve", "-no-color")
                assert writes[-1]["model_router"] == router, writes[-1]
                actual = json.loads(terraform("show", "-json"))["values"][
                    "root_module"
                ]["resources"][0]["values"]
                for key, value in router.items():
                    assert actual["model_router_" + key] == value, actual
                assert "No changes." in terraform("plan", "-input=false", "-no-color")
        server.shutdown()
        print(
            "PASS: real Terraform create plan, observe apply, stable refresh, enforce diff/apply, removal/re-declaration, conditional destroy, and typed/extra routing updates against local fixture"
        )


if __name__ == "__main__":
    main()
