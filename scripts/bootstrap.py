#!/usr/bin/env python3
"""Initialise Agent Ready Project Template v2.1 for a real project."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
TEXT_SUFFIXES = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".py", ".ts", ".tsx",
    ".js", ".jsx", ".mjs", ".cjs", ".sh", ".html", ".css", ".sql",
}
EXCLUDED_PARTS = {".git", ".venv", "node_modules", "dist", "build", "coverage", "__pycache__"}
EXCLUDED_FILES = {
    Path("scripts/bootstrap.py"),
    Path("scripts/platform_check.py"),
}
RUNTIME_KINDS = {"tool", "platform_service", "infrastructure_stack"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialise this template for a project.")
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--project-slug", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--owner-team", required=True)
    parser.add_argument("--technical-owner", required=True)
    parser.add_argument("--product-owner", required=True)
    parser.add_argument(
        "--project-kind",
        choices=["tool", "platform_service", "infrastructure_stack", "sdk_library"],
        default="tool",
    )
    parser.add_argument(
        "--mode",
        choices=["greenfield", "legacy-migration"],
        default="greenfield",
        help="Both modes retain the additive authentication contract when authentication applies.",
    )
    parser.add_argument(
        "--base-url",
        help="Communicated canonical HTTPS URL. Required for project-kind=tool; never inferred from the slug.",
    )
    parser.add_argument(
        "--container-port",
        type=int,
        default=3000,
        help="Internal container port for the primary HTTP service. It may be reused by other Coolify resources.",
    )
    parser.add_argument("--coolify-server", help="Coolify server name. Missing values remain a production blocker.")
    parser.add_argument("--coolify-project", help="Coolify project name. Missing values remain a production blocker.")
    parser.add_argument("--coolify-environment", default="production")
    parser.add_argument("--coolify-resource-name")
    parser.add_argument("--coolify-resource-type", choices=["application", "service"], default="application")
    parser.add_argument(
        "--build-strategy",
        choices=["dockerfile", "docker_compose", "nixpacks", "static", "prebuilt_image"],
        default="docker_compose",
    )
    parser.add_argument("--force", action="store_true", help="Allow re-running bootstrap after reviewing the previous record.")
    return parser.parse_args()


def text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if EXCLUDED_PARTS.intersection(path.parts):
            continue
        if path.relative_to(root) in EXCLUDED_FILES:
            continue
        yield path


def replace_text(root: Path, replacements: list[tuple[str, str]]) -> int:
    changed = 0
    for path in text_files(root):
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = original
        for old, new in replacements:
            updated = updated.replace(old, new)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            changed += 1
    return changed


def canonical_url(value: str | None, project_kind: str, slug: str) -> tuple[str, str | None]:
    if project_kind == "tool" and not value:
        raise ValueError("--base-url is required for tool projects; use the domain that will be registered in Coolify.")
    if not value:
        return f"https://{slug}.pending.invalid", None
    base_url = value.rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError("--base-url must be a canonical HTTPS URL without query or fragment.")
    if parsed.path not in {"", "/"}:
        raise ValueError("--base-url must not contain a path; path routes are configured after bootstrap.")
    return base_url, parsed.hostname


def set_non_network_profile(root: Path, manifest: dict, kind: str) -> None:
    manifest["interfaces"]["web"]["enabled"] = False
    manifest["interfaces"]["web"]["default_auth_profile"] = "none"
    manifest["interfaces"]["api"]["enabled"] = False
    manifest["interfaces"]["mcp"]["enabled"] = False
    manifest["interfaces"]["mcp"]["deployment_mode"] = "disabled"
    manifest["interfaces"]["mcp"]["rollout_state"] = "disabled"
    manifest["authentication"]["authority"] = "none"
    manifest["authentication"]["target_profile"] = "none"
    manifest["authentication"]["compatibility_mode"] = "not-applicable"
    manifest["authentication"]["accepted_profiles"] = ["none"]
    manifest["authentication"]["legacy"]["enabled"] = False
    manifest["authentication"]["oauth"]["enabled"] = False
    manifest["capabilities"] = []
    manifest["ui"]["applicable"] = False
    manifest["ui"]["design_system"] = "none"
    requirements = manifest["platform_requirements"]
    requirements["access_layer_required"] = False
    requirements["api_required"] = False
    requirements["mcp_ready_required"] = False
    requirements["garden_ui_required"] = False

    capability_path = root / "specs/capabilities.v1.yml"
    capability_spec = yaml.safe_load(capability_path.read_text(encoding="utf-8"))
    capability_spec["capabilities"] = []
    capability_path.write_text(yaml.safe_dump(capability_spec, sort_keys=False), encoding="utf-8")

    if kind == "sdk_library":
        requirements["telemetry_required"] = False
        requirements["observatory_registration_required"] = False
        requirements["coolify_runtime_required"] = False
        manifest["telemetry"]["enabled"] = False
        manifest["observatory"]["registration_required"] = False


def build_registration(manifest: dict) -> dict:
    deployment = manifest["deployment"]
    return {
        "schema_version": 1,
        "registration_id": deployment["registry"]["registration_id"],
        "project_slug": manifest["project"]["slug"],
        "project_kind": manifest["project"]["kind"],
        "owner_team": manifest["project"]["owner_team"],
        "environment": deployment["environment"],
        "coolify": {
            key: deployment["coolify"][key]
            for key in (
                "server_name", "project_name", "environment_name", "resource_name",
                "resource_type", "build_strategy", "destination_name"
            )
        },
        "routes": deployment["public_routes"],
        "services": [
            {
                "service_name": service["service_name"],
                "role": service["role"],
                "exposure": service["exposure"],
                "protocol": service["protocol"],
                "container_port": service["container_port"],
            }
            for service in deployment["services"]
        ],
        "published_host_ports": deployment["port_policy"]["published_host_ports"],
        "state": {
            "persistent_storage_required": deployment["persistent_storage"]["required"],
            "database_required": deployment["database"]["required"],
            "backup_required": deployment["backups"]["required"],
        },
        "registry": {
            "status": deployment["registry"]["status"],
            "last_verified_at": deployment["registry"]["last_verified_at"],
        },
    }


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    marker = root / ".template-bootstrap.json"

    if marker.exists() and not args.force:
        print("This repository has already been bootstrapped. Use --force only after reviewing the previous record.", file=sys.stderr)
        return 2
    if not SLUG_RE.fullmatch(args.project_slug):
        print("--project-slug must match ^[a-z][a-z0-9-]{1,62}$", file=sys.stderr)
        return 2
    if not 1 <= args.container_port <= 65535:
        print("--container-port must be between 1 and 65535.", file=sys.stderr)
        return 2

    project_name = args.project_name.strip()
    description = args.description.strip()
    owner_team = args.owner_team.strip()
    technical_owner = args.technical_owner.strip()
    product_owner = args.product_owner.strip()
    if any(len(value) < 2 for value in (project_name, owner_team, technical_owner, product_owner)) or len(description) < 10:
        print("Project name, description, owner team and named owners are required; description must be at least 10 characters.", file=sys.stderr)
        return 2

    try:
        base_url, hostname = canonical_url(args.base_url, args.project_kind, args.project_slug)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    resource_name = args.coolify_resource_name or f"{args.project_slug}-{args.coolify_environment}"
    old_slug = "template-project"
    old_url = "https://template-project.unguess-internal.net"
    replacements = [
        ("{{PROJECT_NAME}}", project_name),
        ("{{SHORT_PROJECT_DESCRIPTION}}", description),
        ("Template Project", project_name),
        (old_url, base_url),
        (old_slug, args.project_slug),
        ("template_project", args.project_slug.replace("-", "_")),
        ("platform-owner", owner_team),
        ("Replace with the project description during bootstrap.", description),
    ]
    changed_files = replace_text(root, replacements)

    manifest_path = root / "project.platform.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["template_mode"] = False
    manifest["project"]["name"] = project_name
    manifest["project"]["kind"] = args.project_kind
    manifest["project"]["description"] = description
    manifest["project"]["owner_team"] = owner_team
    manifest["project"]["technical_owner"] = technical_owner
    manifest["project"]["product_owner"] = product_owner

    deployment = manifest["deployment"]
    deployment["environment"] = args.coolify_environment
    deployment["registry"]["registration_id"] = f"{args.project_slug}:{args.coolify_environment}"
    deployment["registry"]["status"] = "pending_registration"
    deployment["registry"]["last_verified_at"] = None
    deployment["coolify"]["server_name"] = args.coolify_server or "PROJECT_INPUT_REQUIRED"
    deployment["coolify"]["project_name"] = args.coolify_project or "PROJECT_INPUT_REQUIRED"
    deployment["coolify"]["environment_name"] = args.coolify_environment
    deployment["coolify"]["resource_name"] = resource_name
    deployment["coolify"]["resource_type"] = args.coolify_resource_type
    deployment["coolify"]["build_strategy"] = args.build_strategy
    deployment["configuration_status"] = "ready" if args.coolify_server and args.coolify_project else "pending"

    if args.project_kind == "tool":
        deployment["services"][0]["container_port"] = args.container_port
        deployment["public_routes"][0]["hostname"] = hostname
        deployment["public_routes"][0]["target_container_port"] = args.container_port
    elif args.project_kind == "platform_service":
        manifest["interfaces"]["web"]["enabled"] = False
        manifest["ui"]["applicable"] = False
        manifest["ui"]["design_system"] = "none"
        manifest["platform_requirements"]["garden_ui_required"] = False
        deployment["services"][0]["service_name"] = "api"
        deployment["services"][0]["role"] = "api"
        deployment["services"][0]["container_port"] = args.container_port
        deployment["services"][0]["exposure"] = "public" if hostname else "private"
        deployment["public_routes"] = [] if not hostname else [{
            "route_id": "primary-api",
            "hostname": hostname,
            "scheme": "https",
            "path": "/",
            "target_service": "api",
            "target_container_port": args.container_port,
            "canonical": True,
            "shared_hostname": False,
        }]
    elif args.project_kind == "infrastructure_stack":
        set_non_network_profile(root, manifest, args.project_kind)
        deployment["services"] = [{
            "service_name": "primary",
            "role": "other",
            "exposure": "private",
            "protocol": "http",
            "container_port": args.container_port,
            "bind_address": "0.0.0.0",
            "health": {"mode": "none", "liveness_path": None, "readiness_path": None},
            "stateful": False,
        }]
        deployment["public_routes"] = []
    elif args.project_kind == "sdk_library":
        set_non_network_profile(root, manifest, args.project_kind)
        deployment["applicable"] = False
        deployment["platform"] = "none"
        deployment["configuration_status"] = "ready"
        deployment["coolify"] = {
            "server_name": "not-applicable",
            "project_name": "not-applicable",
            "environment_name": "not-applicable",
            "resource_name": f"{args.project_slug}-library",
            "resource_type": "not_applicable",
            "build_strategy": "not_applicable",
            "destination_name": "not-applicable",
            "connect_to_predefined_network": False,
            "raw_compose_deployment": False,
        }
        deployment["services"] = []
        deployment["public_routes"] = []
        deployment["network"]["cross_resource_strategy"] = "none"
        deployment["registry"]["status"] = "exempt"
        deployment["registry"]["validation_required_in_ci"] = False

    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8")
    registration = build_registration(manifest)
    (root / "deployment.registration.yaml").write_text(
        yaml.safe_dump(registration, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    current_state_path = root / "CURRENT_STATE.md"
    current_state = current_state_path.read_text(encoding="utf-8")
    deployment_summary = "No Coolify runtime; SDK library profile." if args.project_kind == "sdk_library" else (
        f"Coolify resource `{resource_name}` on server `{args.coolify_server or 'PROJECT_INPUT_REQUIRED'}`; "
        f"container port `{args.container_port}`."
    )
    bootstrap_section = f"""

## Bootstrap record

- Mode: `{args.mode}`
- Project: `{project_name}` (`{args.project_slug}`)
- Project kind: `{args.project_kind}`
- Canonical URL: `{base_url if hostname else 'not public at bootstrap'}`
- Owner team: `{owner_team}`
- Deployment: {deployment_summary}
- Generated at: `{datetime.now(timezone.utc).isoformat()}`

### Authentication starting state

The target profile is Access Layer OAuth/OIDC Proposal B where authentication applies. Runtime migrations remain additive: existing legacy paths are unchanged and OAuth stays feature-flagged until registration and conformance are complete.

### Deployment starting state

Container ports are local to containers and may be reused by other Coolify resources. Direct host-port publication remains forbidden unless an approved exception is added to the central deployment registry.
"""
    if "## Bootstrap record" not in current_state:
        current_state_path.write_text(current_state.rstrip() + bootstrap_section + "\n", encoding="utf-8")

    record = {
        "template_version": "2.1.0",
        "project_name": project_name,
        "project_slug": args.project_slug,
        "project_kind": args.project_kind,
        "description": description,
        "owner_team": owner_team,
        "technical_owner": technical_owner,
        "product_owner": product_owner,
        "mode": args.mode,
        "base_url": base_url if hostname else None,
        "container_port": args.container_port if args.project_kind in RUNTIME_KINDS else None,
        "coolify_server": args.coolify_server,
        "coolify_project": args.coolify_project,
        "coolify_environment": args.coolify_environment,
        "coolify_resource_name": resource_name if args.project_kind in RUNTIME_KINDS else None,
        "bootstrapped_at": datetime.now(timezone.utc).isoformat(),
        "changed_files": changed_files,
    }
    marker.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    checker = root / "scripts/platform_check.py"
    completed = subprocess.run(
        [sys.executable, str(checker), "--root", str(root)],
        check=False,
        text=True,
    )

    print("\nBootstrap complete.")
    print("Next: complete deployment registration, submit it to the central registry, resolve project placeholders, then run:")
    print("  python scripts/platform_check.py --strict --registry <central-registry-path>")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
