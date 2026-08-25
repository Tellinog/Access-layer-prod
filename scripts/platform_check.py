#!/usr/bin/env python3
"""Validate Agent Ready Project Template v2.1 platform contracts.

The checker is intentionally application-stack neutral. It validates the
repository contract, not framework-specific implementation details.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml
from jsonschema import Draft202012Validator, FormatChecker

CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9-]+(?::[a-z][a-z0-9-]+){1,}$")
OPERATION_KEYS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
REQUIRED_LEGACY_ENDPOINTS = {
    "/v1/auth/start",
    "/v1/auth/google/callback",
    "/v1/auth/exchange",
    "/v1/auth/refresh",
    "/v1/auth/introspect",
    "/v1/auth/logout",
    "/v1/.well-known/jwks.json",
}
SOURCE_GARDEN_COLOURS = {
    "navy": "#003A57",
    "deepNavy": "#001D2C",
    "green": "#00B27F",
    "lightGreen": "#54C38A",
    "primary": "#333333",
    "secondary": "#4B5F5F",
    "muted": "#7A7A7A",
    "subtle": "#F9FAFA",
}


def _srgb_channel(value: int) -> float:
    channel = value / 255.0
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_colour: str) -> float:
    """Return WCAG relative luminance for a six-digit hexadecimal colour."""
    value = hex_colour.lstrip("#")
    if not re.fullmatch(r"[0-9a-fA-F]{6}", value):
        raise ValueError(f"Unsupported colour: {hex_colour}")
    red, green, blue = (int(value[index:index + 2], 16) for index in (0, 2, 4))
    return 0.2126 * _srgb_channel(red) + 0.7152 * _srgb_channel(green) + 0.0722 * _srgb_channel(blue)


def contrast_ratio(foreground: str, background: str) -> float:
    """Return the WCAG contrast ratio for two six-digit hexadecimal colours."""
    first, second = relative_luminance(foreground), relative_luminance(background)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


@dataclass
class CheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def ok(self, message: str) -> None:
        self.passed.append(message)

    @property
    def success(self) -> bool:
        return not self.errors


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def validate_instance(
    instance_path: Path,
    schema_path: Path,
    root: Path,
    result: CheckResult,
) -> None:
    try:
        instance = load_json(instance_path) if instance_path.suffix == ".json" else load_yaml(instance_path)
        schema = load_json(schema_path)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
        if errors:
            for err in errors:
                location = ".".join(str(part) for part in err.absolute_path) or "<root>"
                result.error(
                    f"{display_path(instance_path, root)} does not match "
                    f"{display_path(schema_path, root)} at {location}: {err.message}"
                )
        else:
            result.ok(
                f"Schema validation: {display_path(instance_path, root)}"
            )
    except Exception as exc:  # noqa: BLE001 - report every validation issue
        result.error(
            f"Unable to validate {display_path(instance_path, root)} against "
            f"{display_path(schema_path, root)}: {exc}"
        )


def iter_text_files(root: Path) -> Iterable[Path]:
    extensions = {
        ".md", ".txt", ".json", ".yaml", ".yml", ".py", ".ts", ".tsx",
        ".js", ".jsx", ".mjs", ".cjs", ".sh", ".html", ".css", ".sql",
    }
    excluded_parts = {".git", ".venv", "node_modules", "dist", "build", "coverage", "__pycache__"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        if excluded_parts.intersection(path.parts):
            continue
        yield path


def check_parseability(root: Path, result: CheckResult) -> None:
    for path in root.rglob("*.json"):
        if any(part in {".venv", "node_modules"} for part in path.parts):
            continue
        try:
            load_json(path)
        except Exception as exc:  # noqa: BLE001
            result.error(f"Invalid JSON in {display_path(path, root)}: {exc}")
    for pattern in ("*.yaml", "*.yml"):
        for path in root.rglob(pattern):
            if any(part in {".venv", "node_modules"} for part in path.parts):
                continue
            try:
                load_yaml(path)
            except Exception as exc:  # noqa: BLE001
                result.error(f"Invalid YAML in {display_path(path, root)}: {exc}")
    if not result.errors:
        result.ok("All JSON and YAML files are parseable")


def check_required_files(root: Path, result: CheckResult) -> None:
    required = [
        "AGENTS.md",
        "project.platform.yaml",
        "deployment.registration.yaml",
        "schemas/project-platform.schema.json",
        "schemas/deployment-registration.schema.json",
        "schemas/deployment-registry.schema.json",
        "schemas/request-context.schema.json",
        "schemas/error.schema.json",
        "schemas/events.schema.json",
        "schemas/openapi.yaml",
        "schemas/access-layer-legacy-v1.openapi.yaml",
        "docs/ACCESS_LAYER.md",
        "docs/LEGACY_COMPATIBILITY.md",
        "docs/AGENT_INTERFACE.md",
        "docs/OBSERVABILITY.md",
        "docs/COOLIFY_DEPLOYMENT.md",
        "docs/platform/PROJECT_TYPES.md",
        "docs/platform/UNGUESS_PLATFORM_SDK.md",
        "docs/platform/OBSERVABILITY_STACK_CONTRACT.md",
        "docs/platform/DEPLOYMENT_REGISTRY_CONTRACT.md",
        "specs/deployment.v1.yml",
        "docs/compliance/AI_ACT_ASSESSMENT.md",
        "assets/brand/garden.tokens.json",
        "tests/platform-conformance/test-cases.yml",
        "tests/platform-conformance/legacy/test-cases.yml",
    ]
    missing = [path for path in required if not (root / path).is_file()]
    if missing:
        for path in missing:
            result.error(f"Required file is missing: {path}")
    else:
        result.ok("Required platform-contract files are present")


def check_manifest(root: Path, result: CheckResult) -> dict[str, Any] | None:
    manifest_path = root / "project.platform.yaml"
    schema_path = root / "schemas/project-platform.schema.json"
    if not manifest_path.exists() or not schema_path.exists():
        return None
    validate_instance(manifest_path, schema_path, root, result)
    try:
        manifest = load_yaml(manifest_path)
    except Exception:
        return None

    references = [
        manifest["deployment"]["registration"],
        manifest["deployment"]["rollback"]["runbook"],
        manifest["interfaces"]["api"]["openapi"],
        manifest["interfaces"]["mcp"]["capability_manifest"],
        manifest["authentication"]["legacy"]["contract"],
        manifest["authentication"]["legacy"]["permission_alias_registry"],
        manifest["authentication"]["oauth"]["protected_resource_metadata"],
        manifest["request_context"]["schema"],
        manifest["ui"]["tokens"],
        manifest["ai"]["assessment"],
        manifest["ai"]["system_spec"],
        manifest["ai"]["use_cases"],
        manifest["ai"]["provider_registry"],
        manifest["ai"]["data_boundary"],
        manifest["ai"]["human_oversight"],
        manifest["ai"]["evaluation"],
        manifest["telemetry"]["product_event_schema"],
        manifest["slo"]["specification"],
    ]
    for ref in references:
        ref_path = (root / str(ref)).resolve()
        if not ref_path.exists():
            result.error(f"Manifest reference does not exist: {ref}")
    if not any("Manifest reference" in error for error in result.errors):
        result.ok("All manifest file references resolve")
    return manifest



def check_platform_baseline(manifest: dict[str, Any], result: CheckResult) -> None:
    project_kind = manifest.get("project", {}).get("kind")
    requirements = manifest.get("platform_requirements", {})
    legacy_migration = manifest.get("project", {}).get("mode") == "legacy-migration"

    for key in ("deployment_contract_required", "english_first_required", "ai_assessment_required"):
        if requirements.get(key) is not True:
            result.error(f"Mandatory platform baseline requires platform_requirements.{key}=true")

    runtime_kinds = {"tool", "platform_service", "infrastructure_stack"}
    if project_kind in runtime_kinds:
        for key in ("coolify_runtime_required", "telemetry_required", "observatory_registration_required"):
            if requirements.get(key) is not True:
                result.error(f"Runtime project requires platform_requirements.{key}=true")
    elif project_kind == "sdk_library":
        if requirements.get("coolify_runtime_required") is not False:
            result.error("SDK libraries must set platform_requirements.coolify_runtime_required=false")
    else:
        result.error(f"Unsupported project.kind: {project_kind}")

    interfaces = manifest.get("interfaces", {})
    if project_kind == "tool":
        for key in ("access_layer_required", "api_required", "mcp_ready_required", "garden_ui_required"):
            if requirements.get(key) is not True:
                result.error(f"Tool projects require platform_requirements.{key}=true")
        if interfaces.get("api", {}).get("enabled") is not True:
            result.error("Tool projects must publish an enabled canonical API contract")
        if interfaces.get("mcp", {}).get("enabled") is not True:
            result.error("Tool projects must remain MCP-ready, even when rollout is disabled")

    if interfaces.get("api", {}).get("enabled") and requirements.get("api_required") is not True:
        result.error("Enabled API interface requires platform_requirements.api_required=true")
    if interfaces.get("mcp", {}).get("enabled") and requirements.get("mcp_ready_required") is not True:
        result.error("Enabled MCP interface requires platform_requirements.mcp_ready_required=true")
    if interfaces.get("web", {}).get("enabled") and manifest.get("ui", {}).get("applicable") is not True:
        result.error("Enabled web interface requires ui.applicable=true")

    authentication = manifest.get("authentication", {})
    if requirements.get("access_layer_required"):
        if authentication.get("authority") != "access-layer":
            result.error("Access Layer is the mandatory authentication authority")
        if authentication.get("target_profile") != "unguess-oauth-oidc-v1":
            result.error("Proposal B requires authentication.target_profile=unguess-oauth-oidc-v1")
    elif project_kind == "sdk_library" and authentication.get("authority") not in {"none", "access-layer"}:
        result.error("SDK authentication authority must be none or a documented Access Layer contract")

    telemetry = manifest.get("telemetry", {})
    if requirements.get("telemetry_required"):
        if telemetry.get("enabled") is not True:
            if legacy_migration:
                result.warn("Legacy-migration exception: runtime platform telemetry is required but not integrated in Step 1")
            else:
                result.error("Runtime platform telemetry must be enabled")
        if telemetry.get("non_blocking") is not True:
            result.error("Telemetry must be non-blocking and outside the business critical path")
        if telemetry.get("prohibit_user_identity_in_metric_labels") is not True:
            result.error("User identity must be prohibited in technical metric labels")
        expected_destinations = {
            "instrumentation_source": "unguess-platform-sdk",
            "technical_destination": "unguess-observability-stack",
            "product_event_destination": "tool-observatory",
        }
        for key, expected in expected_destinations.items():
            if telemetry.get(key) != expected:
                result.error(f"Telemetry contract requires telemetry.{key}={expected}")

    if requirements.get("observatory_registration_required") and manifest.get("observatory", {}).get("registration_required") is not True:
        result.error("Tool Observatory registration is mandatory for runtime projects")

    baseline_terms = (
        "Mandatory platform baseline", "Runtime project", "SDK libraries", "Tool projects",
        "Enabled API", "Enabled MCP", "Enabled web", "Proposal B", "telemetry", "Observatory"
    )
    if not any(any(term.lower() in error.lower() for term in baseline_terms) for error in result.errors):
        result.ok("Project type, mandatory platform baseline and Proposal B target are coherent")


def _registration_comparable(registration: dict[str, Any]) -> dict[str, Any]:
    return {
        "registration_id": registration.get("registration_id"),
        "project_slug": registration.get("project_slug"),
        "project_kind": registration.get("project_kind"),
        "owner_team": registration.get("owner_team"),
        "environment": registration.get("environment"),
        "coolify": registration.get("coolify"),
        "routes": registration.get("routes", []),
        "services": registration.get("services", []),
        "published_host_ports": registration.get("published_host_ports", []),
        "state": registration.get("state"),
        "registry": {
            "status": registration.get("registry", {}).get("status"),
            "last_verified_at": registration.get("registry", {}).get("last_verified_at"),
        },
    }


def _manifest_registration(manifest: dict[str, Any]) -> dict[str, Any]:
    deployment = manifest["deployment"]
    services = [
        {
            "service_name": service["service_name"],
            "role": service["role"],
            "exposure": service["exposure"],
            "protocol": service["protocol"],
            "container_port": service["container_port"],
        }
        for service in deployment.get("services", [])
    ]
    return {
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
        "routes": deployment.get("public_routes", []),
        "services": services,
        "published_host_ports": deployment.get("port_policy", {}).get("published_host_ports", []),
        "state": {
            "persistent_storage_required": deployment.get("persistent_storage", {}).get("required"),
            "database_required": deployment.get("database", {}).get("required"),
            "backup_required": deployment.get("backups", {}).get("required"),
        },
        "registry": {
            "status": deployment.get("registry", {}).get("status"),
            "last_verified_at": deployment.get("registry", {}).get("last_verified_at"),
        },
    }


def deployment_paths_overlap(first: str, second: str) -> bool:
    """Return whether two proxy paths overlap on the same hostname."""
    first_path = first.rstrip("/") or "/"
    second_path = second.rstrip("/") or "/"
    if first_path == "/" or second_path == "/":
        return True
    return (
        first_path == second_path
        or first_path.startswith(second_path + "/")
        or second_path.startswith(first_path + "/")
    )


def check_central_deployment_registry(
    root: Path,
    registration: dict[str, Any],
    registry_path: Path,
    result: CheckResult,
) -> None:
    validate_instance(registry_path, root / "schemas/deployment-registry.schema.json", root, result)
    try:
        registry = load_yaml(registry_path)
        deployments = registry.get("deployments", [])
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot load central deployment registry: {exc}")
        return

    ids: dict[str, int] = {}
    resources: dict[tuple[str, str], str] = {}
    route_keys: dict[tuple[str, str], str] = {}
    hostname_entries: dict[str, list[tuple[str, str, bool]]] = {}
    host_ports: dict[tuple[str, str, int], list[tuple[str, str]]] = {}

    for entry in deployments:
        registration_id = entry.get("registration_id", "<missing>")
        ids[registration_id] = ids.get(registration_id, 0) + 1
        coolify = entry.get("coolify", {})
        resource_key = (str(coolify.get("server_name")), str(coolify.get("resource_name")))
        previous = resources.get(resource_key)
        if previous:
            result.error(f"Duplicate Coolify resource on one server: {resource_key} ({previous}, {registration_id})")
        resources[resource_key] = registration_id

        for route in entry.get("routes", []):
            hostname = str(route.get("hostname"))
            path = str(route.get("path"))
            route_key = (hostname, path)
            previous_route = route_keys.get(route_key)
            if previous_route:
                result.error(f"Duplicate deployment route {hostname}{path}: {previous_route}, {registration_id}")
            route_keys[route_key] = registration_id
            hostname_entries.setdefault(hostname, []).append(
                (registration_id, path, bool(route.get("shared_hostname")))
            )

        for mapping in entry.get("published_host_ports", []):
            server = str(coolify.get("server_name"))
            protocol = str(mapping.get("protocol"))
            host_port = int(mapping.get("host_port"))
            bind_address = str(mapping.get("bind_address")).strip().lower()
            key = (server, protocol, host_port)
            wildcard_addresses = {"0.0.0.0", "::", "[::]", "*"}
            for previous_address, previous_registration in host_ports.get(key, []):
                overlaps = (
                    bind_address == previous_address
                    or bind_address in wildcard_addresses
                    or previous_address in wildcard_addresses
                )
                if overlaps:
                    result.error(
                        "Overlapping published host port "
                        f"{server}/{protocol}/{host_port} on {previous_address} and {bind_address}: "
                        f"{previous_registration}, {registration_id}"
                    )
            host_ports.setdefault(key, []).append((bind_address, registration_id))
            try:
                expiry = datetime.fromisoformat(str(mapping.get("expires_at")).replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry <= datetime.now(timezone.utc):
                    result.error(f"Expired published host-port exception in central registry: {registration_id}")
            except (TypeError, ValueError):
                result.error(f"Invalid host-port expires_at in central registry: {registration_id}")

    for registration_id, count in ids.items():
        if count > 1:
            result.error(f"Duplicate deployment registration_id: {registration_id}")

    for hostname, entries in hostname_entries.items():
        if len(entries) <= 1:
            continue
        if not all(shared for _, _, shared in entries):
            owners = ", ".join(item[0] for item in entries)
            result.error(f"Hostname is reused without shared_hostname=true: {hostname} ({owners})")
            continue
        for index, (first_owner, first_path, _) in enumerate(entries):
            for second_owner, second_path, _ in entries[index + 1:]:
                if deployment_paths_overlap(first_path, second_path):
                    result.error(
                        f"Shared hostname routes overlap: {hostname}{first_path} ({first_owner}) "
                        f"and {hostname}{second_path} ({second_owner})"
                    )

    local_id = registration.get("registration_id")
    matches = [entry for entry in deployments if entry.get("registration_id") == local_id]
    if len(matches) != 1:
        result.error(f"Central registry must contain exactly one entry for {local_id}")
    elif _registration_comparable(matches[0]) != _registration_comparable(registration):
        result.error(f"Central registry entry differs from deployment.registration.yaml for {local_id}")
    else:
        result.ok("Central Coolify deployment registry is unique and matches the local registration")


def check_deployment_contract(
    root: Path,
    manifest: dict[str, Any],
    result: CheckResult,
    strict: bool,
    registry_path: Path | None,
) -> None:
    deployment = manifest.get("deployment", {})
    project = manifest.get("project", {})
    project_kind = project.get("kind")
    template_mode = bool(manifest.get("template_mode"))
    registration_path = root / str(deployment.get("registration", ""))

    validate_instance(
        registration_path,
        root / "schemas/deployment-registration.schema.json",
        root,
        result,
    )
    try:
        registration = load_yaml(registration_path)
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot load deployment registration: {exc}")
        return

    runtime = project_kind in {"tool", "platform_service", "infrastructure_stack"}
    if project_kind == "sdk_library":
        if deployment.get("applicable") is not False or deployment.get("platform") != "none":
            result.error("sdk_library projects must set deployment.applicable=false and deployment.platform=none")
        if deployment.get("services") or deployment.get("public_routes") or deployment.get("port_policy", {}).get("published_host_ports"):
            result.error("sdk_library projects cannot declare runtime services, routes or host ports")
        if registration.get("project_kind") != "sdk_library":
            result.warn("SDK libraries are not entered in the runtime deployment registry")
        result.ok("SDK library correctly has no Coolify runtime")
        return

    if not runtime:
        result.error(f"Cannot evaluate deployment for unsupported project kind: {project_kind}")
        return

    if deployment.get("applicable") is not True or deployment.get("platform") != "coolify":
        result.error("Every runtime project must declare an applicable Coolify deployment")
    if deployment.get("unit_policy") != "one-coolify-resource-per-project":
        result.error("Default deployment unit must be one Coolify resource per project")
    if deployment.get("configuration_status") != "ready":
        message = "Coolify deployment configuration_status is not ready"
        if strict and not template_mode:
            result.error(message)
        else:
            result.warn(message)

    services = deployment.get("services", [])
    service_map = {service.get("service_name"): service for service in services}
    if not services:
        result.error("Runtime Coolify deployment requires at least one service")
    if len(service_map) != len(services):
        result.error("Coolify service names must be unique inside the project")

    routes = deployment.get("public_routes", [])
    if project_kind == "tool" and not routes:
        result.error("Tool projects require at least one public HTTPS route")
    canonical = [route for route in routes if route.get("canonical")]
    if project_kind == "tool" and len(canonical) != 1:
        result.error("Tool projects require exactly one canonical public route")

    local_route_keys: set[tuple[str, str]] = set()
    for route in routes:
        key = (str(route.get("hostname")), str(route.get("path")))
        if key in local_route_keys:
            result.error(f"Duplicate local public route: {key[0]}{key[1]}")
        local_route_keys.add(key)
        service = service_map.get(route.get("target_service"))
        if not service:
            result.error(f"Public route targets an unknown service: {route.get('target_service')}")
            continue
        if service.get("container_port") != route.get("target_container_port"):
            result.error(f"Public route target port differs from service port: {route.get('route_id')}")
        if service.get("exposure") != "public":
            result.error(f"Public route targets a non-public service: {route.get('route_id')}")
        if service.get("protocol") not in {"http", "https"}:
            result.error(f"HTTPS public route must target an HTTP service: {route.get('route_id')}")

    for service in services:
        if service.get("role") in {"database", "cache"} and service.get("exposure") == "public":
            result.error(f"Private data service cannot be public: {service.get('service_name')}")
        if service.get("exposure") == "public":
            if service.get("container_port") is None:
                result.error(f"Public service lacks container port: {service.get('service_name')}")
            if service.get("protocol") in {"http", "https"} and service.get("bind_address") != "0.0.0.0":
                result.error(f"Coolify-proxied HTTP service must bind to 0.0.0.0: {service.get('service_name')}")
            health = service.get("health", {})
            if health.get("mode") == "none":
                result.error(f"Public service lacks a health check: {service.get('service_name')}")
            if health.get("mode") == "http" and (not health.get("liveness_path") or not health.get("readiness_path")):
                result.error(f"HTTP service must declare liveness and readiness paths: {service.get('service_name')}")

    network = deployment.get("network", {})
    coolify = deployment.get("coolify", {})
    cross_strategy = network.get("cross_resource_strategy")
    shared_network = bool(coolify.get("connect_to_predefined_network"))
    external_resources = network.get("allowed_external_resources", [])
    if shared_network and cross_strategy not in {"coolify-predefined-network", "mixed"}:
        result.error("Coolify predefined network is enabled without the matching cross-resource strategy")
    if not shared_network and cross_strategy in {"coolify-predefined-network", "mixed"}:
        result.error("Cross-resource strategy requires coolify.connect_to_predefined_network=true")
    if external_resources and cross_strategy == "none":
        result.error("allowed_external_resources requires an explicit cross-resource strategy")
    if cross_strategy != "none" and not external_resources:
        message = "Cross-resource networking is selected but allowed_external_resources is empty"
        if strict and not template_mode:
            result.error(message)
        else:
            result.warn(message)

    port_policy = deployment.get("port_policy", {})
    if port_policy.get("container_ports_may_repeat_across_coolify_resources") is not True:
        result.error("Container ports must not be modelled as globally unique")
    if port_policy.get("host_ports_forbidden_by_default") is not True:
        result.error("Published host ports must be forbidden by default")
    for mapping in port_policy.get("published_host_ports", []):
        target = service_map.get(mapping.get("target_service"))
        if not target:
            result.error(f"Published host port targets unknown service: {mapping.get('target_service')}")
        elif target.get("container_port") != mapping.get("container_port"):
            result.error(f"Published host port container_port mismatch for {mapping.get('target_service')}")
        try:
            expiry = datetime.fromisoformat(str(mapping.get("expires_at")).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                result.error(f"Published host-port exception is expired for {mapping.get('target_service')}")
        except (TypeError, ValueError):
            result.error(f"Published host-port exception has invalid expires_at for {mapping.get('target_service')}")

    storage = deployment.get("persistent_storage", {})
    database = deployment.get("database", {})
    backups = deployment.get("backups", {})
    stateful_services = [service for service in services if service.get("stateful")]
    volumes = storage.get("volumes", [])
    if storage.get("required") and not volumes:
        result.error("Persistent storage is required but no volumes are declared")
    if not storage.get("required") and volumes:
        result.error("Persistent volumes are declared while persistent_storage.required=false")
    if stateful_services and not storage.get("required"):
        result.error("Stateful services require persistent_storage.required=true")
    volume_ids = [volume.get("volume_id") for volume in volumes]
    target_paths = [volume.get("target_path") for volume in volumes]
    if len(volume_ids) != len(set(volume_ids)):
        result.error("Persistent volume IDs must be unique")
    if len(target_paths) != len(set(target_paths)):
        result.error("Persistent volume target paths must be unique")
    backup_volumes = [volume for volume in volumes if volume.get("backup_required")]
    if backup_volumes and backups.get("required") is not True:
        result.error("Volumes marked backup_required require backups.required=true")
    database_services = [service for service in services if service.get("role") == "database"]
    if database_services and database.get("required") is not True:
        result.error("A declared database service requires database.required=true")
    if database.get("required"):
        db_service = service_map.get(database.get("service_name"))
        if not db_service or db_service.get("role") != "database":
            result.error("database.service_name must reference a declared database service")
        if database.get("backup_required") is not True or backups.get("required") is not True:
            result.error("Production database requires backup_required=true and backups.required=true")
    if backups.get("required"):
        unresolved_backup = (
            backups.get("policy") in {"pending", "not_applicable"}
            or not backups.get("schedule")
            or not backups.get("retention_days")
            or backups.get("restore_test_frequency") in {"pending", "not_applicable"}
        )
        if unresolved_backup:
            message = "Required backup schedule, retention or restore-test policy is unresolved"
            if strict and not template_mode:
                result.error(message)
            else:
                result.warn(message)

    expected_registration = _manifest_registration(manifest)
    if _registration_comparable(registration) != expected_registration:
        result.error("deployment.registration.yaml is not aligned with project.platform.yaml")

    registry = deployment.get("registry", {})
    expected_id = f"{project.get('slug')}:{deployment.get('environment')}"
    if registry.get("registration_id") != expected_id:
        result.error(f"Deployment registration_id must be {expected_id}")
    if strict and not template_mode and registry.get("status") != "registered":
        result.error("Production deployment must be registered in the central deployment registry")
    if strict and not template_mode and registry.get("status") == "registered" and not registry.get("last_verified_at"):
        result.error("Registered production deployment requires registry.last_verified_at")

    if registry_path:
        check_central_deployment_registry(root, registration, registry_path.resolve(), result)
    elif registry.get("validation_required_in_ci"):
        message = "Central deployment registry was not supplied; pass --registry or PLATFORM_DEPLOYMENT_REGISTRY_PATH"
        if strict and not template_mode:
            result.error(message)
        else:
            result.warn(message)

    if not any("deployment" in error.lower() or "coolify" in error.lower() or "route" in error.lower() or "port" in error.lower() or "backup" in error.lower() or "registry" in error.lower() for error in result.errors):
        result.ok("Coolify deployment, routing, port, storage, backup and registry contracts are coherent")


def extract_openapi_operations(openapi: dict[str, Any]) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for path, path_item in openapi.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in OPERATION_KEYS or not isinstance(operation, dict):
                continue
            operations.append({"path": path, "method": method.lower(), **operation})
    return operations


def check_capability_contract(root: Path, manifest: dict[str, Any], result: CheckResult) -> None:
    validate_instance(
        root / manifest["interfaces"]["mcp"]["capability_manifest"],
        root / "schemas/capability-manifest.schema.json",
        root,
        result,
    )
    capabilities = manifest.get("capabilities", [])
    interfaces = manifest.get("interfaces", {})
    api_enabled = bool(interfaces.get("api", {}).get("enabled"))
    mcp_enabled = bool(interfaces.get("mcp", {}).get("enabled"))
    if not capabilities and not api_enabled and not mcp_enabled:
        result.ok("No network capability contract is required for this repository profile")
        return
    api_resource = interfaces.get("api", {}).get("resource_id")
    oauth = manifest.get("authentication", {}).get("oauth", {})
    if api_enabled or mcp_enabled:
        if oauth.get("resource_id") != api_resource:
            result.error("OAuth resource_id must equal interfaces.api.resource_id")
        if oauth.get("audience") != api_resource:
            result.error("OAuth audience must equal interfaces.api.resource_id")
    ids: set[str] = set()
    operations: set[str] = set()
    mcp_names: set[str] = set()
    for capability in capabilities:
        capability_id = capability.get("capability_id", "")
        if capability_id in ids:
            result.error(f"Duplicate capability_id: {capability_id}")
        ids.add(capability_id)
        if not CAPABILITY_RE.fullmatch(capability_id):
            result.error(f"Capability uses a non-legacy-compatible identifier: {capability_id}")
        if capability.get("permission") != capability_id:
            result.error(f"Permission must equal capability_id for {capability_id}")
        if capability.get("oauth_scope") != capability_id:
            result.error(f"OAuth scope must equal capability_id for {capability_id}")
        operation_id = capability.get("operation_id")
        if operation_id in operations:
            result.error(f"Duplicate operation_id: {operation_id}")
        operations.add(operation_id)
        if "mcp" in capability.get("exposure", []):
            mcp_name = capability.get("mcp_name")
            if not mcp_name:
                result.error(f"MCP-exposed capability lacks mcp_name: {capability_id}")
            elif mcp_name in mcp_names:
                result.error(f"Duplicate mcp_name: {mcp_name}")
            else:
                mcp_names.add(mcp_name)
        if not capability.get("read_only", False) and capability.get("idempotency") != "required":
            result.error(f"Mutating capability must require idempotency: {capability_id}")
        if capability.get("destructive", False) and capability.get("human_confirmation") == "never":
            result.error(f"Destructive capability cannot set human_confirmation=never: {capability_id}")

    try:
        spec = load_yaml(root / "specs/capabilities.v1.yml")
        spec_map = {item["capability_id"]: item for item in spec.get("capabilities", [])}
        for capability in capabilities:
            capability_id = capability["capability_id"]
            if capability_id not in spec_map:
                result.error(f"Manifest capability missing from specs/capabilities.v1.yml: {capability_id}")
                continue
            for key in ("operation_id", "mcp_name", "permission", "oauth_scope", "risk", "read_only"):
                if spec_map[capability_id].get(key) != capability.get(key):
                    result.error(f"Capability mismatch for {capability_id}: {key}")
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot compare capability specification: {exc}")

    try:
        permissions = load_yaml(root / "specs/permissions.v1.yml")
        permission_ids = {item["permission"] for item in permissions.get("permissions", [])}
        for capability_id in ids:
            if capability_id not in permission_ids:
                result.error(f"Capability permission is not declared: {capability_id}")
        aliases = permissions.get("legacy_permission_aliases", {}) or {}
        if not isinstance(aliases, dict):
            result.error("legacy_permission_aliases must be an object")
        else:
            for source, target in aliases.items():
                if not CAPABILITY_RE.fullmatch(str(source)):
                    result.error(f"Invalid legacy permission alias source: {source}")
                if target not in permission_ids:
                    result.error(f"Legacy permission alias target is not declared: {target}")
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot validate permission catalogue: {exc}")

    try:
        openapi = load_yaml(root / manifest["interfaces"]["api"]["openapi"])
        api_operations = extract_openapi_operations(openapi)
        api_by_capability = {
            operation.get("x-capability-id"): operation
            for operation in api_operations
            if operation.get("x-capability-id")
        }
        for capability in capabilities:
            if "api" not in capability.get("exposure", []):
                continue
            capability_id = capability["capability_id"]
            operation = api_by_capability.get(capability_id)
            if not operation:
                result.error(f"API-exposed capability has no OpenAPI operation: {capability_id}")
                continue
            if operation.get("operationId") != capability["operation_id"]:
                result.error(f"OpenAPI operationId mismatch for {capability_id}")
            expected_mcp = capability.get("mcp_name")
            if expected_mcp and operation.get("x-mcp-name") != expected_mcp:
                result.error(f"OpenAPI x-mcp-name mismatch for {capability_id}")
        for capability_id in api_by_capability:
            if capability_id not in ids:
                result.error(f"OpenAPI exposes undeclared capability: {capability_id}")
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot validate OpenAPI capability mapping: {exc}")

    try:
        metadata_path = root / manifest["authentication"]["oauth"]["protected_resource_metadata"]
        metadata = load_json(metadata_path)
        if metadata.get("resource") != api_resource:
            result.error("OAuth protected-resource metadata must use interfaces.api.resource_id")
        supported_scopes = set(metadata.get("scopes_supported", []))
        required_scopes = {capability["oauth_scope"] for capability in capabilities if "api" in capability.get("exposure", []) or "mcp" in capability.get("exposure", [])}
        missing_scopes = required_scopes - supported_scopes
        if missing_scopes:
            result.error("OAuth protected-resource metadata lacks scopes: " + ", ".join(sorted(missing_scopes)))
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot validate OAuth protected-resource metadata: {exc}")

    if not any("capability" in error.lower() or "operation" in error.lower() or "oauth" in error.lower() for error in result.errors):
        result.ok("Capability, permission, OAuth scope, OpenAPI and MCP names are aligned")


def check_legacy_compatibility(root: Path, manifest: dict[str, Any], result: CheckResult) -> None:
    authentication = manifest.get("authentication", {})
    if authentication.get("authority") == "none" or authentication.get("compatibility_mode") == "not-applicable":
        result.ok("Authentication compatibility is not applicable to this repository profile")
        return
    legacy = authentication.get("legacy", {})
    if legacy.get("enabled") and legacy.get("forced_migration") is not False:
        result.error("Legacy compatibility requires authentication.legacy.forced_migration=false")
    if authentication.get("compatibility_mode") == "dual-run":
        expected_true = [
            "enabled",
            "preserve_existing_consumers",
            "preserve_active_sessions",
            "preserve_refresh_tokens",
            "preserve_token_claims",
            "preserve_endpoints_and_payloads",
            "rollback_without_data_loss",
        ]
        for key in expected_true:
            if legacy.get(key) is not True:
                result.error(f"Dual-run compatibility requires authentication.legacy.{key}=true")

    try:
        legacy_contract = load_yaml(root / authentication["legacy"]["contract"])
        actual = set(legacy_contract.get("paths", {}))
        if not actual:
            actual = {
                route.get("path")
                for route in legacy_contract.get("http", {}).get("routes", [])
                if isinstance(route, dict) and route.get("path")
            }
        missing = REQUIRED_LEGACY_ENDPOINTS - actual
        if missing:
            result.error(f"Frozen legacy contract lacks endpoints: {', '.join(sorted(missing))}")
        else:
            result.ok("Frozen Access Layer legacy endpoint surface is present")
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot validate frozen legacy contract: {exc}")

    pairs = [
        ("examples/access-layer/legacy-exchange.response.json", "schemas/legacy-access-layer-exchange.schema.json"),
        ("examples/access-layer/legacy-introspection.active.json", "schemas/legacy-access-layer-introspection.schema.json"),
        ("examples/access-layer/legacy-introspection.inactive.json", "schemas/legacy-access-layer-introspection.schema.json"),
    ]
    for instance, schema in pairs:
        validate_instance(root / instance, root / schema, root, result)


def check_examples(root: Path, result: CheckResult) -> None:
    pairs = [
        ("examples/oauth/access-token.claims.json", "schemas/oauth-access-token-claims.schema.json"),
        ("examples/oauth/oauth-protected-resource-metadata.json", "schemas/oauth-protected-resource-metadata.schema.json"),
        ("examples/auth/request-context.legacy.json", "schemas/request-context.schema.json"),
        ("examples/auth/request-context.oauth.json", "schemas/request-context.schema.json"),
        ("examples/telemetry/capability-completed.event.json", "schemas/events.schema.json"),
        ("examples/ai/ai-output-envelope.json", "schemas/ai-output-envelope.schema.json"),
        ("examples/ai/ai-output-approved.event.json", "schemas/ai-events.schema.json"),
        ("examples/api/error.response.json", "schemas/error.schema.json"),
    ]
    for instance, schema in pairs:
        validate_instance(root / instance, root / schema, root, result)

    for rel in [
        "examples/mcp/tools-list.request.json",
        "examples/mcp/tools-call.request.json",
    ]:
        try:
            obj = load_json(root / rel)
            meta = obj["params"]["_meta"]
            required = {
                "io.modelcontextprotocol/protocolVersion",
                "io.modelcontextprotocol/clientInfo",
                "io.modelcontextprotocol/clientCapabilities",
            }
            if not required.issubset(meta):
                result.error(f"MCP request lacks required per-request metadata: {rel}")
        except Exception as exc:  # noqa: BLE001
            result.error(f"Cannot validate MCP request example {rel}: {exc}")
    for rel in [
        "examples/mcp/tools-list.response.json",
        "examples/mcp/tools-call.response.json",
        "examples/mcp/tools-call.execution-error.json",
    ]:
        try:
            obj = load_json(root / rel)
            if not obj.get("result", {}).get("resultType"):
                result.error(f"MCP response lacks resultType: {rel}")
        except Exception as exc:  # noqa: BLE001
            result.error(f"Cannot validate MCP response example {rel}: {exc}")


def check_language_and_ui(root: Path, manifest: dict[str, Any], result: CheckResult) -> None:
    legacy_migration = manifest.get("project", {}).get("mode") == "legacy-migration"
    language = manifest.get("language", {})
    expected = {
        "ui_locale": "en-GB",
        "documentation_locale": "en",
        "api_locale": "en",
        "fallback_locale": "en-GB",
    }
    for key, value in expected.items():
        if language.get(key) != value:
            result.error(f"English-first contract requires language.{key}={value}")

    ui_applicable = manifest.get("ui", {}).get("applicable", True)
    if not ui_applicable:
        if manifest.get("interfaces", {}).get("web", {}).get("enabled"):
            result.error("ui.applicable=false is incompatible with an enabled web interface")
        result.ok("English-first baseline is intact; Garden UI is not applicable to this repository profile")
        return

    locale_path = root / "src/locales/en-GB.json"
    if not locale_path.is_file():
        if legacy_migration:
            result.warn("Legacy-migration exception: English locale catalogue is not wired in Step 1")
        else:
            result.error("English locale catalogue is missing: src/locales/en-GB.json")
    try:
        html = (root / "examples/ui/garden-reference.html").read_text(encoding="utf-8")
        if 'lang="en-GB"' not in html:
            result.error("Garden UI reference must declare html lang=en-GB")
    except FileNotFoundError:
        result.error("Garden UI reference is missing")

    try:
        tokens = load_json(root / manifest["ui"]["tokens"])
        values = tokens["colour"]
        actual = {
            "navy": values["brand"]["navy"]["$value"],
            "deepNavy": values["brand"]["deepNavy"]["$value"],
            "green": values["brand"]["green"]["$value"],
            "lightGreen": values["brand"]["lightGreen"]["$value"],
            "primary": values["text"]["primary"]["$value"],
            "secondary": values["text"]["secondary"]["$value"],
            "muted": values["text"]["muted"]["$value"],
            "subtle": values["surface"]["subtle"]["$value"],
        }
        for key, expected_value in SOURCE_GARDEN_COLOURS.items():
            if actual.get(key, "").upper() != expected_value.upper():
                result.error(f"Garden source token changed: {key} must remain {expected_value}")
        css = (root / "assets/brand/garden.css").read_text(encoding="utf-8").lower()
        if "white text on green" not in (root / "assets/brand/colors.md").read_text(encoding="utf-8").lower():
            result.warn("Colour guidance should explicitly prohibit white text on green")
        if "--garden-green" not in css or "--garden-deep-navy" not in css:
            result.error("Garden CSS variables are incomplete")
        if contrast_ratio(actual["deepNavy"], actual["green"]) < 4.5:
            result.error("Garden primary CTA text/background contrast is below WCAG AA")
        if contrast_ratio("#FFFFFF", actual["navy"]) < 4.5:
            result.error("Garden white-on-navy contrast is below WCAG AA")
        if contrast_ratio("#FFFFFF", actual["green"]) >= 4.5:
            result.warn("Review the source Garden rule that forbids white text on green")
    except Exception as exc:  # noqa: BLE001
        result.error(f"Cannot validate Garden tokens: {exc}")

    colour_literal = re.compile(r"#[0-9a-fA-F]{3,8}\b")
    allowed_roots = {
        root / "assets",
        root / "examples" / "ui",
        root / "docs",
        root / "specs",
        root / "schemas",
    }
    for path in list((root / "src").rglob("*")) + list((root / "platform").rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".css"}:
            continue
        if any(allowed == path or allowed in path.parents for allowed in allowed_roots):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if colour_literal.search(text):
            if legacy_migration:
                result.warn(f"Legacy-migration exception: existing raw colour literal remains in {display_path(path, root)}")
            else:
                result.error(f"Raw colour literal outside Garden assets: {display_path(path, root)}")

    if not any("English-first" in error or "Garden" in error or "colour" in error for error in result.errors):
        result.ok("English-first and Garden UI baseline are intact")


def check_ai(root: Path, manifest: dict[str, Any], result: CheckResult) -> None:
    ai = manifest.get("ai", {})
    system = load_yaml(root / ai["system_spec"])
    if ai.get("enabled") is False:
        if ai.get("profile") != "no_ai" or system.get("profile") != "no_ai":
            result.error("AI disabled state requires the no_ai profile")
    else:
        blockers = []
        if ai.get("profile") in {"high_risk_candidate", "prohibited"}:
            blockers.append(f"AI profile is {ai.get('profile')}")
        if system.get("assessment_status") in {"not_assessed", "unknown", None}:
            blockers.append("AI system assessment is incomplete")
        providers = load_yaml(root / ai["provider_registry"])
        for provider in providers.get("providers", []):
            if provider.get("status") != "approved":
                blockers.append(f"AI provider is not approved: {provider.get('provider_id')}")
        if blockers:
            for blocker in blockers:
                result.error(blocker)
    result.ok("AI governance files are present and the default AI state is safe")


def check_security_and_placeholders(
    root: Path,
    manifest: dict[str, Any],
    result: CheckResult,
    strict: bool,
) -> None:
    secret_patterns = [
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ]
    for path in iter_text_files(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in secret_patterns:
            if pattern.search(text):
                result.error(f"Possible secret/private key in {display_path(path, root)}")

    template_mode = bool(manifest.get("template_mode"))
    placeholder_patterns = [
        "TODO_PROJECT_SPECIFIC",
        "PROJECT_INPUT_REQUIRED",
        "PROJECT INPUT REQUIRED",
        "NOT_REVIEWED",
        "NOT_ASSESSED",
        "{{PROJECT_NAME}}",
        "{{SHORT_PROJECT_DESCRIPTION}}",
        ".pending.invalid",
    ]
    found: list[str] = []
    for path in iter_text_files(root):
        if path.name in {"platform_check.py", "bootstrap.py"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in placeholder_patterns:
            if marker in text:
                found.append(f"{display_path(path, root)} ({marker})")
                break
    if found:
        message = "Project-specific placeholders remain: " + ", ".join(sorted(found)[:20])
        if strict and not template_mode:
            result.error(message)
        else:
            result.warn(message)

    if template_mode:
        result.warn("project.platform.yaml is in template_mode; bootstrap before a real release")
    elif strict:
        project = manifest.get("project", {})
        unresolved_owners = [
            key for key in ("owner_team", "technical_owner", "product_owner")
            if str(project.get(key, "")).strip().lower() in {"", "unassigned", "unknown", "tbd"}
            or str(project.get(key, "")).strip().lower().startswith("unresolved")
        ]
        if unresolved_owners:
            result.error("Named project ownership is unresolved: " + ", ".join(unresolved_owners))
        license_text = (root / "LICENSE").read_text(encoding="utf-8", errors="ignore")
        if "Licence decision required" in license_text:
            result.error("Project licence decision is unresolved")

    if manifest.get("project", {}).get("mode") == "legacy-migration":
        compose_text = (root / "docker-compose.yaml").read_text(encoding="utf-8", errors="ignore")
        continuity_volumes_resolved = (
            "access_layer_postgres_data_v2:/var/lib/postgresql/data" in compose_text
            and "access_layer_jwt_secrets:/run/secrets" in compose_text
            and "\n  access_layer_postgres_data_v2:\n" in compose_text.replace("\r\n", "\n")
            and "\n  access_layer_jwt_secrets:\n" in compose_text.replace("\r\n", "\n")
        )
        if not continuity_volumes_resolved:
            message = "Continuity blocker: Compose logical PostgreSQL/JWT volumes differ from the evidence-backed declarations"
            if strict:
                result.error(message)
            else:
                result.warn(message)

    result.ok("Secret-pattern scan completed")


def run_checks(root: Path, strict: bool = False, registry_path: Path | None = None) -> CheckResult:
    result = CheckResult()
    check_required_files(root, result)
    check_parseability(root, result)
    manifest = check_manifest(root, result)
    if manifest:
        check_platform_baseline(manifest, result)
        check_deployment_contract(root, manifest, result, strict, registry_path)
        check_capability_contract(root, manifest, result)
        check_legacy_compatibility(root, manifest, result)
        check_examples(root, result)
        check_language_and_ui(root, manifest, result)
        check_ai(root, manifest, result)
        check_security_and_placeholders(root, manifest, result, strict)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate platform contracts in the current repository.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict", action="store_true", help="Enforce project-release placeholders and licence gates.")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Print machine-readable output.")
    parser.add_argument("--report", type=Path, help="Write the same machine-readable result to a file.")
    parser.add_argument(
        "--registry",
        type=Path,
        help="Path to the central Coolify deployment registry. Can also be set with PLATFORM_DEPLOYMENT_REGISTRY_PATH.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    registry_value = args.registry or (Path(os.environ["PLATFORM_DEPLOYMENT_REGISTRY_PATH"]) if os.environ.get("PLATFORM_DEPLOYMENT_REGISTRY_PATH") else None)
    result = run_checks(root, strict=args.strict, registry_path=registry_value)
    payload = {
        "success": result.success,
        "root": str(root),
        "errors": result.errors,
        "warnings": result.warnings,
        "passed": result.passed,
        "summary": {
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "passed": len(result.passed),
        },
    }

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.json_output:
        print(json.dumps(payload, indent=2))
    else:
        status = "PASS" if result.success else "FAIL"
        print(f"Platform check: {status}")
        for item in result.errors:
            print(f"ERROR: {item}")
        for item in result.warnings:
            print(f"WARN:  {item}")
        print(
            f"Summary: {len(result.errors)} error(s), "
            f"{len(result.warnings)} warning(s), {len(result.passed)} passed check(s)"
        )

    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
