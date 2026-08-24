# Platform Project Types

## Purpose

The template distinguishes deployable products from reusable code. The type is
recorded in `project.kind` and cannot be inferred from the repository name.

## `tool`

A product used directly by people or agents. Examples include Nancy, Petyr,
Goodman, Test Generator, UNGUESS Internal Network and Tool Observatory.

Default characteristics:

- independent Coolify resource;
- canonical HTTPS domain;
- Access Layer integration;
- application API and Agent Gateway readiness;
- product analytics and technical telemetry;
- Garden UI when a user interface exists.

## `platform_service`

A shared runtime capability used by several tools. Access Layer and Agent
Gateway are platform services. They are independently deployed on Coolify and
have stricter availability, security and compatibility requirements.

A platform service is not a shared code library. Consumers integrate through a
versioned network contract or an SDK.

## `infrastructure_stack`

An operational stack such as the central observability deployment. It is a
Coolify resource, often a private multi-container Compose stack. It may have no
public UI or public domain. Access is limited to private networking or
explicitly protected operational routes.

## `sdk_library`

A versioned package imported by projects during build or runtime. The UNGUESS
Platform SDK belongs to this category.

An SDK library has:

- no Coolify resource;
- no domain or container port;
- no database;
- no central runtime dependency;
- versioned releases consumed explicitly by each project.

Updating the SDK never updates deployed tools automatically. Each tool pins a
version, runs its compatibility suite and deploys independently.

## One project versus multiple containers

A project type describes ownership and deployment boundaries, not container
count. A single tool or infrastructure stack may contain web, API, worker,
database and scheduler containers in one Coolify resource.
