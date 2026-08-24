# Service-Level Objectives

## Required project decision

Replace the placeholders in `project.platform.yaml` with approved targets. Do not copy targets blindly between projects.

## Standard indicators

- availability of supported user/API capabilities;
- successful request ratio excluding valid user/policy rejections;
- p95 latency by capability class;
- queue wait and job completion time;
- dependency and AI-provider failure rate;
- telemetry delivery health, monitored separately from product availability.

## Error budget

Define:

- SLO window;
- allowed error budget;
- burn-rate alerts;
- release freeze/escalation rules;
- exclusions with owner approval;
- maintenance-window treatment.

Synthetic checks support external availability evidence but do not replace real user/capability indicators.
