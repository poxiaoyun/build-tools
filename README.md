# Build Tools

This repository contains a collection of build tools.

## Installation

```bash
go install xiaoshiai.cn/build-tools/build-tools/cmd/...
```

## chart-build-tool

This tool is used to build and package Helm charts. It is a wrapper around the `helm` command-line tool that simplifies the process of building and packaging charts.

Features:

- Generates i18n schema files for Helm charts from the `values.yaml` file.
- Get and Merge partial files defined in the `source.yaml` file
- Push charts to a remote chart museum or OCI registry.

Usage:

```bash
chart-build-tool generate ./charts/my-chart
chart-build-tool build ./charts/my-chart
chart-build-tool push ./charts/my-chart --username <username> --password <password> --url oci://registry.example.com/charts
```
