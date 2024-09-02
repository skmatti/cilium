Google Contributing Guidelines
==============================

This doc contains best practices for submitting + maintaining internal Google-specific changes to Cilium.

Organize code to avoid unnecessary rebase conflicts:
- Compose control plane elements into Hive cells.
- Add the top-level cells to `daemon/cmd/google_cells.go`.
- Add options to `pkg/option/google_config.go`.
- Add packages to `pkg/gke`.
- Minimize the use of internal (unstable) APIs.
