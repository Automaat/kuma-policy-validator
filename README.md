# Kuma Policy Validator

Static HTML app for validating Kuma service mesh policies. Client-side only — no build step required.

## Features

- YAML syntax validation with line numbers
- Kubernetes and Universal format detection
- Policy kind validation (16 known types)
- Spec structure validation (required fields, mutual exclusivity)
- TargetRef kind validation with per-kind field rules
- Deprecation warnings from upstream Kuma source
- Dark/light theme
- Example policies built-in
- Real-time validation (300ms debounce)

## Local Development

Open `index.html` in a browser. No build step needed.

## Deploy to Cloudflare Pages

1. Push to GitHub
2. Connect repo in Cloudflare Pages dashboard
3. Settings:
   - Build command: (leave empty)
   - Build output directory: `/`
4. Deploy

The `_headers` file configures security headers automatically.

## Validation Pipeline

1. **YAML Syntax** — parse with js-yaml
2. **Format Detection** — K8s (apiVersion+kind+metadata) vs Universal (type+name)
3. **Kind Validation** — check against known policy types
4. **Spec Structure** — required fields per policy (to/from/rules/default)
5. **TargetRef Validation** — per-kind field rules (Mesh, Dataplane, MeshService, etc.)
6. **Deprecation Checks** — warnings from Kuma `deprecated.go` files
7. **Results Display** — color-coded errors, warnings, info
