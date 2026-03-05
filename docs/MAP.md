# QuicFuscate Map

This document is the single combined **file map** and **architecture index** for the repository.
It is generated from all non-ignored files (respecting ignore rules) and is intended to supersede split architecture/file-map documents.

- Generated on: 2026-02-25 21:22:21 +0100
- Source set: non-ignored repository files
- Total files indexed: 637

## High-Level Architecture and Wiring

- Runtime core: Rust crate under `src/` with entrypoints in `src/main.rs` and `src/lib.rs`.
- Data path wiring: TUN/interface -> stealth -> FEC -> transport -> crypto -> network I/O.
- Control plane wiring: CLI + engine + admin surfaces + metrics/telemetry endpoints.
- UI wiring: `apps/desktop` (Tauri/React) and `apps/web-admin-ui` (React) integrate with server/client control surfaces.
- Automation wiring: scripts in `scripts/` orchestrate build/test/benchmark/audit tasks; runtime artifacts are written to ignored output paths.

## Critical Wiring Paths

1. Client CLI -> runtime init: `src/main.rs` -> `src/core.rs` -> `src/transport/connection.rs`
2. TLS handshake path: `src/qftls.rs` (`CombinedProvider`) -> rustls keys -> `src/transport/packet.rs`
3. Stealth shaping path: `src/stealth.rs` (`StealthManager`) -> `src/transport/config.rs` -> `src/transport/connection.rs`
4. FEC encode/decode path: `src/fec.rs` (`AdaptiveFec`) -> transport observer hooks -> packet egress/ingress
5. Probe mitigation path: `src/stealth.rs` detector -> `src/reality.rs` fallback proxy -> upstream targets
6. Engine embedding path: `src/engine/engine.rs` -> `src/implementations/{client,server}/` runtimes
7. Admin control plane path: `src/implementations/server/admin_http.rs` -> `qkey_registry.rs` -> live server policy enforcement
8. Desktop app path: `apps/desktop/src-tauri/src/main.rs` (invoke commands) -> engine/control runtime
9. Web-admin path: `apps/web-admin-ui/src/api.ts` -> admin HTTP endpoints -> server runtime state
10. Build publish path: `scripts/build/build-web-admin.sh` -> `assets/web-admin/` consumed by `--admin-web-root`

## ASCII Repository Tree (non-ignored files)

```text
.
|-- .cargo
|   |-- audit.toml
|   `-- config.toml
|-- .gitattributes
|-- .github
|   `-- workflows
|       |-- ci.yml
|       `-- clippy-matrix.yml
|-- .gitignore
|-- Cargo.lock
|-- Cargo.toml
|-- README.md
|-- apps
|   |-- desktop
|   |   |-- bun.lock
|   |   |-- index.html
|   |   |-- package.json
|   |   |-- playwright.config.ts
|   |   |-- public
|   |   |   |-- logo-hq.png
|   |   |   `-- logo.png
|   |   |-- src
|   |   |   |-- App.tsx
|   |   |   |-- components
|   |   |   |   |-- error-boundary.tsx
|   |   |   |   |-- icons
|   |   |   |   |   `-- q-mark.tsx
|   |   |   |   |-- layout
|   |   |   |   |   |-- sidebar.tsx
|   |   |   |   |   `-- titlebar.tsx
|   |   |   |   |-- settings
|   |   |   |   |   `-- setting-row.tsx
|   |   |   |   |-- tunnel
|   |   |   |   |   |-- add-tunnel-dialog.tsx
|   |   |   |   |   |-- edit-qkey-dialog.tsx
|   |   |   |   |   |-- tunnel-config-dialog.tsx
|   |   |   |   |   |-- tunnel-detail.tsx
|   |   |   |   |   `-- tunnel-list.tsx
|   |   |   |   `-- ui
|   |   |   |       |-- button.tsx
|   |   |   |       |-- confirm-dialog.tsx
|   |   |   |       |-- connect-button.tsx
|   |   |   |       |-- country-select.tsx
|   |   |   |       |-- dialog.tsx
|   |   |   |       |-- error-banner.tsx
|   |   |   |       |-- glass-card.tsx
|   |   |   |       |-- select.tsx
|   |   |   |       |-- skeleton.tsx
|   |   |   |       |-- switch.tsx
|   |   |   |       |-- toast.tsx
|   |   |   |       `-- tooltip.tsx
|   |   |   |-- content
|   |   |   |   `-- about-content.tsx
|   |   |   |-- data
|   |   |   |   `-- countries.ts
|   |   |   |-- hero.ts
|   |   |   |-- index.css
|   |   |   |-- lib
|   |   |   |   |-- clipboard.ts
|   |   |   |   |-- domain-fronting-policy.ts
|   |   |   |   |-- policy-display.ts
|   |   |   |   |-- stage-modal.ts
|   |   |   |   |-- tunnel-validators.ts
|   |   |   |   |-- updater.ts
|   |   |   |   |-- use-keyboard-shortcuts.ts
|   |   |   |   `-- utils.ts
|   |   |   |-- main.tsx
|   |   |   |-- stores
|   |   |   |   |-- atoms.ts
|   |   |   |   |-- index.ts
|   |   |   |   |-- toastAtom.ts
|   |   |   |   `-- types.ts
|   |   |   |-- views
|   |   |   |   |-- about-view.tsx
|   |   |   |   |-- logs-view.tsx
|   |   |   |   |-- settings-view.tsx
|   |   |   |   `-- tunnels-view.tsx
|   |   |   `-- vite-env.d.ts
|   |   |-- src-tauri
|   |   |   |-- Cargo.lock
|   |   |   |-- Cargo.toml
|   |   |   |-- build.rs
|   |   |   |-- gen
|   |   |   |   `-- schemas
|   |   |   |       |-- acl-manifests.json
|   |   |   |       |-- capabilities.json
|   |   |   |       |-- desktop-schema.json
|   |   |   |       `-- macOS-schema.json
|   |   |   |-- icons
|   |   |   |   |-- 128x128.png
|   |   |   |   |-- 128x128@2x.png
|   |   |   |   |-- 32x32.png
|   |   |   |   |-- 64x64.png
|   |   |   |   |-- Square107x107Logo.png
|   |   |   |   |-- Square142x142Logo.png
|   |   |   |   |-- Square150x150Logo.png
|   |   |   |   |-- Square284x284Logo.png
|   |   |   |   |-- Square30x30Logo.png
|   |   |   |   |-- Square310x310Logo.png
|   |   |   |   |-- Square44x44Logo.png
|   |   |   |   |-- Square71x71Logo.png
|   |   |   |   |-- Square89x89Logo.png
|   |   |   |   |-- StoreLogo.png
|   |   |   |   |-- icon.icns
|   |   |   |   |-- icon.ico
|   |   |   |   |-- icon.png
|   |   |   |   |-- tray_black.png
|   |   |   |   `-- tray_white.png
|   |   |   |-- src
|   |   |   |   |-- main.rs
|   |   |   |   |-- secrets.rs
|   |   |   |   `-- state_store.rs
|   |   |   `-- tauri.conf.json
|   |   |-- tsconfig.app.json
|   |   |-- tsconfig.json
|   |   |-- tsconfig.node.json
|   |   |-- vite.config.ts
|   |   `-- vitest.config.ts
|   `-- web-admin-ui
|       |-- bun.lock
|       |-- index.html
|       |-- package.json
|       |-- playwright.config.ts
|       |-- public
|       |   |-- apple-touch-icon.png
|       |   |-- favicon-16x16.png
|       |   |-- favicon-32x32.png
|       |   |-- favicon-mono-64.png
|       |   `-- favicon.ico
|       |-- src
|       |   |-- App.tsx
|       |   |-- api.ts
|       |   |-- components
|       |   |   |-- error-boundary.tsx
|       |   |   |-- layout
|       |   |   |   `-- sidebar.tsx
|       |   |   |-- login-modal.tsx
|       |   |   |-- settings
|       |   |   |   `-- setting-row.tsx
|       |   |   `-- ui
|       |   |       |-- app-dialog.tsx
|       |   |       |-- confirm-dialog.tsx
|       |   |       |-- controls.tsx
|       |   |       |-- glass-card.tsx
|       |   |       |-- skeleton.tsx
|       |   |       |-- sparkline.tsx
|       |   |       `-- toast.tsx
|       |   |-- hero.ts
|       |   |-- index.css
|       |   |-- lib
|       |   |   |-- cn.ts
|       |   |   |-- ip-access-control.ts
|       |   |   |-- notify-error.ts
|       |   |   |-- runtime-flags.ts
|       |   |   |-- unsaved-guard.ts
|       |   |   |-- use-confirm-dialog.ts
|       |   |   |-- use-notify.ts
|       |   |   |-- use-stage-modal-portal.ts
|       |   |   `-- use-top-status-anchor.ts
|       |   |-- main.tsx
|       |   |-- stores
|       |   |   |-- atoms.ts
|       |   |   |-- confirmDialogAtom.ts
|       |   |   |-- toastAtom.ts
|       |   |   `-- types.ts
|       |   |-- views
|       |   |   |-- about.tsx
|       |   |   |-- configuration.tsx
|       |   |   |-- dashboard.tsx
|       |   |   |-- logs.tsx
|       |   |   `-- settings-admin.tsx
|       |   `-- vite-env.d.ts
|       |-- tsconfig.app.json
|       |-- tsconfig.json
|       |-- tsconfig.node.json
|       `-- vite.config.ts
|-- assets
|   |-- logo
|   |   |-- QuicFuscate.png
|   |   |-- QuicFuscate_clean.png
|   |   `-- QuicFuscate_hf.png
|   `-- web-admin
|       |-- assets
|       |   |-- index-C3FauvWy.css
|       |   |-- index-CkMDWMgP.js
|       |   |-- react-Bpp4R8ks.js
|       |   |-- state-iiSFyfB0.js
|       |   |-- ui-pwAOwm1L.js
|       |   `-- vendor-vMomohIa.js
|       `-- index.html
|-- build.rs
|-- config
|   |-- local
|   |   `-- .gitkeep
|   |-- quicfuscate.toml
|   |-- server-linux.default.logging.json
|   |-- server-linux.default.qkeys.json
|   `-- server-linux.default.toml
|-- deny.toml
|-- docs
|   |-- CONTRIBUTING.md
|   |-- DOCUMENTATION.md
|   |-- LICENSE
|   `-- MAP.md
|-- examples
|   |-- brain_probe.rs
|   |-- compress_bench.rs
|   |-- engine_basic.rs
|   |-- fec_sim.rs
|   |-- microbench.rs
|   |-- rng_bench.rs
|   |-- shuffle_bench.rs
|   `-- tun_factory_example.rs
|-- rust-toolchain.toml
|-- rustfmt.toml
|-- scripts
|   |-- benchmarks
|   |   |-- micro
|   |   |   |-- micro-aes-block.sh
|   |   |   |-- micro-aes-gcm.sh
|   |   |   |-- micro-chacha-x4.sh
|   |   |   |-- micro-crypto-all.sh
|   |   |   |-- micro-ghash.sh
|   |   |   `-- micro-udpfast-throughput.sh
|   |   |-- smoke
|   |   |   `-- smoke-fec-quick.sh
|   |   |-- suites
|   |   |   |-- bench-compression.sh
|   |   |   |-- bench-crypto.sh
|   |   |   |-- bench-fec-simulation.sh
|   |   |   |-- bench-fec.sh
|   |   |   |-- bench-nightly.sh
|   |   |   |-- bench-optimization.sh
|   |   |   |-- bench-orchestrator.sh
|   |   |   |-- bench-profile-transport-fastpaths.sh
|   |   |   |-- bench-qpack-encode.sh
|   |   |   |-- bench-stealth-brain.sh
|   |   |   |-- bench-stealth.sh
|   |   |   `-- bench-transport.sh
|   |   `-- wrappers
|   |       |-- wrap-crypto.sh
|   |       `-- wrap-fec.sh
|   |-- build
|   |   |-- build-server-bundle.sh
|   |   `-- build-web-admin.sh
|   |-- install
|   |   |-- install-server-linux.sh
|   |   `-- quicfuscate-server.service
|   |-- lib
|   |   `-- lib-common.sh
|   |-- tests
|   |   |-- analysis
|   |   |   |-- analysis-coverage-summary.sh
|   |   |   |-- analysis-dead-code-report.sh
|   |   |   |-- analysis-scripts-quality.sh
|   |   |   `-- analysis-suite-matrix.sh
|   |   |-- audits
|   |   |   |-- allowlists
|   |   |   |   `-- critical-allowlist.txt
|   |   |   |-- audit-all-comprehensive.sh
|   |   |   `-- audit-readiness-gates.sh
|   |   |-- build
|   |   |   |-- build-check.sh
|   |   |   |-- build-clippy-matrix.sh
|   |   |   |-- build-debug.sh
|   |   |   |-- build-dev-tools.sh
|   |   |   |-- build-env-doctor.sh
|   |   |   `-- build-release.sh
|   |   |-- fast
|   |   |   |-- test-fast-crypto.sh
|   |   |   `-- test-fast-fec.sh
|   |   |-- frontend
|   |   |   |-- desktop
|   |   |   |   |-- e2e
|   |   |   |   |   |-- app.pw.ts
|   |   |   |   |   |-- dialog-centering.pw.ts
|   |   |   |   |   |-- full-ui.pw.ts
|   |   |   |   |   `-- smoke-ui.pw.ts
|   |   |   |   `-- unit
|   |   |   |       |-- setup.ts
|   |   |   |       `-- src
|   |   |   |           |-- app-persistence.test.tsx
|   |   |   |           |-- components
|   |   |   |           |   |-- error-boundary.test.tsx
|   |   |   |           |   |-- tunnel
|   |   |   |           |   |   |-- add-tunnel-dialog.test.tsx
|   |   |   |           |   |   |-- edit-qkey-dialog.test.tsx
|   |   |   |           |   |   |-- tunnel-detail.test.tsx
|   |   |   |           |   |   `-- tunnel-list.test.tsx
|   |   |   |           |   `-- ui
|   |   |   |           |       `-- toast.test.tsx
|   |   |   |           |-- lib
|   |   |   |           |   |-- domain-fronting-policy.test.ts
|   |   |   |           |   |-- policy-display.test.ts
|   |   |   |           |   |-- tunnel-validators.test.ts
|   |   |   |           |   `-- updater.test.ts
|   |   |   |           `-- views
|   |   |   |               `-- logs-view.test.tsx
|   |   |   `-- web-admin
|   |   |       |-- e2e
|   |   |       |   |-- app.pw.ts
|   |   |       |   |-- button-semantics.pw.ts
|   |   |       |   |-- dialog-centering.pw.ts
|   |   |       |   |-- overlay-notifications.pw.ts
|   |   |       |   `-- smoke-ui.pw.ts
|   |   |       `-- unit
|   |   |           |-- api-error-parsing.test.ts
|   |   |           `-- ip-access-control.test.ts
|   |   |-- fuzz
|   |   |   |-- .gitignore
|   |   |   |-- Cargo.lock
|   |   |   |-- Cargo.toml
|   |   |   |-- fuzz_targets
|   |   |   |   |-- connection_handling.rs
|   |   |   |   |-- crypto_operations.rs
|   |   |   |   |-- fec_encoding.rs
|   |   |   |   |-- frame_decoding.rs
|   |   |   |   |-- packet_parsing.rs
|   |   |   |   `-- varint_parsing.rs
|   |   |   `-- seeds
|   |   |       |-- connection_handling
|   |   |       |   |-- 00181c8f09e9ed6d6e955382a4222db43a2ef89b
|   |   |       |   |-- 0018fa69230e95196f8306180aceea620168ebea
|   |   |       |   |-- 01bfc82140a6f92f99b48860e8daeece553072aa
|   |   |       |   |-- 038c6ada9a48d170a2e68c1eb415081f85caa257
|   |   |       |   |-- 03f80907cf21fb1a702ffb5a30d3a47f4aaed5b1
|   |   |       |   |-- 052f22a88d99c17a575689a3499d4e919fa1ce88
|   |   |       |   |-- 05a79f06cf3f67f726dae68d18a2290f6c9a50c9
|   |   |       |   |-- 05abecacbf48accfb320ce149fba236abe8a6ca6
|   |   |       |   |-- 067adef0436a189baadede0755e1aeac8b678afc
|   |   |       |   |-- 076c5c6ba92847f3849b66bd532b30b2cb322314
|   |   |       |   |-- 07c342be6e560e7f43842e2e21b774e61d85f047
|   |   |       |   |-- 0af8e576e5706f0dbe0f73a84975f3e3dba699f4
|   |   |       |   |-- 0bd213d89bcdc192fee315924e4b18e0ca22ad0d
|   |   |       |   |-- 0d27752d18d214636fa1acfd75bf20d337a9ca32
|   |   |       |   |-- 0df797e287f58ae34ede1cd988576310c768cde0
|   |   |       |   |-- 13436d9c7945ec65e056fb387f47800358ce29f8
|   |   |       |   |-- 157a535e1ddccd0dd1cbd2c06b1f67c88e5dee0c
|   |   |       |   |-- 16886fc84f814d3569b91d95fc5d9cdaea7afda1
|   |   |       |   |-- 16b9baae68a824522a8727a996dbaa31eeb8cdc3
|   |   |       |   |-- 1a7325ca5c0edd5e178d5e1afb4377e54709bad5
|   |   |       |   |-- 1c0c8ce2c281dca51c925ffee34c5a1ad08ed2f4
|   |   |       |   |-- 1d26e249695224a2e2140803063cd9e450b856a4
|   |   |       |   |-- 1dcf0ec2351966fc2b0babee787f535a2683f130
|   |   |       |   |-- 1e095aa6f0fc1311e4c6bb6ef83520f5a9be3eec
|   |   |       |   |-- 20df839c86e6998ba97acd5db1aa591cd33785ff
|   |   |       |   |-- 212a2ed37275180a5b4071d34d79fca3d77e5177
|   |   |       |   |-- 21fe51523b5d7b956c60ad11593118841487fae7
|   |   |       |   |-- 22803c1d358fec0a695260f8836a58c107436913
|   |   |       |   |-- 28426275ddbbe7b7045cb2bf41ffd3e204d4067f
|   |   |       |   |-- 291ea5a4803954e31ae31947affda4547a5e2669
|   |   |       |   |-- 2b4c4b98cc6e7e6acb5b3db5001a4124109b4a9c
|   |   |       |   `-- 2c497c9b32d1b30a264b1970772a6bcc47fe6481
|   |   |       |-- crypto_operations
|   |   |       |   |-- 02c0746beb255afdeb7107a40304df7a09498979
|   |   |       |   |-- 02e803875af4312c41b43bfaace91139da54e33e
|   |   |       |   |-- 06c0d4765d578e49a4e584b8a8ab87ed001316c6
|   |   |       |   |-- 07ee5dd32d9b97d4527a80625596247ead1cb0f8
|   |   |       |   |-- 0b23b2da48329c60b993569de663f235371de5c2
|   |   |       |   |-- 0b374fd4121acd7f4d3453faf00b3fb87aef9437
|   |   |       |   |-- 1142e71a572cd29e7cd2059935fe27dac1a68eeb
|   |   |       |   |-- 17fd7d1fda0a1d83ec185f15363802ed04958475
|   |   |       |   |-- 191017b30c884b530841400ff40081c1f0011a11
|   |   |       |   |-- 1b15fa82d8f7f6a6a0215c93dc4337820e8d1a54
|   |   |       |   |-- 1e5c2f367f02e47a8c160cda1cd9d91decbac441
|   |   |       |   |-- 24fa170fe3619ce8c8da73729624f38ab76316a3
|   |   |       |   |-- 262b6094ab267a9ab2b8167683b298e56261e3a8
|   |   |       |   |-- 2fba2c6ed132680e1670a09291d8d4dd80c35915
|   |   |       |   |-- 354363c1d7c024949ac51fc0f6192f98048b09cc
|   |   |       |   |-- 37c79e40d6b6cfc7c57d63a4e073250bd3c96217
|   |   |       |   |-- 37e99a2e090e415f608f6112970ee53cdc0a3611
|   |   |       |   |-- 3909111f5c1f2a452155c4bb3ebb736a5b7c812d
|   |   |       |   |-- 3e42259f8a482174ecfed2cc2e5cc7fb0e942a8d
|   |   |       |   |-- 3f5b860494473914ed8e61fafa93341dc81684a7
|   |   |       |   |-- 4009c409b941de1781afdae04ab4ce41a06e56e8
|   |   |       |   |-- 4570d5646da158d4167a89cf024a6bc857224b61
|   |   |       |   |-- 4e0451b0354ccc1276025c8c0d8c8bc5e4af5a75
|   |   |       |   |-- 5076d243614bb17c292158792c3dc7c00fa32d8b
|   |   |       |   |-- 523a9b59c726a8681a5c6e58e4b89464f216de15
|   |   |       |   |-- 534ca4b921297b9ac9327d3ff6df5fc436874bfe
|   |   |       |   |-- 54e537747127d59d288bbfc37a25fa441ddb11d6
|   |   |       |   |-- 57759189c04fa21be53502b7b0ea88ff9e992daa
|   |   |       |   |-- 5cd320e8fb9e2472cf671ba21c75ae15002e9b66
|   |   |       |   |-- 5e65f274cf5eaeddf38a9ee6712df8ebcff5abca
|   |   |       |   |-- 5fb34ed7eb1655337dc24b805e0cad0c77e624d2
|   |   |       |   `-- 69f7257aee42a68c79fea7cec0675863f76f698b
|   |   |       |-- fec_encoding
|   |   |       |   |-- 0116e7f493f127f9e7ce8db64f91e3fc8daccfd1
|   |   |       |   |-- 01528362184993443a4a97dbd2ae1232d6fdcd3b
|   |   |       |   |-- 02564a8aeae9abae34a6a4366a9f81064ca33c91
|   |   |       |   |-- 033c828fa2bdc76406185c9ae327c772d9d661de
|   |   |       |   |-- 059637db7329633ae1f338261b0beddf63a40ca8
|   |   |       |   |-- 0debae8a77de2276a3867d718441037c42c9fe82
|   |   |       |   |-- 111d4222dd88ce6a4985c5536da5c24179a31020
|   |   |       |   |-- 1548aef06ddde540c88cf3665c5f8e0e69652c8f
|   |   |       |   |-- 1b95811261fae4d1b387cf75d77d1e22af741f0d
|   |   |       |   |-- 1d91ec7ba28a784f6316083a2b81518e3b163a22
|   |   |       |   |-- 1e1640ab325e1e8c5f1200b1ef17924c6bac6585
|   |   |       |   |-- 25629f6f6212cad27554336c9d26c3c521a983ea
|   |   |       |   |-- 287d08e478d4b67210252d48c738b5e1d25a6bf6
|   |   |       |   |-- 289fd1f8a68036b7fe3481fdea8b61464d977c0c
|   |   |       |   |-- 2a00a752543206b0236e1457490971e7148f85e5
|   |   |       |   |-- 2ae8eef4c7d8055cb4aa31a3a1ce2867ca47762d
|   |   |       |   |-- 36bc58a23e413b5206699f31c6c1d7b59efc675d
|   |   |       |   |-- 3b3bc38eff449e6d77dd3a30f5ab4d2e46de126f
|   |   |       |   |-- 3bf0c68d072c465b52dde75a400cf8c469031c55
|   |   |       |   |-- 3d1f84900db936de44d85b1aa7a873027de300db
|   |   |       |   |-- 44ed10a0bcc7d9b9a63223bb338ef816c5eed358
|   |   |       |   |-- 456f6adc432e43597e697e8891edf7cdbe2b0680
|   |   |       |   |-- 48dad12865d1eb8b98d26723f2abda2f0a6d2409
|   |   |       |   |-- 4ea5daab90868a89db7cd54148b50110d02d8822
|   |   |       |   |-- 508f2618850ef8db85bd6391dd8cb355cc4dac9d
|   |   |       |   |-- 51387f06a53d495de6f4849c4a419b9e1e043f3c
|   |   |       |   |-- 5173707377db403e276033bbeb82723c80e96604
|   |   |       |   |-- 5350a5f874b84d9d0bf63baf41489a1bba9b36e5
|   |   |       |   |-- 58cfee47b1d6109189b0af8eff6e29c66a5bf474
|   |   |       |   |-- 5bab61eb53176449e25c2c82f172b82cb13ffb9d
|   |   |       |   |-- 5cd20a025743284f4446c9d248c81e62100a49ff
|   |   |       |   `-- 5df6320ce19f25463af7f27fe0040cc6f6206699
|   |   |       |-- frame_decoding
|   |   |       |   |-- 000613534890ba01a4c8b470cef1079026ab1f22
|   |   |       |   |-- 0056870b6150cef5e682c67f2eba165bee004dc2
|   |   |       |   |-- 00786b51c71d63718e62c5a546813fa4fc821ff1
|   |   |       |   |-- 00bb379b325a0a064a52a8c91acf2bc34002ec34
|   |   |       |   |-- 00cba95bec8dffff608ed979aac0c141a1dcf6eb
|   |   |       |   |-- 010e2a3c620315d0477f89f8da27bcf5d78319d3
|   |   |       |   |-- 01474b9fe6087f2cdb21800238149c16b22dc7aa
|   |   |       |   |-- 0157d3a43c9aa5f46758596486b1424aaf6c8152
|   |   |       |   |-- 015e22f27e3fe10c34ceb2f25b1b8795f0ec3cc3
|   |   |       |   |-- 016f5dbd31793749236514d88c09b161bf8cafcd
|   |   |       |   |-- 01778907d5a65d615b323bb18483274e11c36211
|   |   |       |   |-- 0183197f1635638110fc8f5f09018e1a49d7cd11
|   |   |       |   |-- 018858e915ce0cb3ec4e93565b975e05a80ff211
|   |   |       |   |-- 01956db57bb09b40ba7c1dc469856bb3d16fe3c1
|   |   |       |   |-- 01a8f64bc22d2f1e03f3f638cd12380147c10f12
|   |   |       |   |-- 01aa5b1c2ab9554f3049c5d7aaa7275acfa1d6bd
|   |   |       |   |-- 01b9dde983a0fb11953117ffe055ca64cc50b138
|   |   |       |   |-- 01cbceddb381b323308270ece98145090d560620
|   |   |       |   |-- 0205743549127ce3a89167855cb0d7fbf4100cf5
|   |   |       |   |-- 0224d54327237232e2b11989504b662ed22ae5cb
|   |   |       |   |-- 029a370483d23e14da6339fdb09d54a78c716e2c
|   |   |       |   |-- 032c3b683a0c7b86f7f79374c9ee00b4e8a9a427
|   |   |       |   |-- 0366f5e0aa127dc20c7af593d55cd027dc7cf199
|   |   |       |   |-- 03b5e5bde94e6870927c76060783a7c9b85a0f16
|   |   |       |   |-- 03c3e3c047b0d6761cd1d84bfe432a30ca46448f
|   |   |       |   |-- 03ed7eb9e44600fb678d0d5a984c761ec7054cd1
|   |   |       |   |-- 0460d28c8195e15ea2f254e181b25820f7dbf776
|   |   |       |   |-- 047cd9ad8c0372f3d0f8d01687934b7a07c65e9c
|   |   |       |   |-- 04857d52efdeacd606758bd37d753a2b4b196a54
|   |   |       |   |-- 049e5ec2ba5e3514eefbbb4f5e3629930a343623
|   |   |       |   |-- 04cc9db067776131b2c1b0acd355da67c5fddbb1
|   |   |       |   `-- 04e8ef819043e1089021187c3af9707e34e10a4a
|   |   |       |-- packet_parsing
|   |   |       |   |-- 0313d05d7753b14738418bf28fbec52b3ace1f90
|   |   |       |   |-- 0a80baa1797615faddb0ccfaa6d46382a6b3e0e2
|   |   |       |   |-- 126fe40d9e64df223c05078f44bf57cb794dd3e7
|   |   |       |   |-- 1489f923c4dca729178b3e3233458550d8dddf29
|   |   |       |   |-- 151dad05c0e7ab256391b6722220bf08362e082b
|   |   |       |   |-- 15f9be4097be2e8e3e2eccbe99485f136f1e10dc
|   |   |       |   |-- 208de8f4361122a16456849117e97a501807150d
|   |   |       |   |-- 23833462f55515a900e016db2eb943fb474c19f6
|   |   |       |   |-- 241cbd6dfb6e53c43c73b62f9384359091dcbf56
|   |   |       |   |-- 2453dc5f19dacb89ff0e150fa7f930f305887bee
|   |   |       |   |-- 24a724a038383f08aa54a340d75795fa0d483aed
|   |   |       |   |-- 32dd31390c524bc3544e17f28b60a900afbbc3b4
|   |   |       |   |-- 3562bdbc33bbba09e984b49cbd87fbd820003f65
|   |   |       |   |-- 39334bdea06e35784caecebdb20934300c176136
|   |   |       |   |-- 39f8dea6d3288521612ab61791183e9bebcdd41b
|   |   |       |   |-- 3eb416223e9e69e6bb8ee19793911ad1ad2027d8
|   |   |       |   |-- 449a14b52ddac6234f42f0a57afeaebb91e16f8a
|   |   |       |   |-- 47403bb203a33969c2560ad261cb1b0b4fc50968
|   |   |       |   |-- 4e44060b715fd5b8a7bc5d82b173090d807d3da0
|   |   |       |   |-- 58672d56c93c14738f584f7d9c9a76902b369b04
|   |   |       |   |-- 5ba93c9db0cff93f52b521d7420e43f6eda2784f
|   |   |       |   |-- 5c2dd944dde9e08881bef0894fe7b22a5c9c4b06
|   |   |       |   |-- 5d96541bcb496e4a4d2fa81d85dbdfc3a402f0b5
|   |   |       |   |-- 5f684cd9eac6ffc0b7f64f67b42464f58ae12605
|   |   |       |   |-- 67ec1e60ba0c35a0dc52fe32a5f33d1c27775f54
|   |   |       |   |-- 6e14a407faae939957b80e641a836735bbdcad5a
|   |   |       |   |-- 7a33b4e863a0dfa8a1acabca36a06bb11c965f81
|   |   |       |   |-- 7c7cf422c7059d24803cbd012a96367f09c57f1a
|   |   |       |   |-- 85e53271e14006f0265921d02d4d736cdc580b0b
|   |   |       |   |-- 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
|   |   |       |   |-- 89b4ad89e92f7eafdb0649196296456dad725af4
|   |   |       |   `-- 8a61cfed63fd509b2d0f37c527880f430d500b36
|   |   |       `-- varint_parsing
|   |   |           |-- 061e8d32dc891eb8ce46ee617868573f3f0c270d
|   |   |           |-- 0db136ec1f832e3e933992283cb5d00125619bc4
|   |   |           |-- 124ae8c043cb7bd0b3d85699057287d7cc844ddb
|   |   |           |-- 12bdd00fd4038756cbcf8ecdad1b0cd862603cd8
|   |   |           |-- 13cba177bcfad90e7b3de70616b2e54ba4bb107f
|   |   |           |-- 18505413ec72266f54643a2a0ab98b8c40ab776c
|   |   |           |-- 1e5c2f367f02e47a8c160cda1cd9d91decbac441
|   |   |           |-- 23eb4d3f4155395a74e9d534f97ff4c1908f5aac
|   |   |           |-- 241cbd6dfb6e53c43c73b62f9384359091dcbf56
|   |   |           |-- 2a378788524f29755976422b2f589d594b18afa5
|   |   |           |-- 395df8f7c51f007019cb30201c49e884b46b92fa
|   |   |           |-- 3a710d2a84f856bc4e1c0bbb93ca517893c48691
|   |   |           |-- 48dad12865d1eb8b98d26723f2abda2f0a6d2409
|   |   |           |-- 4eaad1263f84e48f55f7d8cd2e87aa023ad6b95f
|   |   |           |-- 6073b833872b4cf58703f8ebe941bea4f62dadde
|   |   |           |-- 78bc12957c0a9e83eade9a90526e09b1b6b8595c
|   |   |           |-- 85e53271e14006f0265921d02d4d736cdc580b0b
|   |   |           |-- 86c983a0d00e7241192be92278463179b452d557
|   |   |           |-- 9a78211436f6d425ec38f5c4e02270801f3524f8
|   |   |           |-- ac91f006814ad58cfc048542366a9094945a94e0
|   |   |           |-- adad2ca7ab313add6e955f704719e03d5229e4d0
|   |   |           |-- adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
|   |   |           |-- b412426197e1365c6c5baae2a5ca6a02bb64d9f1
|   |   |           |-- bbbeb1952bdd58e643ca41b1854273c6bdafd756
|   |   |           |-- c2204edbfb1b72c9e996a5e6464f6ab0198c494f
|   |   |           |-- c4488af0c158e8c2832cb927cfb3ce534104cd1e
|   |   |           |-- c4595d8f743731cbc1ca0bb34be79a40d771ddf0
|   |   |           |-- c4d9381c061e9f4bf5e9af7162fab675299878ff
|   |   |           |-- c91f7e5ab7d362eadb802b8c59312805acc421c9
|   |   |           |-- d31db1f95b92a2970c35a583f6828724174e474a
|   |   |           |-- d6aba3f6449ae079b1a474b9f64264cf56fe6d26
|   |   |           `-- ddab14af72bfab923ea8600bad122ffa4fd98c0b
|   |   |-- lib
|   |   |   `-- lib-common.sh
|   |   |-- rust
|   |   |   |-- integration
|   |   |   |   |-- engine_control_plane.rs
|   |   |   |   |-- interface_capabilities.rs
|   |   |   |   |-- masque_runtime_integration.rs
|   |   |   |   |-- orchestrator_runtime_activation.rs
|   |   |   |   |-- qkey_auth_integration.rs
|   |   |   |   `-- stealth_mode_matrix.rs
|   |   |   |-- rt-ack-merge-parity.rs
|   |   |   |-- rt-admin-http-contract.rs
|   |   |   |-- rt-argsort-parity.rs
|   |   |   |-- rt-base64-decode-parity.rs
|   |   |   |-- rt-baseline-oracles.rs
|   |   |   |-- rt-bitmap-range-parity.rs
|   |   |   |-- rt-bitstream-parity.rs
|   |   |   |-- rt-brain-activation-parity.rs
|   |   |   |-- rt-brain-histogram.rs
|   |   |   |-- rt-chacha-x16-parity.rs
|   |   |   |-- rt-chacha-x4-parity.rs
|   |   |   |-- rt-cli-help.rs
|   |   |   |-- rt-compress-preprocessor.rs
|   |   |   |-- rt-core-connection-basics.rs
|   |   |   |-- rt-ecn-popcount.rs
|   |   |   |-- rt-fake-hmac.rs
|   |   |   |-- rt-ghash-sse-parity.rs
|   |   |   |-- rt-harness-cli.rs
|   |   |   |-- rt-harness-udpfast.rs
|   |   |   |-- rt-header-validate-parity.rs
|   |   |   |-- rt-interface.rs
|   |   |   |-- rt-io-hotpath-kernel-integration.rs
|   |   |   |-- rt-iter-reduction-telemetry.rs
|   |   |   |-- rt-iter-reductions.rs
|   |   |   |-- rt-moving-average-parity.rs
|   |   |   |-- rt-packet-number-parity.rs
|   |   |   |-- rt-pnspace-ack-policy.rs
|   |   |   |-- rt-probe-detection.rs
|   |   |   |-- rt-profile-aegis-selection.rs
|   |   |   |-- rt-profile-fuzz-parity.rs
|   |   |   |-- rt-profile-overrides.rs
|   |   |   |-- rt-property-suite.rs
|   |   |   |-- rt-qftls-profiles.rs
|   |   |   |-- rt-random-aes-ctr.rs
|   |   |   |-- rt-reality-targets.rs
|   |   |   |-- rt-ring-buffer-parity.rs
|   |   |   |-- rt-security-suite.rs
|   |   |   |-- rt-shuffle-parity.rs
|   |   |   |-- rt-simd-selfcheck.rs
|   |   |   |-- rt-stealth-ascii-count.rs
|   |   |   |-- rt-stealth-config-toml.rs
|   |   |   |-- rt-stealth-persona-headers.rs
|   |   |   |-- rt-telemetry-counters.rs
|   |   |   |-- rt-telemetry-http.rs
|   |   |   |-- rt-tls-cover-cipher.rs
|   |   |   |-- rt-transport-batch-processor.rs
|   |   |   |-- rt-transport-config.rs
|   |   |   |-- rt-transport-connection.rs
|   |   |   |-- rt-transport-frames-roundtrip.rs
|   |   |   |-- rt-transport-packet-headers.rs
|   |   |   |-- rt-transport-recovery.rs
|   |   |   |-- rt-transport-udpfast.rs
|   |   |   |-- rt-transport-uring.rs
|   |   |   |-- rt-transport-xdp.rs
|   |   |   |-- rt-transpose-parity.rs
|   |   |   |-- rt-udp-batch-send.rs
|   |   |   |-- rt-varint-roundtrip.rs
|   |   |   |-- rt-xor-obfuscator-parity.rs
|   |   |   |-- rt-xor-parity.rs
|   |   |   `-- rt-xor-sse2-parity.rs
|   |   |-- smoke
|   |   |   |-- smoke-avx10.sh
|   |   |   |-- smoke-sve2.sh
|   |   |   `-- smoke-ui-frontends.sh
|   |   |-- suites
|   |   |   |-- test-core.sh
|   |   |   |-- test-crypto.sh
|   |   |   |-- test-desktop-webadmin-rust-integration.sh
|   |   |   |-- test-e2e-admin-web.sh
|   |   |   |-- test-e2e-integration.sh
|   |   |   |-- test-e2e.sh
|   |   |   |-- test-fec-e2e-loss.sh
|   |   |   |-- test-fec-simulation.sh
|   |   |   |-- test-fec.sh
|   |   |   |-- test-optimization.sh
|   |   |   |-- test-performance-regression.sh
|   |   |   |-- test-probe-detection.sh
|   |   |   |-- test-profile-fuzz-parity.sh
|   |   |   |-- test-profile-overrides.sh
|   |   |   |-- test-security-fuzzing.sh
|   |   |   |-- test-stealth-brain.sh
|   |   |   |-- test-stealth.sh
|   |   |   `-- test-transport.sh
|   |   `-- utils
|   |       |-- util-e2e-decode-all-profiles.sh
|   |       |-- util-e2e-verify-all.sh
|   |       |-- util-e2e-verify-current.sh
|   |       |-- util-fuzz-seed-curate.sh
|   |       |-- util-run-full-suite.sh
|   |       |-- util-tls-diff-profiles.sh
|   |       |-- util-tls-export-active-profile.sh
|   |       |-- util-tls-generate-sha256-sidecars.sh
|   |       |-- util-tls-list-profiles.sh
|   |       |-- util-tls-profile-head.sh
|   |       `-- util-tls-show-active-env.sh
|   `-- utils
|       |-- util-analyze-codebase.sh
|       |-- util-check-quality.sh
|       |-- util-cleanup-workspace.sh
|       |-- util-dev-uis-start.sh
|       |-- util-dev-uis-stop.sh
|       |-- util-release-source-package.sh
|       |-- util-run-local-ui.sh
|       `-- util-stop-local-ui.sh
`-- src
    |-- accelerate.rs
    |-- bin
    |   |-- harness.rs
    |   |-- qf-e2e-client.rs
    |   |-- qf-e2e-desktop.rs
    |   `-- quicfuscate-ctl.rs
    |-- brain.rs
    |-- compress.rs
    |-- core.rs
    |-- crypto.rs
    |-- engine
    |   |-- config.rs
    |   |-- engine.rs
    |   |-- mod.rs
    |   `-- qkey.rs
    |-- fec.rs
    |-- harness.rs
    |-- implementations
    |   |-- client
    |   |   |-- backend.rs
    |   |   |-- connection.rs
    |   |   |-- integration.rs
    |   |   |-- io_driver.rs
    |   |   |-- killswitch.rs
    |   |   |-- mod.rs
    |   |   |-- pipeline.rs
    |   |   |-- platform
    |   |   |   |-- linux.rs
    |   |   |   |-- macos.rs
    |   |   |   |-- mod.rs
    |   |   |   |-- traits.rs
    |   |   |   `-- windows.rs
    |   |   |-- profile.rs
    |   |   |-- quality.rs
    |   |   |-- runtime.rs
    |   |   `-- subsystems.rs
    |   |-- mod.rs
    |   `-- server
    |       |-- accept.rs
    |       |-- admin.rs
    |       |-- admin_http.rs
    |       |-- admin_logs.rs
    |       |-- ip_pool.rs
    |       |-- limits.rs
    |       |-- metrics.rs
    |       |-- mod.rs
    |       |-- qkey_registry.rs
    |       |-- routing.rs
    |       |-- session.rs
    |       `-- systemd.rs
    |-- instrumentation.rs
    |-- interface.rs
    |-- lib.rs
    |-- main.rs
    |-- metrics.rs
    |-- optimize
    |   |-- brain.rs
    |   |-- compress.rs
    |   |-- crypto
    |   |   |-- aegis.rs
    |   |   |-- mod.rs
    |   |   |-- morus.rs
    |   |   `-- planner.rs
    |   |-- iter.rs
    |   |-- memory.rs
    |   |-- random.rs
    |   |-- sort.rs
    |   |-- stealth.rs
    |   |-- string.rs
    |   |-- telemetry.rs
    |   |-- transport.rs
    |   |-- udp.rs
    |   |-- unsafe.rs
    |   `-- x86_sse2.rs
    |-- optimize.rs
    |-- profile.rs
    |-- qftls.rs
    |-- reality.rs
    |-- simd
    |   |-- arm_stream.rs
    |   |-- arm_varint.rs
    |   |-- x86_ack.rs
    |   `-- x86_header.rs
    |-- simd.rs
    |-- stealth.rs
    |-- time_source.rs
    |-- transport
    |   |-- batch.rs
    |   |-- config.rs
    |   |-- connection.rs
    |   |-- frames.rs
    |   |-- h3.rs
    |   |-- packet.rs
    |   |-- pn.rs
    |   |-- recovery.rs
    |   |-- udpfast.rs
    |   |-- uring.rs
    |   `-- xdp.rs
    `-- transport.rs
```
