# WASM Example

A minimal first application for the [Enclave OS](https://privasys.org/solutions/enclave-os/)
WASM runtime. It exercises every core host capability a confidential WASM app can use — with
**no configuration step and no freeze gate**, so it deploys and serves traffic straight away.

Looking for the configure-then-freeze pattern (inject a secret at deploy time, advertise its
hash on the RA-TLS leaf, and gate every export until the app is configured)? See the companion
repository **[wasm-app-example-with-config](https://github.com/Privasys/wasm-app-example-with-config)**.

## Exported functions

| Function | Demonstrates |
|----------|--------------|
| `hello` | Basic smoke test — no host imports |
| `get-random` | `wasi:random` → RDRAND inside the enclave |
| `get-time` | `wasi:clocks/wall-clock` → host call |
| `kv-store` | `wasi:filesystem` → per-app sealed KV store |
| `kv-read` | `wasi:filesystem` → per-app sealed KV store |
| `fetch-headlines` | `privasys:enclave-os/https` → attestable TLS egress |
| `analyse-data` | Records, enums, options — doubles as an MCP tool |
| `auth-hello` | Authenticated-only endpoint (OIDC / FIDO2) |
| `role-hello` | Role-gated endpoint (requires `hello-role`) |

Auth and role checks are enforced by the runtime **before** your function is called — the app
itself never inspects credentials.

## Build

```sh
cargo component build --release
```

For faster load times, AOT-compile to `.cwasm` with Wasmtime (no Cranelift inside the enclave):

```sh
wasmtime compile target/wasm32-wasip1/release/wasm_example.wasm -o wasm_example.cwasm
```

## Deploy

Deploy the `.cwasm` through the [developer portal](https://developer.privasys.org) — either by
uploading the file directly, or by pointing the portal at this repository and letting it run a
reproducible build from a commit. Once deployed you can inspect the app's remote attestation and
call its functions (including the MCP tool surface) from the portal.

See the [deploy a WASM app guide](https://docs.privasys.org/solutions/platform/developer-platform/deploy-wasm)
for the full walkthrough.

## Store listing

`privasys.json` carries the App Store `store` block for this app. The platform ingests it
(fill-if-empty) when the app is created or upgraded, so the listing is pre-populated without
retyping it in the portal.

## License

AGPL-3.0. See [LICENSE](LICENSE).
