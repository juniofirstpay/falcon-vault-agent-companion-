# vault-agent-companion — Architecture & Design

## The contract this package consumes

A Vault Agent sidecar (separate container) authenticates to Vault via AppRole and renders
files to a shared volume. This package is the **app-side half**: it watches those files and
hot-reloads them. The two halves only agree on the **rendered files** — that's the
language-agnostic standard (a Go service re-implements the same file-watch natively; this
package is the Python convenience).

```
Vault Agent ──renders──▶ /shared/vault-secrets.yaml ──▶ [secrets.watch] ──▶ on_change()
            ──renders──▶ /shared/certs/<svc>-leaf.pem ─▶ [CertRotator]   ──▶ load_cert_chain()
```

## Why a standalone package (not folded into svcplane)

`falcon-svcplane` owns mTLS **termination** + the peer-CN allow-list (authz). Secret/cert
**reload** is a different concern with a different release cadence:

- Bundling it would force `dynaconf` + `watchfiles` onto every svcplane consumer.
- Cert rotation must also reload the **outbound** http-client context, which svcplane doesn't
  own — so it doesn't cleanly belong inside svcplane.
- svcplane keeps building the initial `ssl_kwargs`; this package reloads the live context it
  produced. Clean handoff, no coupling.

## Agnostic core + adapters

```
core/                        # deps: watchfiles only
  secrets.py   watch(path, on_change) / spawn ; pure _touches_target predicate
  tls.py       CertRotator.register(ctx, cert_path[, key_path]).watch()
adapters/                    # optional extras
  dynaconf.py  make_reload(settings, re_resolve=None)
  uvicorn.py   attach(rotator, server_or_config, cert_path)
```

The core takes **generic hooks** (a callback; a `register(SSLContext, path)`), so it's usable
by any config lib, any ASGI server, with or without svcplane. Adapters are thin translations.

## Design decisions, and why

### Watch the parent directory, not the file
The Vault Agent renders atomically: write a temp file, then **rename** it into place. That
changes the inode. A watch on the file path would end up watching a stale, unlinked inode and
miss every rotation. So both `secrets.watch` and `CertRotator.watch` watch the file's
**parent directory** and filter for the target path. (The `_touches_target` predicate is pure
so it's unit-tested without the filesystem — macOS fsevents can replay a file's own creation
at watcher startup, which makes real-fs negative tests flaky.)

### Single-issuance cert, cert+key in one file
The naïve approach renders the cert and the key from **two separate** template blocks — two
`pki/issue` calls — producing a cert and key that don't match. The correct pattern renders
both from **one** issuance into one PEM, so `cert_path == key_path`. `load_cert_chain` reads
the key from the same file. The trust root is read separately (from `pki/cert/ca`, no
issuance), so the leaf render and the CA render never interfere.

### `SSLContext.load_cert_chain` for cert rotation
`load_cert_chain` is re-callable on a live context. It updates the cert used for **new**
handshakes; existing connections keep the cert they negotiated; `verify_mode` and the trust
root (`load_verify_locations`) are untouched. So rotating a leaf is just re-loading the chain
— no restart, no monkey-patching. Register **both** the inbound (server) context and any
outbound http-client context; a rotated leaf must refresh both.

### Reload depth is the app's concern
The core only fires the callback. What to re-resolve after a secrets change is the app's call,
because it depends on *how each consumer captured the secret*:

| Consumer | Rotates by |
|---|---|
| values read live from settings per use | `settings.reload()` alone |
| provider/client instances that captured a secret at construction | rebuild the instances |
| a pooled DB engine whose creator reads creds live | mutate the live cred object in place |
| a pool that captured creds at build | reconnect / dispose + rebuild |

Keeping this out of the package means the package stays tiny and every service stages its own
depth (e.g. cert seamless + providers re-init now, DB/redis reconnect later).

## Operational notes

- **inotify across Docker volumes works.** A common worry is that a cross-container write to a
  shared volume won't reach another container's inotify watch. In practice it does — watchfiles
  in one container sees the agent's rename in another. If a particular filesystem/driver
  doesn't deliver events, set `WATCHFILES_FORCE_POLLING=true`.
- **The agent must be able to write the shared volume.** If the vault image entrypoint drops to
  a non-root user it can't write a root-owned volume; run it as root / override the entrypoint,
  or pre-create the dir with the right ownership.
- **Startup gate.** A TLS server loads its cert at boot, so the app must wait until the sidecar
  has rendered the leaf before binding.
- **Hold the watch task reference.** `asyncio.ensure_future(rotator.watch())` returns a Task; a
  bare, unreferenced task can be garbage-collected mid-run. Store it (a local in a frame that
  lives for the server's lifetime is enough).

## Testing

`pytest` (15 tests): secrets watcher fires on change (sync + async callbacks); the target
predicate ignores siblings/tempfiles deterministically; `CertRotator` reloads on change; a
half-written PEM is swallowed; the adapters call `settings.reload()` + re-resolve and grab
`config.ssl`; and — the headline — a **real socketpair TLS handshake** proves the served leaf
serial swaps (`1001 → 2002`) after `reload()`.
