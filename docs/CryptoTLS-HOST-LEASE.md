# Crypto TLSHost — host-side DSO admission and quiescent unload (M1.9)

This module is a **host-only C11 library** `Salts::TLSHost`, installed
alongside `Salts::TLS`. It does not link or contain the private GmSSL
static archive or any Crypto TLS backend code. Its job is *only* to own
a native loader reference, verify the eleven public `crypto_tls_*` ABI
symbols, and prevent that loader reference from being released while
a host worker is using it.

`include/crypto/loader.h` and `src/crypto_tls_loader.c` deliberately
leave the unchanged `include/crypto/tls.h` v1 interface untouched.

## Atomic admission / close protocol

- `crypto_tls_module_open(absolute_path, &module)`: explicit native path,
  `dlopen(RTLD_NOW|RTLD_LOCAL)` or Windows `LoadLibraryA`, exact ABI version
  and all eleven required exports validated before the caller receives
  any handle. No dynamic fallback, no auto provider selection.
- `crypto_tls_module_acquire(module, &lease)`: allocates a host lease and
  atomically increments the count **only while OPEN**. One CAS covers
  both the admission state and the count; a concurrent close can never
  see zero after an already admitted lease.
- `crypto_tls_module_lease_api(lease, &api)`: exposes only a borrowed
  C11 function table. All providers/sessions created through that API
  must be destroyed before the **final lease protecting their lifetime**
  is released. Do not call or cache the table after release.
- `crypto_tls_module_close(module)`: atomically enters DRAINING,
  permanently rejects new leases and returns BUSY if any admitted
  worker still holds a lease. The owner may retry after the count
  drains. Exactly one thread transitions into UNLOADING; the native
  unload call executes at most once. This is nonblocking, not a
  forced cancellation of TLS or I/O.
- `crypto_tls_module_destroy(&module)`: only releases the host control
  block after `close` succeeded; otherwise BUSY. Do not call while
  another thread can still *enter* any API via the module pointer.

The host controller itself must remain allocated until all producers,
callbacks and workers have been explicitly stopped or joined. The
lease guarantees DSO code remains resident during an admitted call,
**not** the safety of an arbitrary stale pointer to a destroyed module,
nor the lifetime of independently borrowed callback user memory.
Application-level shutdown must first close admission, cancel/drain
workers, join them, destroy sessions/providers, release their leases,
then finalize and destroy the module.

Independent OS handles to the same image may keep it loaded; the host
loader never claims global ownership of every module reference or
prevents a different DSO from statically embedding a second GmSSL.

## Qualification

Normal Linux/macOS/Windows installed C11 SDK now adds
`crypto.installed.host_lease_unload`: 32 actual
`LoadLibrary/dlopen`/drain/release/unload cycles against the installed
Crypto Provider, with two simultaneous leases, provider creation,
no late admissions and idempotent successful close. The host test
links only `Salts::TLSHost` and is not a direct Crypto TLS consumer.

Native Linux TSan also adds
`crypto.installed.host_lease_callback_race`: 64
callback-in-flight cycles per run, repeated three times. A worker
owns a separate module lease and blocks in an actual GmSSL TLS
external-I/O callback. The main thread enters module DRAINING,
checks no new lease admission and BUSY session/provider destruction,
cancels while all borrowed state is alive, joins the worker, releases
the remaining host lease, and then unloads safely.

The entire GmSSL source, Crypto shared DSO, TLSHost static helper
and independently installed C11 consumers are TSan instrumented.
Linux ASan/UBSan/LSan repeats the ordinary lease test under
instrumented real TLS code.

This is an **additional host-side safety layer**, not a production
unload guarantee for code that bypasses the lease or mismanages
application-level object lifetimes. Before production CNet integration:
resolve SaltsCore's single shared foundation runtime ownership (see
`qigao/salts-core#20`), prove a real final linked CNet SDK consumer,
and audit all GmSSL-bearing images and dynamic loader references.

No production CNet or vcpkg-cache registry change is included.
