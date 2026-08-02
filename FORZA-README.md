# Wine (Valve) + WineGDK — Forza Motorsport online

Branch `forza-online`, based on **ValveSoftware/wine bleeding-edge @
`9578fa3613f`** (Wine 11.0) — the exact commit GE-Proton pins — with the
GDK runtime of [Weather-OS/WineGDK](https://github.com/Weather-OS/WineGDK)
branch `pr60` @ `b5d23b074cf` imported on top (curated to the
self-contained surface: `dlls/xgameruntime/`, the GDK headers, and the
widl/winnt.h support changes its C++ sources need).

This repo is the `wine` submodule of
[AllanVester/proton-ge-custom-forza-motorsport](https://github.com/AllanVester/proton-ge-custom-forza-motorsport):
because the base is Valve's own tree at GE's pin, GE-Proton's
`protonprep-valve-staging.sh` (wine-staging + proton patches + hotfixes)
applies unchanged, and `dlls/xgameruntime` rides along as a new,
additive DLL.

Everything here was found by measuring against the live Xbox Live / Turn 10
service, not by reading code and guessing. The evidence for each item —
what was observed, how, and which claims were later retracted — is in
`UPSTREAM-BUGS.md` and `FINDINGS.md` of the companion `gsstub` repo.

## What this branch fixes

One commit, 7 files, +1869/−102, all under `dlls/xgameruntime/`.

| # | file | defect |
|---|---|---|
| 16 | `main.c` | **`MicrosoftGame.config` `TitleId` is HEXADECIMAL and was parsed with `strtoul(…, 10)`.** `<TitleId>6DD4E56D</TitleId>` became **6**, so `XGameGetXboxTitleId` returned 6 for the life of the process. This was the entire "Failed to sign in" wall. |
| 1 | `XUser.c` | `user_CacheEndpoints` requested `title.mgmt.xboxlive.com`; the host is `title.**mgt**.xboxlive.com` and does not resolve, so the endpoint table was *always* empty and every host took the `http://xboxlive.com` fallback. Silently correct for `xboxlive.com` titles, wrong for any title with its own service. |
| 2 | `XUser.c` | The endpoints fetch sent no credentials, so the title-scoped document `/titles/current/endpoints` answered 401. |
| 3 | `XUser.c` | `SignaturePolicies` was mandatory, but the title-scoped document has only `["EndPoints"]` — so the parse failed *after* a successful 200, indistinguishable from the fetch failing. |
| 4 | `XUser.c` | Requests were signed unconditionally, ignoring each endpoint's `SignaturePolicyIndex`. Microsoft's own config for this title carries none, and a Windows capture shows an **empty** `Signature:` header on those hosts. |
| 5 | `XUser.c` | Both endpoint documents are needed — they are disjoint. ⚠ `?type=1` is *required* by `/titles/default` and makes `/titles/current` answer **414**. |
| 13 | `XUser.c` | `XUserFindUserByLocalId` was `E_NOTIMPL`, and it is the first thing a title calls on a user-change event. |
| 17 | `XUser.c` | The XSTS store was a single slot keyed by relying party while the title interleaves six RPs at boot → `Logon` 8.7 s late. Now a per-RP cache. |
| 7 | `XNetworking.cpp` | The security-information provider ignored the URL it was asked about. |
| 14 | `XTaskQueue.cpp`, `XThreading.cpp` | `XTaskQueue*` must be reached through `IXThreadingImpl`, not the module's own exports. |
| 10, 11 | `XodusService.cpp` | IPC for a **title-claimed** XSTS, carrying `uhs` + `xuid`. |

## Building

The normal way to build this tree is a full GE-Proton build of the parent
repo, which produces `xgameruntime.dll` (PE) and `xgameruntime.so` (unix
half, needed for the Xodus unix-socket client) alongside everything else.

For a quick standalone build of just the DLL (`xgameruntime.dll` is an
**added** DLL, not a replaced Wine builtin, so the PE half is
version-portable — the same code built from Wine 11.8 ran in daily use
inside a Wine 11.0 Proton without trouble):

```bash
autoreconf -f                        # Valve's tree does not commit configure
mkdir -p build && cd build
../configure --enable-win64          # or reuse an existing Wine build tree
make -j8 dlls/xgameruntime/x86_64-windows/xgameruntime.dll
cp dlls/xgameruntime/x86_64-windows/xgameruntime.dll \
   <proton>/files/lib/wine/x86_64-windows/
```

## What this branch does NOT fix

Getting the title online needs three more things that do not belong in Wine's
GDK layer. Do not expect this branch alone to be enough.

1. **Xodus** — a separate service holding the device identity and minting the
   title-claimed XSTS. Items 9–12 in `UPSTREAM-BUGS.md` are Xodus/xal-rs
   changes and are not in this repo.
2. **Two Wine core bugs**, neither GDK-related, both required to get past
   sign-in:
   - ~~**#18** `BCryptSetProperty(hKey, BCRYPT_INITIALIZATION_VECTOR)`~~ —
     **FIXED IN THIS BRANCH** (`dlls/bcrypt/bcrypt_main.c`, commit
     "bcrypt: implement BCRYPT_INITIALIZATION_VECTOR"). It is a Wine core fix,
     not a GDK one, so it is here for convenience — send it upstream to WineHQ
     separately. Verified on Wine 11.0: 50 X-Methods / 10325 gameservices lines
     with zero refusals, versus 47 / 9227 with the userspace shim it replaces.
     ⚠ Because it is a **core** DLL, it only takes effect if you build and ship
     this tree's `bcrypt.dll`. Dropping it into an existing Proton works, but
     **only the PE half** — `bcrypt.so` is a native Linux object and a Proton
     built for the Steam Linux Runtime (`-slr-`) will not load one built against
     your host's libraries.
   - ~~**#19** `NtAllocateVirtualMemory`'s `type_mask` in
     `dlls/ntdll/unix/virtual.c` rejects `MEM_LARGE_PAGES|MEM_PHYSICAL` with
     `STATUS_INVALID_PARAMETER`, so a 14 MB staging pool allocated in a C++
     static constructor is born NULL and unchecked; its first use hits the
     title's "Out of Memory" handler, which deliberately crashes.~~ —
     **FIXED IN THIS BRANCH** (commit "ntdll: accept MEM_LARGE_PAGES and
     tolerate MEM_PHYSICAL in NtAllocateVirtualMemory"). Also a Wine core
     fix; upstream it separately. ⚠ It lives in `ntdll.so`, the **unix**
     half, so unlike #18 it cannot be dropped into an existing `-slr-`
     Proton at all — it only takes effect in a Proton built from this
     tree, which is exactly what this repo is for.
   ⚠ These replace Wine **builtins**, so unlike `winegdkrt.dll` they must be
   built from the *same* Wine version as the Proton they ship in — the PE
   `bcrypt.dll` reaches its unix half through a version-specific unixlib enum.
3. **One behavioural workaround that is not a Wine bug at all.** Measured by
   bisection: with everything else stripped, the title still dies ~14 s in
   unless a single dword is written into its own memory to switch off its
   internal recorder. Why the recorder is fatal under Wine is **unknown** —
   the title has never been observed booting with it running on this stack.

## Known unrelated failure

Loading a track reliably hangs the GPU: `NVRM: Xid 109 CTX SWITCH TIMEOUT`,
~4 s stall, `VK_ERROR_DEVICE_LOST` → `DXGI_ERROR_DEVICE_REMOVED` → the title's
"Fatal Error D3D" handler. Reproduced 6/6 and **not** caused by anything here:
ruled out by measurement are ray tracing, `VKD3D_CONFIG=single_queue`,
`PROTON_VKD3D_HEAP=1` (the `vkd3d-bratan` descriptor-heap build), and the
specific track. It is kernel-driver-side — see
[NVIDIA/open-gpu-kernel-modules#1097](https://github.com/NVIDIA/open-gpu-kernel-modules/issues/1097),
which reports the same Xid on Blackwell; this reproduction is on **Ampere**.
