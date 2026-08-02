# WineGDK — Forza Motorsport online

Branch `forza-online`, based on **`b5d23b074cf`** of
[Weather-OS/WineGDK](https://github.com/Weather-OS/WineGDK) branch `pr60`
("xgameruntime: Enable xbox live multiplayer in minecraft").

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

`winegdkrt.dll` is an **added** DLL, not a replaced Wine builtin, so it is
version-portable — this tree is Wine 11.8 and the resulting DLL is in daily use
inside a Wine **11.0** Proton without trouble.

```bash
mkdir -p build && cd build
../configure --enable-win64          # or reuse an existing Wine build tree
make -j8 dlls/xgameruntime/x86_64-windows/winegdkrt.dll
cp dlls/xgameruntime/x86_64-windows/winegdkrt.dll \
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
   - **#18** `BCryptSetProperty(hKey, BCRYPT_INITIALIZATION_VECTOR)` is
     unimplemented → the title's AES key import fails → **no CMS content is
     ever decrypted** → `IOSys::FileOpenStatus 7` → an endless "Attempting to
     reconnect". Fix is one branch in `dlls/bcrypt/bcrypt_main.c` calling the
     already-present `key_symmetric_set_vector()`.
   - **#19** `NtAllocateVirtualMemory`'s `type_mask` in
     `dlls/ntdll/unix/virtual.c` rejects `MEM_LARGE_PAGES|MEM_PHYSICAL` with
     `STATUS_INVALID_PARAMETER`, so a 14 MB staging pool allocated in a C++
     static constructor is born NULL and unchecked; its first use hits the
     title's "Out of Memory" handler, which deliberately crashes.
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
