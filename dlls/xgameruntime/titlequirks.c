/*
 * Title-specific quirks applied by the GDK runtime
 *
 * Copyright 2026 Allan Vester
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * ⚠ THIS FILE PATCHES A GAME'S OWN MEMORY. It is NOT a Wine bug fix and must
 * never be sent upstream to WineHQ. It exists because one specific title is
 * otherwise unusable under Proton for reasons that are not Wine's fault, and it
 * is fenced into one file, behind an exact-image check, so it can be deleted or
 * disabled without touching anything else.
 *
 * FORZA MOTORSPORT (forza_steamworks_release_final.exe): the title carries an
 * internal leak-recorder that appends a 24-byte record {block, size, tag} to a
 * per-CPU std::vector on EVERY free. Its consumer is real and works - it is
 * driven per tick from exe+0x38a340 and drains the vectors in one pass - but it
 * only starts once the title is ticking, roughly ten seconds in. Everything
 * freed while the title is still loading therefore accumulates first, and under
 * Proton loading takes long enough that the burst reaches ~15 MILLION records
 * (343 MB) before the first drain.
 *
 * The records themselves are not the problem; they are drained and the vectors
 * settle at ~450 MB of reserved capacity. The problem is what the churn does to
 * the title's OWN allocator. Measured with paired runs that differ only in this
 * one dword (t+20 s, large blocks >= 1 MB):
 *
 *     recorder OFF   alloc  377 MB /   51 calls   free 288 MB /  32   LIVE   88 MB
 *     recorder ON    alloc 2807 MB /  160 calls   free 788 MB /  84   LIVE 2019 MB
 *
 * and over a full two-minute run with the recorder off the allocator returns
 * 94% of what it takes (2675 MB freed of 2855 MB, 1355 free calls against 1406
 * allocs) and holds a flat 180 MB. With the recorder on the free count STICKS -
 * it stops handing large blocks back at all - while allocation runs away. Those
 * bytes never reach HeapFree, so the retention is above the Win32 boundary, in
 * the title's arena: there is nothing Wine could return and nothing to fix in
 * Wine. Resident set with the recorder running reaches 14.4 GB by t+105 s and
 * was still climbing when the measurement was stopped, against a ~5.1 GB
 * plateau with it off.
 *
 * The off switch is the title's own: sub_140ba1e40 opens with
 *
 *     cmp dword ptr [ctx+0x2040], 0
 *     je  <skip>                       ; skip path still frees, it only
 *                                      ; stops the recording
 *
 * so zeroing that one dword disables recording and nothing else. The context is
 * reachable from a fixed global, and the title keeps a second copy of the same
 * bucket count in another global, which is what makes the write verifiable
 * rather than a leap of faith - see forza_disable_free_recorder().
 *
 * ⚠ DO NOT "SIMPLIFY" THIS BY ZEROING THE GLOBAL COUNT AT exe+0x621b5d4. The
 * title's ALLOCATOR reads that same global to pick a per-CPU arena and divides
 * by it at exe+0xba2cb2. Zeroing it is a divide-by-zero. Only the recorder
 * reads ctx+0x2040, which is why that is the correct target.
 *
 * Sign-in does NOT depend on this: the title signs in fine with the recorder
 * running (measured, 6625 gameservices lines). This is purely about memory.
 */

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "private.h"

WINE_DEFAULT_DEBUG_CHANNEL(xgameruntime);

/* All RVAs below were measured in the shipping build of
 * forza_steamworks_release_final.exe. They are validated at runtime before any
 * write, so a different build fails the checks and is left alone. */
#define FORZA_EXE_NAME        L"forza_steamworks_release_final.exe"
#define FORZA_REC_CTX_RVA     0x621b570   /* void*  the recorder context      */
#define FORZA_REC_COUNT_RVA   0x621b5d4   /* DWORD  bucket count, = cpus + 1  */
#define FORZA_REC_CTX_COUNT   0x2040      /* the recorder's own copy of it    */
#define FORZA_REC_MAX_BUCKETS 129

static BOOL quirk_readable( const void *addr, SIZE_T size, BOOL need_write )
{
    MEMORY_BASIC_INFORMATION mbi;

    if (!VirtualQuery( addr, &mbi, sizeof(mbi) )) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return FALSE;
    if (need_write && !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return FALSE;
    if ((const BYTE *)addr + size > (const BYTE *)mbi.BaseAddress + mbi.RegionSize)
        return FALSE;
    return TRUE;
}

static BOOL running_forza( BYTE **image_base, SIZE_T *image_size )
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    WCHAR path[MAX_PATH], *name;
    HMODULE exe;

    if (!GetModuleFileNameW( NULL, path, ARRAY_SIZE(path) )) return FALSE;
    name = wcsrchr( path, '\\' );
    name = name ? name + 1 : path;
    if (wcsicmp( name, FORZA_EXE_NAME )) return FALSE;

    if (!(exe = GetModuleHandleW( NULL ))) return FALSE;
    dos = (IMAGE_DOS_HEADER *)exe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)exe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    *image_base = (BYTE *)exe;
    *image_size = nt->OptionalHeader.SizeOfImage;
    return TRUE;
}

/***********************************************************************
 *      forza_disable_free_recorder
 *
 * Returns TRUE once the recorder has been switched off (or was already off),
 * FALSE if this is not Forza, if the quirk is disabled, or if the recorder is
 * not up yet and the caller should try again later.
 *
 * EVERY step is validated, because a mis-aimed dword store into a live game is
 * not a bug you get to debug: the executable must be the one these RVAs were
 * measured in, both globals must lie inside its image, the bucket count must
 * agree with the processor count, the context must point OUTSIDE the image (it
 * is heap-allocated), and the context's own copy of the count must match the
 * global. Only then is the store made. Any mismatch means a different build and
 * the title is left exactly as it was.
 */
BOOL forza_disable_free_recorder(void)
{
    static BOOL done;
    BYTE *base, *ctx;
    SIZE_T image_size;
    DWORD global_count, ctx_count, cpus;
    SYSTEM_INFO si;
    char buf[8];

    if (done) return TRUE;

    if (GetEnvironmentVariableA( "WINEGDK_FORZA_QUIRKS", buf, sizeof(buf) ) && buf[0] == '0')
    {
        TRACE( "disabled by WINEGDK_FORZA_QUIRKS=0.\n" );
        done = TRUE;
        return TRUE;
    }

    if (!running_forza( &base, &image_size )) return FALSE;

    if (FORZA_REC_CTX_RVA + sizeof(void *) > image_size ||
        FORZA_REC_COUNT_RVA + sizeof(DWORD) > image_size)
    {
        WARN( "not the expected build (image is %#Ix bytes); leaving the recorder alone.\n",
              image_size );
        done = TRUE;
        return TRUE;
    }

    if (!quirk_readable( base + FORZA_REC_COUNT_RVA, sizeof(DWORD), FALSE ) ||
        !quirk_readable( base + FORZA_REC_CTX_RVA, sizeof(void *), FALSE ))
        return FALSE;

    global_count = *(DWORD *)(base + FORZA_REC_COUNT_RVA);
    ctx = *(BYTE **)(base + FORZA_REC_CTX_RVA);
    if (!global_count || !ctx) return FALSE;    /* not initialised yet */

    /* The count is set as "processor count + 1" by the title's own recorder
     * initialiser, so it is checkable against the machine we are on. */
    GetSystemInfo( &si );
    cpus = si.dwNumberOfProcessors;
    if (global_count > FORZA_REC_MAX_BUCKETS || global_count != cpus + 1)
    {
        WARN( "bucket count %lu does not match %lu processors + 1; not the expected"
              " layout, leaving the recorder alone.\n", global_count, cpus );
        done = TRUE;
        return TRUE;
    }

    /* The context is heap-allocated; a pointer into the image would mean we are
     * reading something else entirely. */
    if (ctx >= base && ctx < base + image_size)
    {
        WARN( "recorder context %p is inside the image; not the expected layout.\n", ctx );
        done = TRUE;
        return TRUE;
    }

    if (!quirk_readable( ctx + FORZA_REC_CTX_COUNT, sizeof(DWORD), TRUE )) return FALSE;

    ctx_count = *(DWORD *)(ctx + FORZA_REC_CTX_COUNT);
    if (!ctx_count)
    {
        TRACE( "recorder already off.\n" );
        done = TRUE;
        return TRUE;
    }
    if (ctx_count != global_count)
    {
        WARN( "recorder context count %lu disagrees with the global %lu; not the"
              " expected layout, leaving the recorder alone.\n", ctx_count, global_count );
        done = TRUE;
        return TRUE;
    }

    *(DWORD *)(ctx + FORZA_REC_CTX_COUNT) = 0;
    done = TRUE;
    ERR( "Forza Motorsport: disabled the title's internal free-recorder"
         " (context %p, %lu buckets). This trades the title's own leak tracking,"
         " which it does not need at runtime, for several GB of resident memory;"
         " set WINEGDK_FORZA_QUIRKS=0 to keep the recorder running.\n",
         ctx, global_count );
    return TRUE;
}
