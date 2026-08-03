/*
 * Persistent Local Storage provider
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
 * A GDK title does not build its own per-title storage path: it asks the runtime
 * for one. Without this provider that query fails, the title is left with an
 * empty root, and every container path it builds stays RELATIVE - so its saves,
 * caches and settings are written next to the executable instead of under
 * %LOCALAPPDATA%. Forza Motorsport is the measured case: its CmsCache,
 * ConnectedStorage, InputMappings, UGC and CrashReport.xml all landed in the game
 * directory, and CrashReport.xml came out as a DIRECTORY because the storage layer
 * creates one container directory per item name under the root - with no root, the
 * item name itself becomes a top-level directory.
 *
 * There is no public IDL for this class, so the interface below was measured
 * rather than declared, by answering the query with an object of numbered logging
 * thunks and watching which slots the title called:
 *
 *   slot 3  XPersistentLocalStorageGetPathSize( size_t *pathSize )
 *   slot 4  XPersistentLocalStorageGetPath( size_t pathSize, char *path, size_t *pathUsed )
 *
 * which is the documented GDK two-call pattern: ask for the length, then supply a
 * buffer of that length. The slot NAMES come from the skeleton in
 * xodus-gaming/wine (`dlls/xgameruntime/xpersistentlocalstorage.c`), where every
 * method is still E_NOTIMPL; the BEHAVIOUR below is measured against the title.
 *
 * ⚠ Reading them as "get identity name" + "get root path" also produces a title
 * that writes to the right folder, but only by accident: a size written as text
 * comes back as a nonsense length, which the title then passes straight into
 * pathSize. Any title that checks that length would break. Slots 5-8
 * (GetSpaceInfo, PromptUserForSpaceAsync/Result, MountForPackage) are not
 * implemented - Forza never calls them.
 */

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "private.h"

WINE_DEFAULT_DEBUG_CHANNEL(xgameruntime);

/* Defined outright rather than with DEFINE_GUID: that macro only emits storage
 * when INITGUID is set, and initguid.h is already included by main.c - pulling it
 * in here as well would re-define every other GUID the headers declare. */
const GUID CLSID_XPersistentLocalStorageImpl =
    { 0xf4faf4d4, 0x2d04, 0x4fce, { 0xb3, 0xe0, 0x47, 0x4a, 0x71, 0x3a, 0x3e, 0x84 } };

struct persistent_local_storage;

struct persistent_local_storage_vtbl
{
    HRESULT (WINAPI *QueryInterface)( struct persistent_local_storage *, REFIID, void ** );
    ULONG   (WINAPI *AddRef)( struct persistent_local_storage * );
    ULONG   (WINAPI *Release)( struct persistent_local_storage * );
    HRESULT (WINAPI *GetPathSize)( struct persistent_local_storage *, SIZE_T * );
    HRESULT (WINAPI *GetPath)( struct persistent_local_storage *, SIZE_T, char *, SIZE_T * );
};

struct persistent_local_storage
{
    const struct persistent_local_storage_vtbl *vtbl;
};

static HRESULT WINAPI persistent_local_storage_QueryInterface( struct persistent_local_storage *impl,
                                                               REFIID iid, void **out )
{
    TRACE( "impl %p, iid %s, out %p\n", impl, debugstr_guid( iid ), out );
    if (!out) return E_POINTER;
    /* The class has exactly one interface and the title asks for it by class, so
     * there is nothing to discriminate on. */
    *out = impl;
    return S_OK;
}

static ULONG WINAPI persistent_local_storage_AddRef( struct persistent_local_storage *impl )
{
    return 2;   /* a singleton that outlives every caller */
}

static ULONG WINAPI persistent_local_storage_Release( struct persistent_local_storage *impl )
{
    return 1;
}

/* %LOCALAPPDATA%\<Identity Name>, created on demand. The name is the title's own
 * Identity/@Name from MicrosoftGame.config, which is exactly the folder Windows
 * uses - "Microsoft.ForzaMotorsport" for Forza Motorsport. */
static HRESULT persistent_local_storage_path( char *path, SIZE_T size )
{
    char local[MAX_PATH];
    int len;

    if (!identityName)
    {
        WARN( "MicrosoftGame.config carries no Identity Name.\n" );
        return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
    }
    if (!GetEnvironmentVariableA( "LOCALAPPDATA", local, ARRAY_SIZE(local) ))
        return HRESULT_FROM_WIN32( GetLastError() );

    len = _snprintf( path, size, "%s\\%s", local, identityName );
    if (len < 0 || (SIZE_T)len >= size) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );

    if (!CreateDirectoryA( path, NULL ) && GetLastError() != ERROR_ALREADY_EXISTS)
        WARN( "could not create %s, error %lu\n", debugstr_a( path ), GetLastError() );
    return S_OK;
}

/***********************************************************************
 *      XPersistentLocalStorageGetPathSize  (vtable slot 3)
 */
static HRESULT WINAPI persistent_local_storage_GetPathSize( struct persistent_local_storage *impl,
                                                            SIZE_T *pathSize )
{
    char path[MAX_PATH];
    HRESULT hr;

    TRACE( "impl %p, pathSize %p\n", impl, pathSize );

    if (!pathSize) return E_POINTER;
    if (FAILED(hr = persistent_local_storage_path( path, ARRAY_SIZE(path) ))) return hr;
    *pathSize = strlen( path ) + 1;
    return S_OK;
}

/***********************************************************************
 *      XPersistentLocalStorageGetPath  (vtable slot 4)
 */
static HRESULT WINAPI persistent_local_storage_GetPath( struct persistent_local_storage *impl,
                                                        SIZE_T pathSize, char *path,
                                                        SIZE_T *pathUsed )
{
    char full[MAX_PATH];
    SIZE_T needed;
    HRESULT hr;

    TRACE( "impl %p, pathSize %Iu, path %p, pathUsed %p\n", impl, pathSize, path, pathUsed );

    if (!path) return E_POINTER;
    if (FAILED(hr = persistent_local_storage_path( full, ARRAY_SIZE(full) ))) return hr;

    needed = strlen( full ) + 1;
    if (pathUsed) *pathUsed = needed;
    if (pathSize < needed) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );

    memcpy( path, full, needed );
    TRACE( "-> %s\n", debugstr_a( full ) );
    return S_OK;
}

static const struct persistent_local_storage_vtbl persistent_local_storage_vtbl =
{
    persistent_local_storage_QueryInterface,
    persistent_local_storage_AddRef,
    persistent_local_storage_Release,
    persistent_local_storage_GetPathSize,
    persistent_local_storage_GetPath,
};

static struct persistent_local_storage persistent_local_storage = { &persistent_local_storage_vtbl };

HRESULT persistent_local_storage_query( REFIID iid, void **out )
{
    return persistent_local_storage_QueryInterface( &persistent_local_storage, iid, out );
}
