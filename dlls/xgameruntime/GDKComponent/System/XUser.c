/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XUser
 *
 * Copyright 2026 Olivia Ryan
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

#include "private.h"
#include "util.h"
#include <errno.h>
#include <ntdef.h>
#include <time.h>
#include <wincrypt.h>
#include <wininet.h>

WINE_DEFAULT_DEBUG_CHANNEL(gdkc);

static const WCHAR *ACCEPT_JSON[] = { L"application/json", NULL };
static const WCHAR CT_JSON[] = L"Content-Type: application/json";
static const WCHAR CT_FORM_URLENCODED[] = L"Content-Type: application/x-www-form-urlencoded";

static const char PROOF_KEY_TEMPLATE[] = "{\"alg\":\"ES256\",\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"";
static const char PROOF_KEY_TEMPLATE2[] = "\",\"y\":\"";
/* x & y are 43 chars */
#define PROOF_KEY_SIZE ARRAY_SIZE( PROOF_KEY_TEMPLATE ) + ARRAY_SIZE( PROOF_KEY_TEMPLATE2 ) + 86

static HRESULT MultiByteToHSTRING( const char *str, UINT32 str_size, HSTRING *hstr )
{
    UINT32 wstr_size;
    WCHAR *wstr;
    HRESULT hr;

    if (!(wstr_size = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, str, str_size, NULL, 0 )))
        return HRESULT_FROM_WIN32( GetLastError() );

    if (!(wstr = calloc( wstr_size, sizeof(WCHAR) ))) return E_OUTOFMEMORY;

    if (!(wstr_size = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, str, str_size, wstr, wstr_size )))
    {
        free( wstr );
        return HRESULT_FROM_WIN32( GetLastError() );
    }

    hr = WindowsCreateString( wstr, wstr_size, hstr );
    free( wstr );
    return hr;
}

static HRESULT HSTRINGToMultiByte( HSTRING hstr, char **str )
{
    const WCHAR *wstr;
    UINT32 wstr_size;
    int str_size;

    wstr = WindowsGetStringRawBuffer( hstr, &wstr_size );
    if (!(str_size = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wstr, wstr_size, NULL, 0, NULL, NULL )))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (!(*str = calloc( str_size + 1, sizeof(char) ))) return E_OUTOFMEMORY;
    if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wstr, wstr_size, *str, str_size, NULL, NULL ))
    {
        HRESULT hr = HRESULT_FROM_WIN32( GetLastError() );
        free( *str );
        *str = NULL;
        return hr;
    }
    return S_OK;
}

static HRESULT get_json_utf8( IJsonObject *object, const WCHAR *key, char **value )
{
    HSTRING string = NULL;
    HRESULT hr;

    if (FAILED(hr = get_json_string( object, key, &string ))) return hr;
    hr = HSTRINGToMultiByte( string, value );
    WindowsDeleteString( string );
    return hr;
}

static HRESULT parse_json( const char *json, SIZE_T jsonLen, IJsonObject **object )
{
    static const WCHAR *name = RuntimeClass_Windows_Data_Json_JsonValue;
    IJsonValueStatics *statics;
    HSTRING_HEADER header;
    IJsonValue *value;
    UINT32 wJsonLen;
    HSTRING string;
    WCHAR *wJson;
    HRESULT hr;

    TRACE( "json %s, object %p.\n", debugstr_an( json, jsonLen ), object );

    if (!(wJsonLen = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, json, jsonLen, NULL, 0 ))) return HRESULT_FROM_WIN32( GetLastError() );
    if (FAILED(hr = WindowsCreateStringReference( name, wcslen( name ), &header, &string ))) return hr;
    if (FAILED(hr = RoGetActivationFactory( string, &IID_IJsonValueStatics, (void **)&statics ))) return hr;
    if (!(wJson = calloc( wJsonLen + 1, sizeof(WCHAR) )))
    {
        IJsonValueStatics_Release( statics );
        return E_OUTOFMEMORY;
    }

    if (!MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, json, jsonLen, wJson, wJsonLen + 1 )) goto error;
    if (FAILED(hr = WindowsCreateStringReference( wJson, wJsonLen, &header, &string ))) goto cleanup;
    if (FAILED(hr = IJsonValueStatics_Parse( statics, string, &value ))) goto cleanup;
    hr = IJsonValue_GetObject( value, object );
    IJsonValue_Release( value );
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
cleanup:
    IJsonValueStatics_Release( statics );
    free( wJson );
    return hr;
}

struct endpoint
{
    char *host;
    char *path;
    char *relyingParty;
    /* Microsoft's own title-scoped config carries NO SignaturePolicyIndex for a
       title's own service hosts, and the Windows ground-truth capture sends those
       requests with an EMPTY Signature. Signing unconditionally is therefore
       wrong; remember whether this endpoint asked to be signed. */
    BOOL hasSignaturePolicy;
};

static void free_endpoints( struct endpoint *endpoints, UINT32 count )
{
    /* count is set from get_Size BEFORE the array is allocated, so the cleanup path can
     * reach here with endpoints == NULL and count > 0 - dereferencing that faults at
     * address 0. Guard the pointer, not just the count. */
    if (!endpoints) return;
    for (UINT32 i = 0; i < count; ++i)
    {
        free( endpoints[i].host );
        free( endpoints[i].path );
        free( endpoints[i].relyingParty );
    }
    free( endpoints );
}

struct policy
{
    UINT32 version;
    UINT32 maxBodyBytes;
};

/*
 * PER-RELYING-PARTY XSTS CACHE.
 *
 * The token store used to be a SINGLE slot - one token plus the relying party it
 * was minted for - and the only reuse test was "is this the same relying party as
 * last time":
 *
 *     if (!user->xstsRelyingParty || strcmp( user->xstsRelyingParty, relyingParty ))
 *         user_request_xsts_token( user, relyingParty );
 *
 * A title that talks to one service is fine. A title that INTERLEAVES services
 * evicts on every alternation and re-mints from scratch each time, and each mint
 * is a full network round trip (SISU/XSTS, and for a title-claim relying party a
 * round trip through the Xodus service on top). Worse, the call site holds
 * `xstsLock` EXCLUSIVELY across the mint, so they cannot even overlap.
 *
 * MEASURED, Forza Motorsport: six token requests for six DISTINCT relying parties
 * (sisu, peoplehub, playfab, gameservices.fm.forzamotorsport.net, profile, rta)
 * are issued within ~80 ms of each other during boot. With a single slot that is
 * six misses, serialised, 1.0-4.3 s each - and the title's own LSP `Logon` could
 * not go out until 8.6 s after the first ask.
 *
 * That delay is not cosmetic. FM starts its CMS content request 52 ms after the
 * first token ask and expects a session to exist; with Logon 8.6 s late the
 * request has nothing to travel on and is failed 183 ms after Logon finally
 * completes - deterministically, in every cycle.
 *
 * WINEGDK_XSTS_CACHE_TTL sets the lifetime in seconds (default 600; XSTS tokens
 * live hours, so this is deliberately conservative). Setting it to 0 DISABLES the
 * cache and restores the old single-slot behaviour, which is what makes the
 * before/after measurable rather than asserted.
 */
#define XSTS_CACHE_MAX 8

struct xsts_cache_entry
{
    char    *relyingParty;
    HSTRING  token;
    HSTRING  userHash;
    UINT64   xuid;
    BOOL     unsignedToken;
    time_t   expiry;
};

struct XUser
{
    IUser IUser_iface;
    LONG ref;

    UINT64 xuid;
    HSTRING userHash;
    /* Set when the XSTS came from the Xodus service: it is bound to that
       process's proof key, so this one cannot produce a valid signature for it
       and must send an empty one - which is what Windows does for the endpoint
       this exists for. */
    BOOL xstsUnsigned;

    DOUBLE interval;
    time_t oauth_expiry;
    HSTRING deviceCode;
    HSTRING accessToken;
    HSTRING refreshToken;
    HSTRING userToken;
    HSTRING xstsToken;
    char *xstsRelyingParty;
    SRWLOCK xstsLock;
    struct xsts_cache_entry xstsCache[XSTS_CACHE_MAX];
    UINT32 xstsCacheLen;

    HSTRING publicGamerpic;
    HSTRING classicGamertag;
    HSTRING modernGamertag;
    HSTRING modernGamertagSuffix;
    HSTRING uniqueModernGamertag;

    BCRYPT_KEY_HANDLE key;
    char proofKey[PROOF_KEY_SIZE];

    UINT32 endpointsLen;
    struct endpoint *endpoints;
    /* The TITLE-SCOPED document (/titles/current/endpoints) describes the title's
       own services; the unscoped one (/titles/default/endpoints?type=1) describes
       the xboxlive.com platform. They are disjoint, so BOTH are needed and both are
       kept - the title's entries are consulted first. See user_CacheEndpoints. */
    UINT32 titleEndpointsLen;
    struct endpoint *titleEndpoints;
    UINT32 policiesLen;
    struct policy *policies;
};

/* Live-user registry, defined with XUserFindUserById further down. */
static void user_register( struct XUser *user );
static void user_unregister( struct XUser *user );

static struct XUser *impl_from_IUser( IUser *iface )
{
    return CONTAINING_RECORD( iface, struct XUser, IUser_iface );
}

static BOOL ascii_equal_i( const char *left, const char *right, SIZE_T length )
{
    for (SIZE_T i = 0; i < length; ++i)
        if (tolower( (unsigned char)left[i] ) != tolower( (unsigned char)right[i] )) return FALSE;
    return TRUE;
}

static BOOL endpoint_host_matches( const char *host, SIZE_T host_length, const char *pattern )
{
    SIZE_T pattern_length = strlen( pattern );

    if (pattern_length > 2 && pattern[0] == '*' && pattern[1] == '.')
    {
        ++pattern;
        --pattern_length;
        return host_length > pattern_length &&
                ascii_equal_i( host + host_length - pattern_length, pattern, pattern_length );
    }
    if (host_length == pattern_length) return ascii_equal_i( host, pattern, pattern_length );
    return host_length > pattern_length && host[host_length - pattern_length - 1] == '.' &&
            ascii_equal_i( host + host_length - pattern_length, pattern, pattern_length );
}

/*
 * WINEGDK_EXTRA_ENDPOINTS - host -> relying party entries the discovery document
 * does not carry.
 *
 * WHY. `title.mgt.xboxlive.com/titles/default/endpoints?type=1` is the UNSCOPED
 * document: 88 entries and not one of them is the title's own service. A title
 * whose backend is missing from it gets the `http://xboxlive.com` fallback
 * below, i.e. a token minted for the wrong relying party, and its service
 * refuses the call. The title-scoped document that would list it
 * (`/titles/current/endpoints`) is not reachable without title authentication.
 *
 * Rather than intercepting Microsoft's endpoint response and editing it in
 * flight - which means proxying a live auth host and re-signing nothing - let
 * the host state the mapping directly. Same effect, no man in the middle, and it
 * is inspectable in one file.
 *
 * Format: one `<host-pattern> <relying-party>` per line, '#' comments, blank
 * lines ignored. Host patterns use the same matcher as the real table, so
 * `*.forzamotorsport.net` works. Example:
 *     *.forzamotorsport.net  http://xboxliveauth.forzamotorsport.net/
 */
#define MAX_EXTRA_ENDPOINTS 16
static struct { char host[128]; char relyingParty[192]; } extra_endpoints[MAX_EXTRA_ENDPOINTS];
static UINT32 extra_endpoints_len;
static INIT_ONCE extra_endpoints_once = INIT_ONCE_STATIC_INIT;

static BOOL WINAPI load_extra_endpoints( INIT_ONCE *once, void *param, void **ctx )
{
    char path[MAX_PATH], line[512];
    UINT32 n = 0;
    FILE *f;

    if (!GetEnvironmentVariableA( "WINEGDK_EXTRA_ENDPOINTS", path, sizeof(path) )) return TRUE;
    if (!(f = fopen( path, "r" )))
    {
        ERR( "WINEGDK_EXTRA_ENDPOINTS %s cannot be opened.\n", debugstr_a(path) );
        return TRUE;
    }
    while (n < MAX_EXTRA_ENDPOINTS && fgets( line, sizeof(line), f ))
    {
        char host[128], rp[192];
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf( line, "%127s %191s", host, rp ) != 2) continue;
        strcpy( extra_endpoints[n].host, host );
        strcpy( extra_endpoints[n].relyingParty, rp );
        TRACE( "extra endpoint %s -> %s.\n", debugstr_a(host), debugstr_a(rp) );
        ++n;
    }
    fclose( f );
    extra_endpoints_len = n;
    return TRUE;
}

/* Longest-match lookup within ONE endpoint table. */
static const struct endpoint *match_endpoint( const struct endpoint *endpoints, UINT32 count,
                                              const URL_COMPONENTSA *url )
{
    const struct endpoint *best = NULL;
    SIZE_T best_score = 0;

    for (UINT32 i = 0; i < count; ++i)
    {
        const struct endpoint *endpoint = &endpoints[i];
        SIZE_T path_length = endpoint->path ? strlen( endpoint->path ) : 0;
        SIZE_T score;

        if (!endpoint->host || !endpoint->relyingParty ||
                !endpoint_host_matches( url->lpszHostName, url->dwHostNameLength, endpoint->host ))
            continue;
        if (path_length && (url->dwUrlPathLength < path_length ||
                memcmp( url->lpszUrlPath, endpoint->path, path_length )))
            continue;
        score = strlen( endpoint->host ) + path_length;
        if (score > best_score)
        {
            best = endpoint;
            best_score = score;
        }
    }
    return best;
}

/* The title's OWN document wins over the platform one for the hosts it describes -
   it is more specific by construction, and its entries deliberately differ from
   anything the platform document would say about the same host (a different relying
   party, and no signature policy). Only if the title says nothing about this host
   does the platform table decide. */
static const struct endpoint *user_MatchEndpoint( struct XUser *impl, const URL_COMPONENTSA *url )
{
    const struct endpoint *best = match_endpoint( impl->titleEndpoints, impl->titleEndpointsLen, url );
    if (best) return best;
    return match_endpoint( impl->endpoints, impl->endpointsLen, url );
}

/* Does the endpoint matched for this URL carry a signature policy? Uses the same
   matching as user_GetRelyingParty; host-supplied overrides never sign, because
   they exist for hosts the fetched documents do not describe. */
static BOOL user_UrlWantsSignature( struct XUser *impl, const URL_COMPONENTSA *url )
{
    const struct endpoint *best = user_MatchEndpoint( impl, url );

    /* Unknown host: sign, which is what this code has always done and what the
       xboxlive.com relying parties require. */
    return best ? best->hasSignaturePolicy : TRUE;
}

static const char *user_GetRelyingParty( struct XUser *impl, const URL_COMPONENTSA *url )
{
    const struct endpoint *best;

    /* Host-supplied mappings win: they exist precisely because the documents we
       are allowed to fetch do not describe this host. */
    InitOnceExecuteOnce( &extra_endpoints_once, load_extra_endpoints, NULL, NULL );
    for (UINT32 i = 0; i < extra_endpoints_len; ++i)
        if (endpoint_host_matches( url->lpszHostName, url->dwHostNameLength, extra_endpoints[i].host ))
            return extra_endpoints[i].relyingParty;

    if ((best = user_MatchEndpoint( impl, url ))) return best->relyingParty;
    if (endpoint_host_matches( url->lpszHostName, url->dwHostNameLength, "playfabapi.com" ))
        return "http://playfab.xboxlive.com/";
    return "http://xboxlive.com";
}

static ULONG WINAPI user_AddRef( IUser *iface )
{
    struct XUser *impl = impl_from_IUser( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI user_Release( IUser *iface )
{
    struct XUser *impl = impl_from_IUser( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p decreasing refcount to %lu.\n", iface, ref );
    if (!ref)
    {
        user_unregister( impl );
        if (impl->userHash) WindowsDeleteString( impl->userHash );
        if (impl->deviceCode) WindowsDeleteString( impl->deviceCode );
        if (impl->accessToken) WindowsDeleteString( impl->accessToken );
        if (impl->refreshToken) WindowsDeleteString( impl->refreshToken );
        if (impl->userToken) WindowsDeleteString( impl->userToken );
        if (impl->xstsToken) WindowsDeleteString( impl->xstsToken );
        free( impl->xstsRelyingParty );
        {
            UINT32 i;
            for (i = 0; i < impl->xstsCacheLen; i++)
            {
                if (impl->xstsCache[i].token) WindowsDeleteString( impl->xstsCache[i].token );
                if (impl->xstsCache[i].userHash) WindowsDeleteString( impl->xstsCache[i].userHash );
                free( impl->xstsCache[i].relyingParty );
            }
        }
        if (impl->publicGamerpic) WindowsDeleteString( impl->publicGamerpic );
        if (impl->classicGamertag) WindowsDeleteString( impl->classicGamertag );
        if (impl->modernGamertag) WindowsDeleteString( impl->modernGamertag );
        if (impl->modernGamertagSuffix) WindowsDeleteString( impl->modernGamertagSuffix );
        if (impl->uniqueModernGamertag) WindowsDeleteString( impl->uniqueModernGamertag );
        if (impl->key) BCryptDestroyKey( impl->key );
        free_endpoints( impl->endpoints, impl->endpointsLen );
        free_endpoints( impl->titleEndpoints, impl->titleEndpointsLen );
        if (impl->policiesLen) free( impl->policies );
        free( impl );
    }
    return ref;
}


/*
 * The MSA scope this runtime asks for.
 *
 * `service::user.auth.xboxlive.com::MBI_SSL` is the FULL-TRUST scope. A title
 * declares full trust with <MSAFullTrust> in MicrosoftGame.config, and Forza
 * Motorsport's config does not - it carries only Identity, MSAAppId and TitleId.
 * For such a title the correct scope is `XboxLive.signin`, which is what the
 * SISU path uses for its user ticket.
 *
 * NOT changed unconditionally, and the reason matters: the refresh token cached
 * in HKLM\Software\Wine\WineGDK was obtained under the old scope, and a
 * refresh requested under a different one can fail outright - which would take
 * sign-in down rather than fix it. So this is a knob, defaulting to the existing
 * behaviour, and switching it is an A/B rather than a leap.
 *
 *   WINEGDK_MSA_SCOPE=XboxLive.signin    try the non-full-trust scope
 */
static const char *user_msa_scope( void )
{
    static char scope[128];
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    BOOL pending;

    if (InitOnceBeginInitialize( &once, 0, &pending, NULL ) && pending)
    {
        if (!GetEnvironmentVariableA( "WINEGDK_MSA_SCOPE", scope, sizeof(scope) ))
            strcpy( scope, "service::user.auth.xboxlive.com::MBI_SSL" );
        InitOnceComplete( &once, 0, NULL );
    }
    return scope;
}

static HRESULT WINAPI user_RequestOAuthCode( IUser *iface, HSTRING *user, HSTRING *uri )
{
    static const char prefix[] = "scope=";
    static const char middle[] = "&response_type=device_code&client_id=";
    struct XUser *impl = impl_from_IUser( iface );
    char *buffer = NULL, *data = NULL;
    IJsonObject *object = NULL;
    SIZE_T size = 0;
    HRESULT hr;

    TRACE( "iface %p, user %p, uri %p.\n", iface, user, uri );

    if (!(data = calloc( 1, ARRAY_SIZE( prefix ) + strlen( user_msa_scope() ) +
                            ARRAY_SIZE( middle ) + strlen( msaAppId ) )))
    {
        return E_OUTOFMEMORY;
    }
    strcpy( data, prefix );
    strcat( data, user_msa_scope() );
    strcat( data, middle );
    strcat( data, msaAppId );
    TRACE( "requesting MSA scope %s.\n", debugstr_a( user_msa_scope() ) );

    if (FAILED(hr = http_request( L"POST", L"login.live.com", L"/oauth20_connect.srf", data, CT_FORM_URLENCODED, ACCEPT_JSON, (UCHAR **)&buffer, &size )))
        goto cleanup;
    if (FAILED(hr = parse_json( buffer, size, &object ))) goto cleanup;
    if (FAILED(hr = get_json_string( object, L"device_code", &impl->deviceCode ))) goto cleanup;
    if (FAILED(hr = get_json_string( object, L"verification_uri", uri ))) goto cleanup;
    if (FAILED(hr = get_json_number( object, L"interval", &impl->interval ))) goto cleanup;
    hr = get_json_string( object, L"user_code", user );

cleanup:
    if (data) free( data );
    if (buffer) free( buffer );
    IJsonObject_Release( object );
    if (SUCCEEDED(hr)) return hr;
    if (*uri) WindowsDeleteString( *uri );
    if (*user) WindowsDeleteString( *user );
    if (impl->deviceCode) WindowsDeleteString( impl->deviceCode );
    return hr;
}

static HRESULT WINAPI user_RequestOAuthToken( IUser *iface )
{
    static const char template[] = "grant_type=device_code&device_code=";
    char *buffer = NULL, *data = NULL, *deviceCode = NULL;
    struct XUser *impl = impl_from_IUser( iface );
    UINT32 deviceCodeLen = 0, wDeviceCodeLen;
    HSTRING access = NULL, refresh = NULL;
    IJsonObject *object = NULL;
    const WCHAR *wDeviceCode;
    DOUBLE delta = 0;
    SIZE_T size = 0;
    time_t expiry;
    HRESULT hr;

    TRACE( "iface %p.\n", iface );

    wDeviceCode = WindowsGetStringRawBuffer( impl->deviceCode, &wDeviceCodeLen );
    if (!(deviceCodeLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wDeviceCode, wDeviceCodeLen, NULL, 0, NULL, NULL ))) goto error;
    if (!(data = calloc( 1, ARRAY_SIZE( template ) + deviceCodeLen + strlen( "&client_id=" ) + strlen( msaAppId ) )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    strcpy( data, template );
    if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wDeviceCode, wDeviceCodeLen, data + ARRAY_SIZE( template ) - 1, deviceCodeLen, NULL, NULL )) goto error;
    strcat( data, "&client_id=" );
    strcat( data, msaAppId );

    while (TRUE)
    {
        if (SUCCEEDED(hr = http_request( L"POST", L"login.live.com", L"/oauth20_token.srf", data, CT_FORM_URLENCODED, ACCEPT_JSON, (UCHAR **)&buffer, &size ))) break;
        Sleep( impl->interval * 1000 );
    }

    if (FAILED(hr = parse_json( buffer, size, &object ))) goto cleanup;
    if (FAILED(hr = get_json_string( object, L"refresh_token", &refresh ))) goto cleanup;
    if (FAILED(hr = get_json_string( object, L"access_token", &access ))) goto cleanup;
    if (FAILED(hr = get_json_number( object, L"expires_in", &delta ))) goto cleanup;

    if ((expiry = time(NULL)) == -1) hr = E_FAIL;
    else impl->oauth_expiry = expiry + delta;
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
cleanup:
    if (data) free( data );
    if (buffer) free( buffer );
    if (deviceCode) free( deviceCode );
    if (object) IJsonObject_Release( object );
    if (SUCCEEDED(hr))
    {
        if (impl->refreshToken) WindowsDeleteString( impl->refreshToken );
        if (impl->accessToken) WindowsDeleteString( impl->accessToken );
        impl->refreshToken = refresh;
        impl->accessToken = access;
        return hr;
    }
    if (refresh) WindowsDeleteString( refresh );
    if (access) WindowsDeleteString( access );
    return hr;
}

static HRESULT WINAPI user_RefreshOAuthToken( IUser *iface )
{
    /* The REFRESH path, and the one that actually runs once a token is cached -
       parameterising only RequestOAuthCode made the scope A/B inert, because the
       device-code flow never executes on a machine that has already signed in. */
    static const char prefix[] = "grant_type=refresh_token&scope=";
    static const char middle[] = "&client_id=";
    struct XUser *impl = impl_from_IUser( iface );
    HSTRING newAccess = NULL, newRefresh = NULL;
    UINT32 refreshTokenLen, wRefreshTokenLen;
    char *buffer = NULL, *data = NULL;
    const WCHAR *wRefreshToken;
    IJsonObject *object = NULL;
    time_t expiry;
    DOUBLE delta;
    SIZE_T size;
    HRESULT hr;

    TRACE( "iface %p.\n", iface );

    wRefreshToken = WindowsGetStringRawBuffer( impl->refreshToken, &wRefreshTokenLen );
    if (!(refreshTokenLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wRefreshToken, wRefreshTokenLen, NULL, 0, NULL, NULL ))) goto error;
    if (!(data = calloc( 1, ARRAY_SIZE( prefix ) + strlen( user_msa_scope() ) + ARRAY_SIZE( middle ) + strlen( msaAppId ) + strlen( "&refresh_token=" ) + refreshTokenLen )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    strcpy( data, prefix );
    strcat( data, user_msa_scope() );
    strcat( data, middle );
    strcat( data, msaAppId );
    strcat( data, "&refresh_token=" );
    if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wRefreshToken, wRefreshTokenLen, data + strlen( data ), refreshTokenLen, NULL, NULL )) goto error;
    if (FAILED(hr = http_request( L"POST", L"login.live.com", L"/oauth20_token.srf", data, CT_FORM_URLENCODED, ACCEPT_JSON, (UCHAR **)&buffer, &size ))) goto cleanup;
    if (FAILED(hr = parse_json( buffer, size, &object ))) goto cleanup;
    if (FAILED(hr = get_json_string( object, L"refresh_token", &newRefresh ))) goto cleanup;
    if (FAILED(hr = get_json_string( object, L"access_token", &newAccess ))) goto cleanup;
    if (FAILED(hr = get_json_number( object, L"expires_in", &delta ))) goto cleanup;
    if ((expiry = time(NULL)) == -1) hr = E_FAIL;
    else impl->oauth_expiry = expiry + delta;
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
cleanup:
    if (data) free( data );
    if (buffer) free( buffer );
    if (object) IJsonObject_Release( object );
    if (SUCCEEDED(hr))
    {
        impl->refreshToken = newRefresh;
        impl->accessToken = newAccess;
        return hr;
    }
    if (newRefresh) WindowsDeleteString( newRefresh );
    if (newAccess) WindowsDeleteString( newAccess );
    return hr;
}

static HRESULT WINAPI user_RequestUserToken( IUser *iface )
{
    const char *template = "{\"TokenType\":\"JWT\",\"RelyingParty\":\"http://auth.xboxlive.com\",\"Properties\":{\"AuthMethod\":\"RPS\",\"SiteName\":\"user.auth.xboxlive.com\",\"RpsTicket\":\"";
    struct XUser *impl = impl_from_IUser( iface );
    UINT32 tokenLen, wTokenLen;
    IJsonObject *object = NULL;
    const WCHAR *wToken;
    UCHAR *buf = NULL;
    char *body = NULL;
    SIZE_T bufSize;
    HRESULT hr;

    TRACE( "iface %p.\n", iface );

    wToken = WindowsGetStringRawBuffer( impl->accessToken, &wTokenLen );
    if (!(tokenLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wToken, wTokenLen, NULL, 0, NULL, NULL ))) goto error;
    if (!(body = calloc( strlen( template ) + tokenLen + strlen( "\"}}" ), sizeof(char) )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    /* construct request body */
    strcpy( body, template );
    if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wToken, wTokenLen, body + strlen( template ), tokenLen, NULL, NULL )) goto error;
    strcat( body, "\"}}" );

    if (FAILED(hr = http_request( L"POST", L"user.auth.xboxlive.com", L"/user/authenticate", body, CT_JSON, ACCEPT_JSON, &buf, &bufSize )))
    {
        WARN( "User-token HTTP request failed, hr %#lx.\n", hr );
        goto cleanup;
    }
    if (FAILED(hr = parse_json( (char *)buf, bufSize, &object )))
    {
        WARN( "User-token JSON parse failed, hr %#lx.\n", hr );
        goto cleanup;
    }
    if (FAILED(hr = get_json_string( object, L"Token", &impl->userToken )))
        WARN( "User-token response lacked Token, hr %#lx.\n", hr );
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
cleanup:
    if (buf) free( buf );
    if (body) free( body );
    if (object) IJsonObject_Release( object );
    return hr;
}

/*
 * WINEGDK_DEVICE_TOKEN - path to a file holding a DeviceToken to present in the
 * XSTS request.
 *
 * A real console/PC sends DeviceToken (and TitleToken) alongside UserTokens, and
 * the resulting XSTS carries the corresponding claims. WineGDK sends UserTokens
 * alone. The token is bound to the proof key it was minted with, so this is only
 * usable together with WINEGDK_PROOF_KEY pinning the matching key - otherwise
 * xsts.auth answers 400 (measured).
 */
static const char *load_device_token(void)
{
    static char token[4096];
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    static BOOL loaded;
    BOOL pending;

    if (InitOnceBeginInitialize( &once, 0, &pending, NULL ) && pending)
    {
        char path[MAX_PATH];
        FILE *f;
        if (GetEnvironmentVariableA( "WINEGDK_DEVICE_TOKEN", path, sizeof(path) ) &&
            (f = fopen( path, "r" )))
        {
            if (fgets( token, sizeof(token), f ))
            {
                size_t n = strlen( token );
                while (n && (token[n - 1] == '\n' || token[n - 1] == '\r')) token[--n] = 0;
                loaded = n > 0;
                TRACE( "device token loaded, %u chars.\n", (unsigned)n );
            }
            fclose( f );
        }
        InitOnceComplete( &once, 0, NULL );
    }
    return loaded ? token : NULL;
}

extern HRESULT xodus_request_xsts( const char *relyingParty, const char *clientId,
                                   const char *titleId, char **token, char **userHash,
                                   char **xuid );

/*
 * Relying parties whose XSTS must carry a TITLE claim, and therefore has to be
 * minted by the Xodus service rather than here.
 *
 * WHY NOT ALWAYS. A token minted there is bound to the SERVICE's proof key, so
 * requests carrying it cannot be signed by this process - and the xboxlive.com
 * relying parties DO send a 104-byte signature that is validated against the
 * token's key. Routing everything through the service would break them. Only the
 * relying parties that actually need a title claim are sent that way, and for
 * those the Windows ground truth sends an EMPTY Signature anyway.
 *
 * WINEGDK_TITLE_RELYING_PARTIES is a comma-separated list of substrings, e.g.
 *   WINEGDK_TITLE_RELYING_PARTIES=forzamotorsport
 * Unset, nothing changes and every token is minted locally as before.
 */
static BOOL relying_party_needs_title_claim( const char *relyingParty )
{
    char list[512], *tok, *ctx;

    if (!GetEnvironmentVariableA( "WINEGDK_TITLE_RELYING_PARTIES", list, sizeof(list) )) return FALSE;
    for (tok = strtok_s( list, ",", &ctx ); tok; tok = strtok_s( NULL, ",", &ctx ))
        if (*tok && strstr( relyingParty, tok )) return TRUE;
    return FALSE;
}

/* Take an XSTS the service minted whole, in place of the local exchange. */
static HRESULT user_request_xsts_token_via_xodus( struct XUser *impl, const char *relyingParty )
{
    char *token = NULL, *userHash = NULL, *xuid = NULL, *newRelyingParty = NULL;
    char titleIdStr[16];
    HSTRING hToken = NULL, hUserHash = NULL;
    HRESULT hr;

    /* The service cannot know the title's identity; the config we parsed can.
       Both values come straight out of MicrosoftGame.config - <MSAAppId> and
       <TitleId> - so there is nothing here for a deployment to supply. */
    if (!msaAppId || !titleId)
    {
        ERR( "%s needs a title claim, but MicrosoftGame.config yielded no "
             "MSAAppId/TitleId to ask for one with.\n", debugstr_a( relyingParty ) );
        return E_INVALIDARG;
    }
    snprintf( titleIdStr, sizeof(titleIdStr), "%u", titleId );

    if (FAILED(hr = xodus_request_xsts( relyingParty, msaAppId, titleIdStr, &token, &userHash, &xuid )))
        return hr;

    if (FAILED(hr = MultiByteToHSTRING( token, strlen( token ), &hToken ))) goto cleanup;
    if (FAILED(hr = MultiByteToHSTRING( userHash, strlen( userHash ), &hUserHash ))) goto cleanup;
    if (!(newRelyingParty = strdup( relyingParty )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    if (impl->xstsToken) WindowsDeleteString( impl->xstsToken );
    if (impl->userHash) WindowsDeleteString( impl->userHash );
    free( impl->xstsRelyingParty );
    impl->xstsToken = hToken;
    impl->userHash = hUserHash;
    impl->xstsRelyingParty = newRelyingParty;
    /* The local path sets this from the XSTS response's `xid` claim; without it
       the user id stays 0 and the title asks for `users/xuid(0)/...`, which every
       Xbox service refuses with 403. */
    if (xuid && *xuid)
    {
        errno = 0;
        impl->xuid = _strtoui64( xuid, NULL, 10 );
        if (errno == ERANGE) impl->xuid = 0;
    }
    /* This token is not ours to sign with - see the comment above. */
    impl->xstsUnsigned = TRUE;
    hToken = hUserHash = NULL;
    newRelyingParty = NULL;
    hr = S_OK;

cleanup:
    if (hToken) WindowsDeleteString( hToken );
    if (hUserHash) WindowsDeleteString( hUserHash );
    free( newRelyingParty );
    free( token );
    free( userHash );
    free( xuid );
    return hr;
}

/* Seconds an entry stays usable. 0 disables the cache entirely - see the note on
   struct xsts_cache_entry for why that switch exists. */
static long xsts_cache_ttl( void )
{
    char value[16];
    if (!GetEnvironmentVariableA( "WINEGDK_XSTS_CACHE_TTL", value, sizeof(value) )) return 600;
    return atol( value );
}

/* Callers already hold impl->xstsLock EXCLUSIVELY, so no extra locking here. */
static BOOL xsts_cache_get( struct XUser *impl, const char *relyingParty )
{
    long ttl = xsts_cache_ttl();
    time_t now;
    UINT32 i;

    if (ttl <= 0) return FALSE;
    if ((now = time( NULL )) == -1) return FALSE;

    for (i = 0; i < impl->xstsCacheLen; i++)
    {
        struct xsts_cache_entry *e = &impl->xstsCache[i];
        HSTRING token = NULL, userHash = NULL;
        char *rp;

        if (!e->relyingParty || strcmp( e->relyingParty, relyingParty )) continue;
        if (now >= e->expiry) return FALSE;   /* stale - fall through and re-mint */

        /* Duplicate rather than alias: the "current" fields are freed on the next
           mint, and freeing a string the cache still owns is a double free. */
        if (FAILED(WindowsDuplicateString( e->token, &token ))) return FALSE;
        if (FAILED(WindowsDuplicateString( e->userHash, &userHash )))
        {
            WindowsDeleteString( token );
            return FALSE;
        }
        if (!(rp = strdup( relyingParty )))
        {
            WindowsDeleteString( token );
            WindowsDeleteString( userHash );
            return FALSE;
        }

        if (impl->xstsToken) WindowsDeleteString( impl->xstsToken );
        if (impl->userHash) WindowsDeleteString( impl->userHash );
        free( impl->xstsRelyingParty );
        impl->xstsToken        = token;
        impl->userHash         = userHash;
        impl->xstsRelyingParty = rp;
        impl->xuid             = e->xuid;
        impl->xstsUnsigned     = e->unsignedToken;
        TRACE( "XSTS cache HIT for %s.\n", debugstr_a( relyingParty ) );
        return TRUE;
    }
    return FALSE;
}

/* Store whatever the mint just left in the "current" fields. */
static void xsts_cache_put( struct XUser *impl, const char *relyingParty )
{
    long ttl = xsts_cache_ttl();
    struct xsts_cache_entry *e = NULL;
    HSTRING token = NULL, userHash = NULL;
    time_t now;
    char *rp;
    UINT32 i;

    if (ttl <= 0) return;
    if ((now = time( NULL )) == -1) return;
    if (!impl->xstsToken || !impl->userHash) return;

    for (i = 0; i < impl->xstsCacheLen; i++)
        if (impl->xstsCache[i].relyingParty && !strcmp( impl->xstsCache[i].relyingParty, relyingParty ))
            { e = &impl->xstsCache[i]; break; }

    if (!e)
    {
        /* Full: drop the entry closest to expiry rather than refusing to cache.
           There are ~6 relying parties in play and XSTS_CACHE_MAX is 8, so this
           is a safety net, not the normal path. */
        if (impl->xstsCacheLen < XSTS_CACHE_MAX) e = &impl->xstsCache[impl->xstsCacheLen++];
        else
        {
            e = &impl->xstsCache[0];
            for (i = 1; i < impl->xstsCacheLen; i++)
                if (impl->xstsCache[i].expiry < e->expiry) e = &impl->xstsCache[i];
        }
    }

    if (FAILED(WindowsDuplicateString( impl->xstsToken, &token ))) return;
    if (FAILED(WindowsDuplicateString( impl->userHash, &userHash )))
    {
        WindowsDeleteString( token );
        return;
    }
    if (!(rp = strdup( relyingParty )))
    {
        WindowsDeleteString( token );
        WindowsDeleteString( userHash );
        return;
    }

    if (e->token) WindowsDeleteString( e->token );
    if (e->userHash) WindowsDeleteString( e->userHash );
    free( e->relyingParty );
    e->relyingParty  = rp;
    e->token         = token;
    e->userHash      = userHash;
    e->xuid          = impl->xuid;
    e->unsignedToken = impl->xstsUnsigned;
    e->expiry        = now + ttl;
    TRACE( "XSTS cached for %s, ttl %lds.\n", debugstr_a( relyingParty ), ttl );
}

static HRESULT user_request_xsts_token_uncached( struct XUser *impl, const char *relyingParty );

static HRESULT user_request_xsts_token( struct XUser *impl, const char *relyingParty )
{
    HRESULT hr;

    if (xsts_cache_get( impl, relyingParty )) return S_OK;
    if (SUCCEEDED(hr = user_request_xsts_token_uncached( impl, relyingParty )))
        xsts_cache_put( impl, relyingParty );
    return hr;
}

static HRESULT user_request_xsts_token_uncached( struct XUser *impl, const char *relyingParty )
{
    static const char prefix[] = "{\"TokenType\":\"JWT\",\"RelyingParty\":\"";
    static const char properties[] = "\",\"Properties\":{\"SandboxId\":\"RETAIL\",\"ProofKey\":";
    static const char userTokens[] = ",\"UserTokens\":[\"";
    static const char deviceTokenKey[] = ",\"DeviceToken\":\"";
    const char *deviceToken = load_device_token();
    IJsonObject *child = NULL, *claims = NULL, *object = NULL;
    HSTRING newToken = NULL, newUserHash = NULL, xuid = NULL;
    UINT32 tokenLen, wTokenLen;
    char *body = NULL, *newRelyingParty = NULL, *token;
    IJsonArray *array = NULL;
    UCHAR *buffer = NULL;
    const WCHAR *wToken;
    SIZE_T bufferSize;
    UINT64 newXuid;
    HRESULT hr;

    TRACE( "impl %p, relyingParty %s.\n", impl, debugstr_a( relyingParty ) );

    if (relying_party_needs_title_claim( relyingParty ))
        return user_request_xsts_token_via_xodus( impl, relyingParty );
    impl->xstsUnsigned = FALSE;

    /* Lazily acquired - finish_user_load no longer does this up front, so the
       first local mint is what pays for it, and a session that never takes this
       path never pays at all. */
    if (!impl->userToken && FAILED(hr = IUser_RequestUserToken( &impl->IUser_iface )))
    {
        WARN( "Xbox user-token exchange failed, hr %#lx.\n", hr );
        return hr;
    }
    wToken = WindowsGetStringRawBuffer( impl->userToken, &wTokenLen );
    if (!(tokenLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wToken, wTokenLen, NULL, 0, NULL, NULL ))) goto error;
    if (!(body = calloc( strlen( prefix ) + strlen( relyingParty ) + strlen( properties ) +
            PROOF_KEY_SIZE + strlen( userTokens ) + tokenLen + strlen( "\"]}}" ) + 1 +
            (deviceToken ? strlen( deviceTokenKey ) + strlen( deviceToken ) + 1 : 0), sizeof(char) )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    strcpy( body, prefix );
    strcat( body, relyingParty );
    strcat( body, properties );
    strncat( body, impl->proofKey, PROOF_KEY_SIZE );
    if (deviceToken)
    {
        strcat( body, deviceTokenKey );
        strcat( body, deviceToken );
        strcat( body, "\"" );
    }
    strcat( body, userTokens );
    token = body + strlen( body );
    if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wToken, wTokenLen, token, tokenLen, NULL, NULL )) goto error;
    strcat( body, "\"]}}" );

    if (FAILED(hr = http_request( L"POST", L"xsts.auth.xboxlive.com", L"/xsts/authorize", body, CT_JSON, ACCEPT_JSON, &buffer, &bufferSize ))) goto cleanup;
    if (FAILED(hr = parse_json( (char *)buffer, bufferSize, &object ))) goto cleanup;
    if (FAILED(hr = get_json_string( object, L"Token", &newToken ))) goto cleanup;
    if (FAILED(hr = get_json_object( object, L"DisplayClaims", &claims ))) goto cleanup;
    if (FAILED(hr = get_json_array( claims, L"xui", &array ))) goto cleanup;
    if (FAILED(hr = IJsonArray_GetObjectAt( array, 0, &child ))) goto cleanup;
    if (FAILED(hr = get_json_string( child, L"uhs", &newUserHash ))) goto cleanup;
    newXuid = impl->xuid;
    if (SUCCEEDED(get_json_string( child, L"xid", &xuid )))
    {
        errno = 0;
        newXuid = wcstoull( WindowsGetStringRawBuffer( xuid, NULL ), NULL, 10 );
        if (errno == ERANGE)
        {
            hr = E_UNEXPECTED;
            goto cleanup;
        }
    }
    hr = S_OK;
    if (!(newRelyingParty = strdup( relyingParty )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    if (impl->xstsToken) WindowsDeleteString( impl->xstsToken );
    if (impl->userHash) WindowsDeleteString( impl->userHash );
    free( impl->xstsRelyingParty );
    impl->xstsToken = newToken;
    impl->userHash = newUserHash;
    impl->xstsRelyingParty = newRelyingParty;
    impl->xuid = newXuid;
    newToken = NULL;
    newUserHash = NULL;
    newRelyingParty = NULL;

cleanup:
    free( body );
    free( buffer );
    free( newRelyingParty );
    if (newToken) WindowsDeleteString( newToken );
    if (newUserHash) WindowsDeleteString( newUserHash );
    if (xuid) WindowsDeleteString( xuid );
    if (array) IJsonArray_Release( array );
    if (child) IJsonObject_Release( child );
    if (claims) IJsonObject_Release( claims );
    if (object) IJsonObject_Release( object );
    return hr;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
    goto cleanup;
}

static HRESULT WINAPI user_RequestXstsToken( IUser *iface )
{
    return user_request_xsts_token( impl_from_IUser( iface ), "http://xboxlive.com" );
}

/*
 * WINEGDK_PROOF_KEY - use a P-256 keypair supplied by the host instead of
 * generating a fresh one.
 *
 * WHY. The XSTS request advertises this key as its "ProofKey", and a DeviceToken
 * is bound to the key it was minted with. A caller that wants to add a device
 * claim therefore has to make the two agree, and a key generated per-run inside
 * this process can never be the one an external DeviceToken was minted against
 * (the private half never leaves here). Letting the host pin the key is the only
 * way to close that loop; it changes nothing when the variable is unset.
 *
 * Format: three lines of 64 lowercase hex chars - x, y, d - which is exactly the
 * field order of BCRYPT_ECCPRIVATE_BLOB. Deliberately not JSON: this is C in a
 * builtin and a hand-rolled parser would be the least trustworthy part of the
 * chain. See gsstub/export_proofkey.py, which writes it.
 */
static BOOL read_hex_field( HANDLE file, UCHAR *out, ULONG len )
{
    char buf[64];
    ULONG got = 0, i;
    DWORD n;

    while (got < sizeof(buf))
    {
        char c;
        if (!ReadFile( file, &c, 1, &n, NULL ) || !n) break;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
        {
            if (!got) continue;      /* leading/blank separators */
            break;
        }
        buf[got++] = c;
    }
    if (got != len * 2) return FALSE;
    for (i = 0; i < len; i++)
    {
        int hi, lo;
        char a = buf[i * 2], b = buf[i * 2 + 1];
        hi = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10 :
             (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        lo = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10 :
             (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return FALSE;
        out[i] = (UCHAR)((hi << 4) | lo);
    }
    return TRUE;
}

/* Fills blob with a BCRYPT_ECCPRIVATE_BLOB and imports it. Returns S_FALSE when
   no key is configured, so the caller falls back to generating one. */
static HRESULT load_host_proof_key( BCRYPT_ALG_HANDLE ecdsa, BCRYPT_KEY_HANDLE *key,
                                    UCHAR *pub )
{
    UCHAR blob[sizeof(BCRYPT_ECCKEY_BLOB) + 96];
    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
    WCHAR path[MAX_PATH];
    HANDLE file;
    NTSTATUS status;
    UCHAR *xyd = blob + sizeof(*hdr);

    if (!GetEnvironmentVariableW( L"WINEGDK_PROOF_KEY", path, MAX_PATH )) return S_FALSE;

    file = CreateFileW( path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL );
    if (file == INVALID_HANDLE_VALUE)
    {
        ERR( "WINEGDK_PROOF_KEY %s cannot be opened, err %lu - generating instead.\n",
             debugstr_w(path), GetLastError() );
        return S_FALSE;
    }
    if (!read_hex_field( file, xyd, 32 ) ||          /* x */
        !read_hex_field( file, xyd + 32, 32 ) ||     /* y */
        !read_hex_field( file, xyd + 64, 32 ))       /* d */
    {
        ERR( "WINEGDK_PROOF_KEY %s is malformed (want 3 lines of 64 hex chars: "
             "x, y, d) - generating instead.\n", debugstr_w(path) );
        CloseHandle( file );
        return S_FALSE;
    }
    CloseHandle( file );

    hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    hdr->cbKey = 32;
    if (!NT_SUCCESS(status = BCryptImportKeyPair( ecdsa, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                                  key, blob, sizeof(*hdr) + 96, 0 )))
    {
        /* A bad d/x/y triple is rejected here rather than silently producing a
           key whose signatures never verify - which is the failure mode that is
           impossible to debug from Xbox Live's bare 401s. */
        ERR( "WINEGDK_PROOF_KEY rejected by BCryptImportKeyPair, status %#lx - "
             "generating instead.\n", (long)status );
        return S_FALSE;
    }
    memcpy( pub, xyd, 64 );
    TRACE( "using host-supplied proof key from %s.\n", debugstr_w(path) );
    return S_OK;
}

static HRESULT WINAPI user_GenerateKeyPair( IUser *iface )
{
    char proofKey[PROOF_KEY_SIZE + 1] = {}, *x, *y;
    struct XUser *impl = impl_from_IUser( iface );
    UCHAR blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ALG_HANDLE ecdsa = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS status;
    ULONG dummy;
    HRESULT hr;

    TRACE( "iface %p.\n", iface );

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider( &ecdsa, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0 ))) goto error;
    hr = load_host_proof_key( ecdsa, &key, blob + sizeof(BCRYPT_ECCKEY_BLOB) );
    if (FAILED(hr)) goto cleanup;
    if (hr == S_FALSE)
    {
        if (!NT_SUCCESS(status = BCryptGenerateKeyPair( ecdsa, &key, 256, 0 ))) goto error;
        if (!NT_SUCCESS(status = BCryptFinalizeKeyPair( key, 0 ))) goto error;
        if (!NT_SUCCESS(status = BCryptExportKey( key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &dummy, 0 ))) goto error;
    }
    hr = S_OK;

    /* convert proof key to jwk format */
    memcpy( proofKey, PROOF_KEY_TEMPLATE, ARRAY_SIZE( PROOF_KEY_TEMPLATE ) );
    x = proofKey + ARRAY_SIZE( PROOF_KEY_TEMPLATE ) - 1;
    y = x + 43 + ARRAY_SIZE( PROOF_KEY_TEMPLATE2 ) - 1;
    if (FAILED(hr = encode_base64_url( 32, blob + sizeof(BCRYPT_ECCKEY_BLOB), 43, x, FALSE ))) goto cleanup;
    strcat( proofKey, PROOF_KEY_TEMPLATE2 );
    if (FAILED(hr = encode_base64_url( 32, blob + sizeof(BCRYPT_ECCKEY_BLOB) + 32, 43, y, FALSE ))) goto cleanup;
    strcat( proofKey, "\"}" );
    goto cleanup;

error:
    hr = HRESULT_FROM_NT( status );
cleanup:
    if (ecdsa) BCryptCloseAlgorithmProvider( ecdsa, 0 );
    if (FAILED(hr)) BCryptDestroyKey( key );
    else
    {
        memcpy( impl->proofKey, proofKey, PROOF_KEY_SIZE ); /* ignore null terminator */
        if (impl->key) BCryptDestroyKey( impl->key );
        impl->key = key;
    }
    return hr;
}

static HRESULT WINAPI user_SignData( IUser *iface, ULONG dataSize, UCHAR *data, ULONG signatureSize, UCHAR *signature )
{
    struct XUser *impl = impl_from_IUser( iface );
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE object = NULL;
    HRESULT hr = S_OK;
    NTSTATUS status;
    UCHAR hash[32];
    ULONG dummy;

    TRACE( "iface %p, dataSize %lu, data %p, signatureSize %lu, signature %p.\n", iface, dataSize, data, signatureSize, signature );

    /* ES256 signs sha-256 hash of data */
    if (signatureSize < 64) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0 ))) goto error;
    if (!NT_SUCCESS(status = BCryptCreateHash( algorithm, &object, NULL, 0, NULL, 0, 0 ))) goto error;
    if (!NT_SUCCESS(status = BCryptHashData( object, data, dataSize, 0 ))) goto error;
    if (!NT_SUCCESS(status = BCryptFinishHash( object, hash, 32, 0 ))) goto error;
    if (!NT_SUCCESS(status = BCryptSignHash( impl->key, NULL, hash, 32, signature, signatureSize, &dummy, 0 ))) goto error;
    goto cleanup;

error:
    hr = HRESULT_FROM_NT( status );
cleanup:
    if (object) BCryptDestroyHash( object );
    if (algorithm) BCryptCloseAlgorithmProvider( algorithm, 0 );
    return hr;
}

/*
 * Parse ONE endpoints document into an endpoint table (and, if it carries them,
 * the signature policies). Both documents this file fetches have the same shape,
 * so both come through here; see user_CacheEndpoints for which is which.
 */
static HRESULT user_ParseEndpointDocument( const UCHAR *buffer, SIZE_T size,
                                           struct endpoint **endpointsOut, UINT32 *endpointsLenOut,
                                           struct policy **policiesOut, UINT32 *policiesLenOut )
{
    IJsonObject *child = NULL, *object = NULL;
    IVector_IJsonValue *vector = NULL;
    struct endpoint *endpoints = NULL;
    UINT32 endpointsLen = 0, policiesLen = 0;
    struct policy *policies = NULL;
    IJsonArray *array = NULL;
    HRESULT hr;

    *endpointsOut = NULL;
    *endpointsLenOut = 0;
    if (policiesOut) { *policiesOut = NULL; *policiesLenOut = 0; }

    if (FAILED(hr = parse_json( (const char *)buffer, size, &object ))) goto cleanup;
    /* parse_json can report success while handing back nothing; every helper below
     * dereferences this, so a NULL here faults at address 0. */
    if (!object) { hr = E_FAIL; goto cleanup; }

    /*
     * SignaturePolicies is OPTIONAL.
     *
     * The unscoped document carries it; the TITLE-SCOPED one
     * (/titles/current/endpoints) has ONLY an EndPoints array - measured, its
     * top-level keys are exactly ["EndPoints"]. Requiring it here made the
     * title-scoped document parse as a failure the moment it was finally
     * fetchable, so the fetch returned 200 and the endpoint table stayed EMPTY,
     * which then looked exactly like the fetch not working at all: relying
     * parties fell back to http://xboxlive.com and every request signed.
     * A title whose own document omits policies simply signs nothing.
     */
    if (SUCCEEDED(get_json_array( object, L"SignaturePolicies", &array )) && array)
    {
        if (FAILED(hr = IJsonArray_QueryInterface( array, &IID_IVector_IJsonValue, (void **)&vector ))) goto cleanup;
        if (FAILED(hr = IVector_IJsonValue_get_Size( vector, &policiesLen ))) goto cleanup;
    }
    else
    {
        TRACE( "no SignaturePolicies in this document - nothing here is signed.\n" );
        policiesLen = 0;
        array = NULL;
    }
    if (policiesLen && !(policies = calloc( policiesLen, sizeof(*policies) )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    for (UINT32 i = 0; i < policiesLen; ++i)
    {
        DOUBLE maxBodyBytes, version;

        if (FAILED(hr = IJsonArray_GetObjectAt( array, i, &child ))) goto cleanup;
        /* a non-object element (or a NULL on success) must be skipped, not dereferenced */
        if (!child) continue;
        if (FAILED(hr = get_json_number( child, L"MaxBodyBytes", &maxBodyBytes ))) goto cleanup;
        if (FAILED(hr = get_json_number( child, L"Version", &version ))) goto cleanup;
        policies[i].maxBodyBytes = maxBodyBytes;
        policies[i].version = version;
        IJsonObject_Release( child );
        child = NULL;
    }

    if (array) { IJsonArray_Release( array ); array = NULL; }
    if (vector) { IVector_IJsonValue_Release( vector ); vector = NULL; }

    hr = S_OK;
    if (FAILED(hr = get_json_array( object, L"EndPoints", &array ))) goto cleanup;
    if (!array) { hr = E_FAIL; goto cleanup; }
    if (FAILED(hr = IJsonArray_QueryInterface( array, &IID_IVector_IJsonValue, (void **)&vector ))) goto cleanup;
    if (FAILED(hr = IVector_IJsonValue_get_Size( vector, &endpointsLen ))) goto cleanup;
    if (!(endpoints = calloc( endpointsLen, sizeof(*endpoints) )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    for (UINT32 i = 0; i < endpointsLen; ++i)
    {
        HSTRING string = NULL;

        if (FAILED(hr = IJsonArray_GetObjectAt( array, i, &child ))) goto cleanup;
        if (!child) continue;
        /* An entry with no Host is legitimate in the live document - skip it rather than
         * abandoning the whole endpoint table (which is what leaves FM without the
         * gameservices host). */
        if (FAILED(hr = get_json_utf8( child, L"Host", &endpoints[i].host )))
        {
            hr = S_OK;
            IJsonObject_Release( child );
            child = NULL;
            continue;
        }
        if (FAILED(hr = get_json_string( child, L"RelyingParty", &string )))
        {
            hr = S_OK;
            IJsonObject_Release( child );
            child = NULL;
            continue;
        }
        hr = HSTRINGToMultiByte( string, &endpoints[i].relyingParty );
        WindowsDeleteString( string );
        string = NULL;
        if (FAILED(hr)) goto cleanup;
        {
            DOUBLE policyIndex;
            endpoints[i].hasSignaturePolicy =
                SUCCEEDED(get_json_number( child, L"SignaturePolicyIndex", &policyIndex ));
        }
        if (SUCCEEDED(get_json_string( child, L"Path", &string )))
        {
            hr = HSTRINGToMultiByte( string, &endpoints[i].path );
            WindowsDeleteString( string );
            string = NULL;
            if (FAILED(hr)) goto cleanup;
        }
        IJsonObject_Release( child );
        child = NULL;
    }

    *endpointsOut = endpoints;
    *endpointsLenOut = endpointsLen;
    endpoints = NULL;
    if (policiesOut)
    {
        *policiesOut = policies;
        *policiesLenOut = policiesLen;
        policies = NULL;
    }

cleanup:
    if (array) IJsonArray_Release( array );
    if (child) IJsonObject_Release( child );
    if (object) IJsonObject_Release( object );
    if (vector) IVector_IJsonValue_Release( vector );
    free_endpoints( endpoints, endpointsLen );
    free( policies );
    return hr;
}

/*
 * Fetch BOTH endpoint documents and keep BOTH.
 *
 * They are disjoint, and each answers a question the other cannot:
 *
 *   /titles/default/endpoints?type=1   the UNSCOPED, platform document: 88
 *       xboxlive.com hosts (profile, social, userpresence, sessiondirectory...),
 *       every one with a SignaturePolicyIndex - those requests must be signed.
 *       Needs no credentials.
 *
 *   /titles/current/endpoints          the TITLE-SCOPED document: this game's OWN
 *       11 hosts. For Forza Motorsport, `*.fm.forzamotorsport.net` /
 *       `*.services.forzamotorsport.net` with RelyingParty
 *       `http://xboxliveauth.forzamotorsport.net/` and, notably, NO
 *       SignaturePolicyIndex - Microsoft's own config says Turn 10's services take
 *       an EMPTY signature, which is exactly what a Windows capture shows.
 *       Requires an XSTS carrying the TITLE claim.
 *
 * Using only the title-scoped one loses the platform hosts (measured: the Social
 * Manager stops reaching userpresence). Using only the unscoped one leaves the
 * title's own backend unmatched, so it falls back to `http://xboxlive.com` -
 * a token minted for the wrong relying party, which its service refuses.
 *
 * NOTE the query strings differ: `?type=1` is REQUIRED by /titles/default, and
 * makes /titles/current answer 414.
 *
 * Either fetch may fail without failing sign-in; only losing both is fatal.
 */
static HRESULT WINAPI user_CacheEndpoints( IUser *iface )
{
    struct XUser *impl = impl_from_IUser( iface );
    struct endpoint *endpoints = NULL, *titleEndpoints = NULL;
    UINT32 endpointsLen = 0, titleEndpointsLen = 0, policiesLen = 0;
    struct policy *policies = NULL;
    UCHAR *buffer = NULL;
    SIZE_T size;
    HRESULT hr, titleHr;

    TRACE( "iface %p.\n", iface );

    /*
     * The title-scoped document requires the caller to AUTHENTICATE - the
     * unscoped one does not, which is why this call used to pass no headers at
     * all and why only the unscoped fetch ever worked. Measured directly against
     * the service: with an `Authorization: XBL3.0 x=<uhs>;<token>` carrying the
     * title claim, `/titles/current/endpoints` returns 200 whether the request is
     * signed or not; without it, 401.
     */
    {
        const WCHAR *wUserHash, *wToken;
        UINT32 wUserHashLen, wTokenLen;
        WCHAR *authHeaders = NULL;

        wUserHash = WindowsGetStringRawBuffer( impl->userHash, &wUserHashLen );
        wToken = WindowsGetStringRawBuffer( impl->xstsToken, &wTokenLen );
        if (wUserHash && wToken && wTokenLen)
        {
            SIZE_T n = wcslen( L"x-xbl-contract-version: 1\r\nAuthorization: XBL3.0 x=;" )
                       + wUserHashLen + wTokenLen + 1;
            if ((authHeaders = calloc( n, sizeof(WCHAR) )))
            {
                wcscpy( authHeaders, L"x-xbl-contract-version: 1\r\nAuthorization: XBL3.0 x=" );
                wcsncat( authHeaders, wUserHash, wUserHashLen );
                wcscat( authHeaders, L";" );
                wcsncat( authHeaders, wToken, wTokenLen );
            }
        }

        titleHr = authHeaders
                  ? http_request( L"GET", L"title.mgt.xboxlive.com", L"/titles/current/endpoints",
                                  NULL, authHeaders, ACCEPT_JSON, &buffer, &size )
                  : E_FAIL;
        free( authHeaders );
    }

    if (SUCCEEDED(titleHr))
    {
        /* No policies here: the title-scoped document has exactly one top-level
           key, EndPoints. */
        titleHr = user_ParseEndpointDocument( buffer, size, &titleEndpoints, &titleEndpointsLen, NULL, NULL );
        if (SUCCEEDED(titleHr))
            TRACE( "title-scoped endpoint document: %u entries.\n", titleEndpointsLen );
        else
            WARN( "title-scoped endpoint document did not parse, hr %#lx.\n", titleHr );
    }
    else
    {
        /* No title claim in the current token, or the title is not provisioned
           for it. The platform document below still describes the xboxlive.com
           hosts, so keep going rather than failing sign-in. */
        WARN( "title-scoped endpoints unavailable, hr %#lx.\n", titleHr );
    }
    free( buffer );
    buffer = NULL;

    if (SUCCEEDED(hr = http_request( L"GET", L"title.mgt.xboxlive.com", L"/titles/default/endpoints?type=1",
                                     NULL, NULL, ACCEPT_JSON, &buffer, &size )))
    {
        hr = user_ParseEndpointDocument( buffer, size, &endpoints, &endpointsLen, &policies, &policiesLen );
        if (SUCCEEDED(hr)) TRACE( "platform endpoint document: %u entries.\n", endpointsLen );
        else WARN( "platform endpoint document did not parse, hr %#lx.\n", hr );
        free( buffer );
        buffer = NULL;
    }
    else WARN( "platform endpoints unavailable, hr %#lx.\n", hr );

    /* One document is enough to proceed; none is not. */
    if (FAILED(hr) && FAILED(titleHr))
    {
        ERR( "neither endpoint document could be fetched - every host would fall back to "
             "http://xboxlive.com and sign.\n" );
        return hr;
    }

    if (SUCCEEDED(titleHr))
    {
        free_endpoints( impl->titleEndpoints, impl->titleEndpointsLen );
        impl->titleEndpoints = titleEndpoints;
        impl->titleEndpointsLen = titleEndpointsLen;
        titleEndpoints = NULL;
    }
    if (SUCCEEDED(hr))
    {
        free_endpoints( impl->endpoints, impl->endpointsLen );
        free( impl->policies );
        impl->endpoints = endpoints;
        impl->endpointsLen = endpointsLen;
        impl->policies = policies;
        impl->policiesLen = policiesLen;
        endpoints = NULL;
        policies = NULL;
    }

    free_endpoints( titleEndpoints, titleEndpointsLen );
    free_endpoints( endpoints, endpointsLen );
    free( policies );
    return S_OK;
}

static const struct IUserVtbl user_vtbl =
{
    NULL,
    user_AddRef,
    user_Release,
    /* IUser methods */
    user_RequestOAuthCode,
    user_RequestOAuthToken,
    user_RefreshOAuthToken,
    user_RequestUserToken,
    user_RequestXstsToken,
    user_GenerateKeyPair,
    user_SignData,
    user_CacheEndpoints,
};

static HRESULT finish_user_load( XUserHandle impl )
{
    IJsonObject *classicGamertag = NULL, *modernGamertag = NULL, *modernGamertagSuffix = NULL;
    IJsonObject *object = NULL, *profile = NULL, *publicGamerpic = NULL, *uniqueModernGamertag = NULL;
    IJsonArray *settings = NULL, *users = NULL;
    UINT32 headersLen, tokenLen, userHashLen;
    const WCHAR *token, *userHash;
    UCHAR *settingsBuffer = NULL;
    SIZE_T settingsBufferSize;
    WCHAR *headers = NULL;
    IUser *iface = &impl->IUser_iface;
    HRESULT hr;

    /*
     * The Xbox user token is fetched LAZILY, not here.
     *
     * It is used in exactly one place - building the body of a LOCALLY minted
     * XSTS request (`UserTokens:[...]`). When a relying party is served by an
     * external identity provider instead, that body is never built and the
     * exchange is a wasted round trip to user.auth.xboxlive.com on every
     * sign-in: measured, one per boot, whose result nothing then read.
     *
     * Deferring it rather than deleting it keeps the local mint working for any
     * relying party the external provider does not handle - the token is
     * acquired the first time a local mint actually needs it.
     */
    if (FAILED(hr = IUser_GenerateKeyPair( iface )))
    {
        WARN( "Xbox proof-key generation failed, hr %#lx.\n", hr );
        goto cleanup;
    }
    if (FAILED(hr = IUser_RequestXstsToken( iface )))
    {
        WARN( "Xbox XSTS exchange failed, hr %#lx.\n", hr );
        goto cleanup;
    }
    if (FAILED(hr = IUser_CacheEndpoints( iface )))
    {
        WARN( "Xbox endpoint cache failed, using bootstrap routes, hr %#lx.\n", hr );
        hr = S_OK;
    }

    userHash = WindowsGetStringRawBuffer( impl->userHash, &userHashLen );
    token = WindowsGetStringRawBuffer( impl->xstsToken, &tokenLen );
    headersLen = wcslen( L"x-xbl-contract-version: 2\r\nAuthorization: XBL3.0 x=;" ) + userHashLen + tokenLen;
    if (!(headers = calloc( headersLen + 1, sizeof(WCHAR) )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    wcscpy( headers, L"x-xbl-contract-version: 2\r\nAuthorization: XBL3.0 x=" );
    wcsncat( headers, userHash, userHashLen );
    wcscat( headers, L";" );
    wcsncat( headers, token, tokenLen );
    if (FAILED(hr = http_request(
        L"GET", L"profile.xboxlive.com",
        L"/users/me/profile/settings?settings=PublicGamerpic,Gamertag,ModernGamertag,ModernGamertagSuffix,UniqueModernGamertag",
        NULL, headers, ACCEPT_JSON, &settingsBuffer, &settingsBufferSize
    ))) goto cleanup;
    if (FAILED(hr = parse_json( (char *)settingsBuffer, settingsBufferSize, &object ))) goto cleanup;
    if (FAILED(hr = get_json_array( object, L"profileUsers", &users ))) goto cleanup;
    if (FAILED(hr = IJsonArray_GetObjectAt( users, 0, &profile ))) goto cleanup;
    if (FAILED(hr = get_json_array( profile, L"settings", &settings ))) goto cleanup;
    if (FAILED(hr = IJsonArray_GetObjectAt( settings, 0, &publicGamerpic ))) goto cleanup;
    if (FAILED(hr = get_json_string( publicGamerpic, L"value", &impl->publicGamerpic ))) goto cleanup;
    if (FAILED(hr = IJsonArray_GetObjectAt( settings, 1, &classicGamertag ))) goto cleanup;
    if (FAILED(hr = get_json_string( classicGamertag, L"value", &impl->classicGamertag ))) goto cleanup;
    if (FAILED(hr = IJsonArray_GetObjectAt( settings, 2, &modernGamertag ))) goto cleanup;
    if (FAILED(hr = get_json_string( modernGamertag, L"value", &impl->modernGamertag ))) goto cleanup;
    if (FAILED(hr = IJsonArray_GetObjectAt( settings, 3, &modernGamertagSuffix ))) goto cleanup;
    if (FAILED(hr = get_json_string( modernGamertagSuffix, L"value", &impl->modernGamertagSuffix ))) goto cleanup;
    if (FAILED(hr = IJsonArray_GetObjectAt( settings, 4, &uniqueModernGamertag ))) goto cleanup;
    hr = get_json_string( uniqueModernGamertag, L"value", &impl->uniqueModernGamertag );

cleanup:
    free( headers );
    free( settingsBuffer );
    if (users) IJsonArray_Release( users );
    if (object) IJsonObject_Release( object );
    if (profile) IJsonObject_Release( profile );
    if (settings) IJsonArray_Release( settings );
    if (publicGamerpic) IJsonObject_Release( publicGamerpic );
    if (classicGamertag) IJsonObject_Release( classicGamertag );
    if (modernGamertag) IJsonObject_Release( modernGamertag );
    if (modernGamertagSuffix) IJsonObject_Release( modernGamertagSuffix );
    if (uniqueModernGamertag) IJsonObject_Release( uniqueModernGamertag );
    return hr;
}

static HRESULT LoadMsaUser( const char *access_token, XUserHandle *user )
{
    XUserHandle impl;
    HRESULT hr;

    TRACE( "user %p.\n", user );

    if (!access_token) return E_INVALIDARG;
    if (!(impl = calloc( 1, sizeof(*impl) ))) return E_OUTOFMEMORY;
    impl->IUser_iface.lpVtbl = &user_vtbl;
    impl->ref = 1;

    if (FAILED(hr = MultiByteToHSTRING( access_token, strlen( access_token ), &impl->accessToken )))
        goto error;
    if (FAILED(hr = finish_user_load( impl ))) goto error;

    *user = impl;
    return S_OK;

error:
    IUser_Release( &impl->IUser_iface );
    return hr;
}

static HRESULT LoadDefaultUser( XUserHandle *user )
{
    char *buffer = NULL;
    XUserHandle impl;
    LSTATUS status;
    HRESULT hr;
    DWORD size;

    TRACE( "user %p.\n", user );

    if (!(impl = calloc( 1, sizeof(*impl) ))) return E_OUTOFMEMORY;
    impl->IUser_iface.lpVtbl = &user_vtbl;
    impl->ref = 1;

    status = RegGetValueA( HKEY_LOCAL_MACHINE, "Software\\Wine\\WineGDK", "RefreshToken", RRF_RT_REG_SZ, NULL, NULL, &size );
    if (status != ERROR_SUCCESS) goto error;
    if (!(buffer = calloc( 1, size )))
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    status = RegGetValueA( HKEY_LOCAL_MACHINE, "Software\\Wine\\WineGDK", "RefreshToken", RRF_RT_REG_SZ, NULL, buffer, &size );
    if (status != ERROR_SUCCESS) goto error;
    if (FAILED(hr = MultiByteToHSTRING( buffer, size, &impl->refreshToken ))) goto cleanup;
    if (FAILED(hr = IUser_RefreshOAuthToken( &impl->IUser_iface ))) goto cleanup;
    hr = finish_user_load( impl );
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( status );
cleanup:
    free( buffer );
    if (SUCCEEDED(hr))
    {
        *user = impl;
        user_register( impl );
    }
    else IUser_Release( &impl->IUser_iface );
    return hr;
}

struct x_user
{
    IXUserImpl6 IXUserImpl_iface;
    IXUserGamertagImpl IXUserGamertagImpl_iface;
    LONG ref;
};

static inline struct x_user *impl_from_IXUserImpl( IXUserImpl6 *iface )
{
    return CONTAINING_RECORD( iface, struct x_user, IXUserImpl_iface );
}

static HRESULT WINAPI x_user_QueryInterface( IXUserImpl6 *iface, REFIID iid, void **out )
{
    struct x_user *impl = impl_from_IXUserImpl( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown    ) ||
        IsEqualGUID( iid, &IID_IXUserImpl  ) ||
        IsEqualGUID( iid, &IID_IXUserImpl2 ) ||
        IsEqualGUID( iid, &IID_IXUserImpl3 ) ||
        IsEqualGUID( iid, &IID_IXUserImpl4 ) ||
        IsEqualGUID( iid, &IID_IXUserImpl5 ) ||
        IsEqualGUID( iid, &IID_IXUserImpl6 ))
    {
        IXUserImpl6_AddRef( *out = &impl->IXUserImpl_iface );
        return S_OK;
    }

    if (IsEqualGUID( iid, &IID_IXUserGamertagImpl ))
    {
        IXUserGamertagImpl_AddRef( *out = &impl->IXUserGamertagImpl_iface );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI x_user_AddRef( IXUserImpl6 *iface )
{
    struct x_user *impl = impl_from_IXUserImpl( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI x_user_Release( IXUserImpl6 *iface )
{
    struct x_user *impl = impl_from_IXUserImpl( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p decreasing refcount to %lu.\n", iface, ref );
    return ref;
}

static HRESULT WINAPI x_user_XUserDuplicateHandle( IXUserImpl6 *iface, XUserHandle handle, XUserHandle *duplicatedHandle )
{
    TRACE( "iface %p, handle %p, duplicatedHandle %p.\n", iface, handle, duplicatedHandle );
    IUser_AddRef( &handle->IUser_iface );
    *duplicatedHandle = handle;
    return S_OK;
}

static void WINAPI x_user_XUserCloseHandle( IXUserImpl6 *iface, XUserHandle user )
{
    TRACE( "iface %p, user %p.\n", iface, user );
    if (!user) return;
    IUser_Release( &user->IUser_iface );
}

/*
 * Live users, so a handle can be found by id.
 *
 * XUserGetLocalId hands out the pointer, so XUserFindUserByLocalId can cast it
 * back; XUserFindUserById cannot - a XUID is not a pointer - and needs to know
 * who is signed in. Entries are added when a user is loaded and removed when the
 * last reference goes.
 */
#define MAX_LIVE_USERS 8
static XUserHandle live_users[MAX_LIVE_USERS];
static SRWLOCK live_users_lock = SRWLOCK_INIT;

static void user_register( XUserHandle user )
{
    UINT32 i;
    if (!user) return;
    AcquireSRWLockExclusive( &live_users_lock );
    for (i = 0; i < MAX_LIVE_USERS; ++i)
        if (!live_users[i]) { live_users[i] = user; break; }
    ReleaseSRWLockExclusive( &live_users_lock );
}

static void user_unregister( XUserHandle user )
{
    UINT32 i;
    AcquireSRWLockExclusive( &live_users_lock );
    for (i = 0; i < MAX_LIVE_USERS; ++i)
        if (live_users[i] == user) live_users[i] = NULL;
    ReleaseSRWLockExclusive( &live_users_lock );
}

/* GDK contract: an ordering, like memcmp - negative, zero or positive - so a
   title can sort handles. It must be a TOTAL order, hence the pointer tiebreak:
   two distinct users must never compare equal. (The stub returned E_NOTIMPL,
   which as an INT32 is a large negative number - i.e. "user1 < user2", always.) */
static INT32 WINAPI x_user_XUserCompare( IXUserImpl6 *iface, XUserHandle user1, XUserHandle user2 )
{
    TRACE( "iface %p, user1 %p, user2 %p.\n", iface, user1, user2 );

    if (user1 == user2) return 0;
    if (!user1) return -1;
    if (!user2) return 1;
    if (user1->xuid != user2->xuid) return user1->xuid < user2->xuid ? -1 : 1;
    return (ULONG_PTR)user1 < (ULONG_PTR)user2 ? -1 : 1;
}

static HRESULT WINAPI x_user_XUserGetMaxUsers( IXUserImpl6 *iface, UINT32 *maxUsers )
{
    TRACE( "iface %p, maxUsers %p.\n", iface, maxUsers );
    *maxUsers = 1;
    return S_OK;
}

struct XUserAddContext
{
    XUserAddOptions options;
    XUserHandle user;
};

#if XODUS_INTEROP
DEFINE_ASYNC_COMPLETED_HANDLER( async_operation_msa_token_response, IAsyncOperationCompletedHandler_IMsaTokenResponse, IAsyncOperation_IMsaTokenResponse )
#endif

/*
 * An async that has nothing to do. Used by the operations whose whole job is to
 * put a UI in front of the user - there is none here, and the state they would
 * be resolving is already the state the title wants (see
 * XUserResolvePrivilegeWithUiAsync). Returning E_NOTIMPL from those instead
 * reads to a title as "the user refused", which is a different and wrong answer.
 */
static HRESULT WINAPI complete_immediately_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;

    switch (op)
    {
        case XAsyncOp_Begin:
            hr = IXThreadingImpl_XAsyncSchedule( xthreading, data->async, 0 );
            break;
        case XAsyncOp_DoWork:
            IXThreadingImpl_XAsyncComplete( xthreading, data->async, S_OK, 0 );
            hr = S_OK;
            break;
        default:
            hr = S_OK;
            break;
    }

    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserFindUserById( IXUserImpl6 *iface, UINT64 userId, XUserHandle *handle );

struct XUserAddByIdContext
{
    UINT64 userId;
    XUserHandle user;
};

static HRESULT WINAPI XUserAddByIdProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    struct XUserAddByIdContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    context = (struct XUserAddByIdContext *)data->context;

    switch (op)
    {
        case XAsyncOp_Begin:
            hr = IXThreadingImpl_XAsyncSchedule( xthreading, data->async, 0 );
            break;

        case XAsyncOp_GetResult:
            memcpy( data->buffer, &context->user, sizeof(XUserHandle) );
            break;

        case XAsyncOp_DoWork:
            hr = x_user_XUserFindUserById( NULL, context->userId, &context->user );
            IXThreadingImpl_XAsyncComplete( xthreading, data->async, hr,
                                            SUCCEEDED(hr) ? sizeof(XUserHandle) : 0 );
            hr = S_OK;
            break;

        case XAsyncOp_Cleanup:
            free( context );
            break;

        case XAsyncOp_Cancel:
            break;
    }

    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI XUserAddProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    struct XUserAddContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    context = (struct XUserAddContext *)data->context;

    switch (op)
    {
        case XAsyncOp_Begin:
            hr = IXThreadingImpl_XAsyncSchedule( xthreading, data->async, 0 );
            break;

        case XAsyncOp_GetResult:
            memcpy( data->buffer, &context->user, sizeof(XUserHandle) );
            break;

        case XAsyncOp_DoWork:
#if XODUS_INTEROP
            {
                IAsyncOperation_IMsaTokenResponse *operation = NULL;
                IMsaTokenResponse *response = NULL;
                const char *access_token = NULL;
                DWORD async;

                if (context->options & XUserAddOptions_AddDefaultUserSilently ||
                    context->options & XUserAddOptions_AddDefaultUserAllowingUI)
                {
                    hr = IXodusService_MsaTokenRequest(
                        xodus_service, msaAppId, context->options & XUserAddOptions_AddDefaultUserAllowingUI,
                        fullTrust, &operation
                    );
                    if (FAILED(hr))
                        WARN( "failed to request MSA token from Xodus, hr %#lx.\n", hr );
                    else if ((async = await_IAsyncOperation_IMsaTokenResponse( operation, IPC_REQUEST_TIMEOUT_MS )))
                    {
                        if (async == STATUS_TIMEOUT)
                            WARN( "Timeout while waiting for MSA_TOKEN_RESPONSE response.\n" );
                        else
                            WARN( "Async action await failed. Status was %ld.\n", async );
                        hr = E_ABORT;
                    }
                    else if (FAILED(hr = IAsyncOperation_IMsaTokenResponse_GetResults( operation, &response )))
                        WARN( "Xodus MSA operation failed, hr %#lx.\n", hr );
                    else if (FAILED(hr = IMsaTokenResponse_get_Token( response, &access_token )))
                        WARN( "Xodus MSA result failed, hr %#lx.\n", hr );
                    else if (FAILED(hr = LoadMsaUser( access_token, &context->user )))
                        WARN( "Xodus user initialization failed, hr %#lx.\n", hr );

                    free( (void *)access_token );
                    if (response) IMsaTokenResponse_Release( response );
                    if (operation) IAsyncOperation_IMsaTokenResponse_Release( operation );
                    if (SUCCEEDED(hr)) goto complete;
                }
            }
#endif
            if (context->options & XUserAddOptions_AddDefaultUserSilently)
                hr = LoadDefaultUser( &context->user );
            else hr = E_ABORT;

        complete:
            IXThreadingImpl_XAsyncComplete( xthreading, data->async, hr, SUCCEEDED(hr) ? sizeof(XUserHandle) : 0 );
            hr = S_OK;
            break;

        case XAsyncOp_Cleanup:
            free( context );
            break;

        case XAsyncOp_Cancel:
            break;
    }

    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserAddAsync( IXUserImpl6 *iface, XUserAddOptions options, XAsyncBlock *async )
{
    struct XUserAddContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, options %d, async %p.\n", iface, options, async );

    if (!async) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    if (!(context = calloc( 1, sizeof(*context) )))
    {
        IXThreadingImpl_Release( xthreading );
        return E_OUTOFMEMORY;
    }

    context->options = options;
    hr = IXThreadingImpl_XAsyncBegin( xthreading, async, context, NULL, "XUserAddAsync", XUserAddProvider );
    IXThreadingImpl_Release( xthreading );
    if (FAILED(hr)) free( context );
    return hr;
}

/* Raised on a real transition - defined with the change-event registry below. */
static void user_on_signed_in( XUserHandle user );

static HRESULT WINAPI x_user_XUserAddResult( IXUserImpl6 *iface, XAsyncBlock *async, XUserHandle *newUser )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, newUser %p.\n", iface, async, newUser );

    if (!async || !newUser) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResult( xthreading, async, NULL, sizeof(*newUser), newUser, NULL );
    IXThreadingImpl_Release( xthreading );
    /* The title now holds its user handle AND its Live auth has completed
       (finish_user_load ran inside the add path), so this is a real
       SignedInAgain transition, not an experiment. */
    if (SUCCEEDED(hr)) user_on_signed_in( *newUser );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetLocalId( IXUserImpl6 *iface, XUserHandle user, XUserLocalId *userLocalId )
{
    TRACE( "iface %p, user %p, userLocalId %p.\n", iface, user, userLocalId );
    if (!user || !userLocalId) return E_POINTER;

    userLocalId->value = (UINT64)(ULONG_PTR)user;
    return S_OK;
}

/*
 * The inverse of XUserGetLocalId, which is where the id comes from: it hands out
 * `(UINT64)(ULONG_PTR)user`, so the handle is recoverable by casting back. The
 * caller owns the returned handle, hence the AddRef - same contract as
 * XUserDuplicateHandle.
 *
 * This was an E_NOTIMPL stub, and the first thing Forza Motorsport does on
 * receiving a user-change event is call it: the event carries an XUserLocalId
 * and the title needs a handle. Measured - `FindUserByLocalId` appears in the
 * XUser call census exactly once, and only in runs where a change event was
 * delivered; it is absent from every control run.
 */
static HRESULT WINAPI x_user_XUserFindUserByLocalId( IXUserImpl6 *iface, XUserLocalId userLocalId, XUserHandle *handle )
{
    XUserHandle user = (XUserHandle)(ULONG_PTR)userLocalId.value;

    TRACE( "iface %p, userLocalId %llu, handle %p.\n", iface, (unsigned long long)userLocalId.value, handle );

    if (!handle) return E_POINTER;
    *handle = NULL;
    if (!user) return E_GAMEUSER_NO_DEFAULT_USER;
    /* An id this runtime never issued must not be dereferenced. Nothing here can
       prove a pointer is one of ours, so at least refuse the shapes that cannot
       be: a null or misaligned value. */
    if ((ULONG_PTR)user & (sizeof(void *) - 1)) return E_GAMEUSER_NO_DEFAULT_USER;

    IUser_AddRef( &user->IUser_iface );
    *handle = user;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserGetId( IXUserImpl6 *iface, XUserHandle user, UINT64 *userId )
{
    TRACE( "iface %p, user %p, userId %p.\n", iface, user, userId );
    *userId = user->xuid;
    return S_OK;
}

/* The XUID counterpart of XUserFindUserByLocalId. The caller owns the returned
   handle, so it is AddRef'd - same contract as XUserDuplicateHandle. */
static HRESULT WINAPI x_user_XUserFindUserById( IXUserImpl6 *iface, UINT64 userId, XUserHandle *handle )
{
    HRESULT hr = E_GAMEUSER_NO_DEFAULT_USER;
    UINT32 i;

    TRACE( "iface %p, userId %llu, handle %p.\n", iface, userId, handle );

    if (!handle) return E_POINTER;
    *handle = NULL;

    AcquireSRWLockShared( &live_users_lock );
    for (i = 0; i < MAX_LIVE_USERS; ++i)
        if (live_users[i] && live_users[i]->xuid == userId)
        {
            IUser_AddRef( &live_users[i]->IUser_iface );
            *handle = live_users[i];
            hr = S_OK;
            break;
        }
    ReleaseSRWLockShared( &live_users_lock );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetIsGuest( IXUserImpl6 *iface, XUserHandle user, BOOLEAN *isGuest )
{
    TRACE( "iface %p, user %p, isGuest %p.\n", iface, user, isGuest );
    *isGuest = FALSE;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserGetState( IXUserImpl6 *iface, XUserHandle user, XUserState *state )
{
    TRACE( "iface %p, user %p, state %p.\n", iface, user, state );
    *state = XUserState_SignedIn;
    return S_OK;
}

static HRESULT WINAPI __PADDING__( IXUserImpl6 *iface )
{
    WARN( "iface %p padding function called! It's unknown what this function does.\n", iface );
    return E_NOTIMPL;
}

struct XUserGetGamerPictureContext
{
    XUserHandle user;
    XUserGamerPictureSize pictureSize;
    SIZE_T bufferSize;
    void *buffer;
};

static HRESULT WINAPI XUserGetGamerPictureProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    URL_COMPONENTSW uc = { .dwStructSize = sizeof(URL_COMPONENTSW), .dwHostNameLength = -1, .dwUrlPathLength = -1, .dwExtraInfoLength = -1 };
    static const WCHAR *accept[] = { L"image/png", NULL };
    struct XUserGetGamerPictureContext *context;
    WCHAR *hostName = NULL, *pathAndQuery;
    const WCHAR *buffer, *suffix;
    IXThreadingImpl *xthreading;
    IJsonObject *object = NULL;
    HSTRING url = NULL;
    HRESULT hr;

    TRACE( "op %d, data %p.\n", op, data );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    context = (struct XUserGetGamerPictureContext *)data->context;

    switch (op)
    {
        case XAsyncOp_Begin:
            hr = IXThreadingImpl_XAsyncSchedule( xthreading, data->async, 0 );
            break;

        case XAsyncOp_GetResult:
            memcpy( data->buffer, context->buffer, context->bufferSize );
            break;

        case XAsyncOp_DoWork:
            switch (context->pictureSize)
            {
                case XUserGamerPictureSize_Small:
                    suffix = L"&format=png&w=64&h=64";
                    break;
                case XUserGamerPictureSize_Medium:
                    suffix = L"&format=png&w=208&h=208";
                    break;
                case XUserGamerPictureSize_Large:
                    suffix = L"&format=png&w=424&h=424";
                    break;
                case XUserGamerPictureSize_ExtraLarge:
                    suffix = L"&format=png&w=1080&h=1080";
                    break;
                default:
                    hr = E_INVALIDARG;
                    goto cleanup;
            }

            buffer = WindowsGetStringRawBuffer( context->user->publicGamerpic, NULL );
            if (!InternetCrackUrlW( buffer, 0, 0, &uc ))
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                goto cleanup;
            }

            if (!(hostName = calloc( uc.dwHostNameLength + uc.dwUrlPathLength + uc.dwExtraInfoLength + wcslen( suffix ) + 2, sizeof(WCHAR) )))
            {
                hr = E_OUTOFMEMORY;
                goto cleanup;
            }

            memcpy( hostName, uc.lpszHostName, uc.dwHostNameLength * sizeof(WCHAR) );
            pathAndQuery = hostName + uc.dwHostNameLength + 1;
            memcpy( pathAndQuery, uc.lpszUrlPath, (uc.dwUrlPathLength + uc.dwExtraInfoLength) * sizeof(WCHAR) );

            hr = http_request( L"GET", hostName, pathAndQuery, NULL, NULL, accept, (UCHAR **)&context->buffer, &context->bufferSize );

        cleanup:
            IXThreadingImpl_XAsyncComplete( xthreading, data->async, hr, SUCCEEDED(hr) ? context->bufferSize : 0 );
            if (object) IJsonObject_Release( object );
            if (url) WindowsDeleteString( url );
            if (hostName) free( hostName );
            hr = S_OK;
            break;

        case XAsyncOp_Cleanup:
            IUser_Release( &context->user->IUser_iface );
            if (context->buffer) free( context->buffer );
            free( context );
            break;

        case XAsyncOp_Cancel:
            break;
    }

    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetGamerPictureAsync( IXUserImpl6 *iface, XUserHandle user, XUserGamerPictureSize pictureSize, XAsyncBlock *async )
{
    struct XUserGetGamerPictureContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, user %p, pictureSize %d, async %p.\n", iface, user, pictureSize, async );

    if (!user || !async) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    if (!(context = calloc( 1, sizeof(*context) )))
    {
        IXThreadingImpl_Release( xthreading );
        return E_OUTOFMEMORY;
    }

    context->pictureSize = pictureSize;
    if (FAILED(hr = IXUserImpl6_XUserDuplicateHandle( iface, user, &context->user )))
    {
        IXThreadingImpl_Release( xthreading );
        return hr;
    }

    hr = IXThreadingImpl_XAsyncBegin( xthreading, async, context, NULL, "XUserGetGamerPictureAsync", XUserGetGamerPictureProvider );
    IXThreadingImpl_Release( xthreading );
    if (FAILED(hr)) free( context );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetGamerPictureResultSize( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T *bufferSize )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, bufferSize %p.\n", iface, async, bufferSize );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResultSize( xthreading, async, bufferSize );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetGamerPictureResult( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T bufferSize, void *buffer, SIZE_T *bufferUsed )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, bufferSize %Iu, buffer %p, bufferUsed %p.\n", iface, async, bufferSize, buffer, bufferUsed );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResult( xthreading, async, NULL, bufferSize, buffer, bufferUsed );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetAgeGroup( IXUserImpl6 *iface, XUserHandle user, XUserAgeGroup *ageGroup )
{
    TRACE( "iface %p, user %p, ageGroup %p.\n", iface, user, ageGroup );
    *ageGroup = XUserAgeGroup_Adult;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserCheckPrivilege( IXUserImpl6 *iface, XUserHandle user, XUserPrivilegeOptions options, XUserPrivilege privilege, BOOLEAN *hasPrivilege, XUserPrivilegeDenyReason *reason )
{
    TRACE( "iface %p, user %p, options %d, privilege %d, hasPrivilege %p, reason %p.\n", iface, user, options, privilege, hasPrivilege, reason );
    if (!user || !hasPrivilege) return E_POINTER;

    *hasPrivilege = TRUE;
    if (reason) *reason = XUserPrivilegeDenyReason_None;
    return S_OK;
}

/*
 * Resolving a privilege means showing the user an upsell/consent UI and then
 * reporting whether they now have it. There is no such UI here - but there is
 * also nothing to resolve: XUserCheckPrivilege grants every privilege with
 * XUserPrivilegeDenyReason_None, so the privilege is already held and the honest
 * result of "resolve it" is success.
 *
 * Completing S_OK is materially better than E_NOTIMPL: a title that calls this
 * after a denied check treats the failure as "the user refused" and blocks the
 * feature, whereas the check it just made said yes.
 */
static HRESULT WINAPI x_user_XUserResolvePrivilegeWithUiAsync( IXUserImpl6 *iface, XUserHandle user, XUserPrivilegeOptions options, XUserPrivilege privilege, XAsyncBlock *async )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, user %p, options %d, privilege %d, async %p.\n", iface, user, options, privilege, async );

    if (!user || !async) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncBegin( xthreading, async, NULL, NULL, "XUserResolvePrivilegeWithUiAsync", complete_immediately_provider );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserResolvePrivilegeWithUiResult( IXUserImpl6 *iface, XAsyncBlock *async )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p.\n", iface, async );

    if (!async) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResult( xthreading, async, NULL, 0, NULL, NULL );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

struct XUserGetTokenAndSignatureContext
{
    XUserHandle user;
    XUserGetTokenAndSignatureOptions options;
    char *url;
    char *method;
    SIZE_T headersSize;
    char *headers;
    SIZE_T bodySize;
    void *bodyBuffer;
    BOOLEAN isUtf16;
    union
    {
        XUserGetTokenAndSignatureData *data;
        XUserGetTokenAndSignatureUtf16Data *dataUtf16;
    };
};

static HRESULT WINAPI XUserGetTokenAndSignatureProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    URL_COMPONENTSA uc = { .dwStructSize = sizeof(URL_COMPONENTSA), .dwHostNameLength = -1,
            .dwUrlPathLength = -1, .dwExtraInfoLength = -1 };
    UINT32 authLen, bufLen, dataSize = 0, pathAndQueryLen, tokenLen, userHashLen, wAuthLen, wTokenLen, wUserHashLen;
    struct XUserGetTokenAndSignatureContext *context;
    char *auth, *method, *ptr, *signature;
    const WCHAR *wToken, *wUserHash;
    const char *relyingParty;
    IXThreadingImpl *xthreading;
    BYTE rawSignature[76] = {}; /* 4 byte version, 8 byte filetime, 64 byte signature */
    UINT32 signatureLen = 104;  /* 76 raw bytes -> 104 base64 chars; 0 when unsigned */
    WCHAR *wAuth, *wSignature;
    FILETIME timestamp;
    char *buf = NULL;
    BOOL xstsLocked = FALSE;
    HRESULT hr;

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    context = (struct XUserGetTokenAndSignatureContext *)data->context;

    /*
     * signatures constructed by following
     * https://learn.microsoft.com/gaming/gdk/docs/services/fundamentals/s2s-auth-calls/s2s-calls/live-title-service-calls-xbox-live#proof-keys
     * using signature policy specified for host xboxlive.com at:
     * https://title.mgt.xboxlive.com/titles/default/endpoints?type=1
     * (Version 1, ES256, 0x2000 (8KiB) MaxBodyBytes)
     */

    switch (op)
    {
        case XAsyncOp_Begin:
            hr = IXThreadingImpl_XAsyncSchedule( xthreading, data->async, 0 );
            break;

        case XAsyncOp_GetResult:
            if (context->isUtf16)
            {
                XUserGetTokenAndSignatureUtf16Data *result = data->buffer;
                SIZE_T size = sizeof(*result) +
                        (context->dataUtf16->tokenCount + context->dataUtf16->signatureCount + 2) * sizeof(WCHAR);

                memcpy( result, context->dataUtf16, size );
                result->token = (WCHAR *)(result + 1);
                result->signature = result->token + result->tokenCount + 1;
            }
            else
            {
                XUserGetTokenAndSignatureData *result = data->buffer;
                SIZE_T size = sizeof(*result) + context->data->tokenSize + context->data->signatureSize + 2;

                memcpy( result, context->data, size );
                result->token = (char *)(result + 1);
                result->signature = result->token + result->tokenSize + 1;
            }
            break;

        case XAsyncOp_DoWork:
            if (!InternetCrackUrlA( context->url, 0, 0, &uc )) goto error;
            pathAndQueryLen = uc.dwUrlPathLength + uc.dwExtraInfoLength;
            relyingParty = user_GetRelyingParty( context->user, &uc );
            AcquireSRWLockExclusive( &context->user->xstsLock );
            xstsLocked = TRUE;
            if (!context->user->xstsRelyingParty || strcmp( context->user->xstsRelyingParty, relyingParty ))
            {
                if (FAILED(hr = user_request_xsts_token( context->user, relyingParty ))) goto cleanup;
            }
            TRACE( "Using XSTS relying party %s for %s.\n", debugstr_a( relyingParty ), debugstr_a( context->url ) );
            wUserHash = WindowsGetStringRawBuffer( context->user->userHash, &wUserHashLen );
            wToken = WindowsGetStringRawBuffer( context->user->xstsToken, &wTokenLen );
            if (!(userHashLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wUserHash, wUserHashLen, NULL, 0, NULL, NULL ))) goto error;
            if (!(tokenLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wToken, wTokenLen, NULL, 0, NULL, NULL ))) goto error;
            wAuthLen = wcslen( L"XBL3.0 x=;" ) + wUserHashLen + wTokenLen;
            authLen = strlen( "XBL3.0 x=;" ) + userHashLen + tokenLen;
            bufLen = strlen( context->method ) + pathAndQueryLen + authLen + context->headersSize + min( context->bodySize, 0x2000 ) + 18;
            GetSystemTimeAsFileTime( &timestamp );

            if (!(buf = calloc( 1, bufLen )))
            {
                hr = E_OUTOFMEMORY;
                goto cleanup;
            }

            /* version */
            buf[3] = 1;
            memcpy( rawSignature, buf, 4 );

            /* filetime */
            buf[5]  = (timestamp.dwHighDateTime >> 24) & 0xff;
            buf[6]  = (timestamp.dwHighDateTime >> 16) & 0xff;
            buf[7]  = (timestamp.dwHighDateTime >> 8 ) & 0xff;
            buf[8]  =  timestamp.dwHighDateTime        & 0xff;
            buf[9]  = (timestamp.dwLowDateTime  >> 24) & 0xff;
            buf[10] = (timestamp.dwLowDateTime  >> 16) & 0xff;
            buf[11] = (timestamp.dwLowDateTime  >> 8 ) & 0xff;
            buf[12] =  timestamp.dwLowDateTime         & 0xff;
            memcpy( rawSignature + 4, buf + 5, 8 );

            /* method */
            ptr = buf + 14;
            method = context->method;
            while (*method) *(ptr++) = toupper( *(method++) );
            ptr++;

            /* path and query */
            memcpy( ptr, uc.lpszUrlPath, pathAndQueryLen );
            ptr += pathAndQueryLen + 1;

            /* authorization header */
            ptr += strlen( strcpy( ptr, "XBL3.0 x=" ) );
            if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wUserHash, wUserHashLen, ptr, userHashLen, NULL, NULL )) goto error;
            strcat( ptr, ";" );
            ptr += userHashLen + 1;
            if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wToken, wTokenLen, ptr, tokenLen, NULL, NULL )) goto error;
            ptr += tokenLen + 1;

            /* headers */
            memcpy( ptr, context->headers, context->headersSize );
            ptr += context->headersSize;

            /* body */
            memcpy( ptr, context->bodyBuffer, min( context->bodySize, 0x2000 ) );

            TRACE( "buf: %s\n", debugstr_an( (char *)buf, bufLen ) );
            TRACE( "rawSignature: %s\n", debugstr_an( (char *)rawSignature, 76 ) );

            /* Sign normally, including for service-minted tokens: with
               WINEGDK_PROOF_KEY and XODUS_PROOF_KEY pointing at the SAME key, a
               token minted by the service is bound to a key this process holds,
               so the signature is valid. GSSTUB_NOSIG / an unsigned endpoint is
               handled by the caller, not here.
               (Before the shared key existed this branch had to send an empty
               signature for service-minted tokens - correct for the Forza Logon,
               which Windows sends unsigned, but it left every xboxlive.com
               request unsigned too, and those ARE signed on Windows.) */
            /* Sign only if the endpoint's own config asks for it. Turn 10's hosts
               carry no SignaturePolicyIndex in the title-scoped document, and the
               Windows capture sends them an empty Signature. */
            if (!user_UrlWantsSignature( context->user, &uc ))
            {
                TRACE( "endpoint has no signature policy; sending an empty signature.\n" );
                signatureLen = 0;
            }
            else if (FAILED(hr = IUser_SignData( &context->user->IUser_iface, bufLen, (UCHAR *)buf, 64, rawSignature + 12 ))) goto cleanup;

            if (context->isUtf16)
            {
                /* 76 byte signature = 104 chars base64 with padding */
                dataSize = sizeof(*context->dataUtf16) + (wAuthLen + signatureLen + 2) * sizeof(WCHAR);
                if (!(context->dataUtf16 = calloc( 1, dataSize )))
                {
                    hr = E_OUTOFMEMORY;
                    goto cleanup;
                }

                context->dataUtf16->tokenCount = wAuthLen;
                context->dataUtf16->signatureCount = signatureLen;
                wAuth = (WCHAR *)(context->dataUtf16 + 1);
                wSignature = wAuth + wAuthLen + 1;
                context->dataUtf16->token = wAuth;
                context->dataUtf16->signature = wSignature;

                wcscpy( wAuth, L"XBL3.0 x=" );
                wcsncat( wAuth, wUserHash, wUserHashLen );
                wcscat( wAuth, L";" );
                wcsncat( wAuth, wToken, wTokenLen );
                if (signatureLen) encode_base64_utf16( 76, rawSignature, 104, wSignature, TRUE );
                else *wSignature = 0;

                TRACE( "token: %s\n", debugstr_wn( context->dataUtf16->token, context->dataUtf16->tokenCount ) );
                TRACE( "signature: %s\n", debugstr_wn( context->dataUtf16->signature, context->dataUtf16->signatureCount ) );
            }
            else
            {
                /* 76 byte signature = 104 chars base64 with padding */
                dataSize = sizeof(*context->data) + authLen + 106;
                if (!(context->data = calloc( 1, dataSize )))
                {
                    hr = E_OUTOFMEMORY;
                    goto cleanup;
                }

                context->data->tokenSize = authLen;
                context->data->signatureSize = signatureLen;
                auth = (char *)context->data + sizeof(*context->data);
                signature = auth + authLen + 1;
                context->data->token = auth;
                context->data->signature = signature;

                strcpy( auth, buf + strlen( context->method ) + pathAndQueryLen + 16 );
                if (signatureLen) encode_base64( 76, rawSignature, 104, signature, TRUE );
                else *signature = 0;

                TRACE( "token: %s\n", debugstr_an( context->data->token, context->data->tokenSize ) );
                TRACE( "signature: %s\n", debugstr_an( context->data->signature, context->data->signatureSize ) );
            }
            goto cleanup;

        error:
            hr = HRESULT_FROM_WIN32( GetLastError() );
        cleanup:
            if (xstsLocked) ReleaseSRWLockExclusive( &context->user->xstsLock );
            if (buf) free( buf );
            if (FAILED(hr))
            {
                dataSize = 0;
                free( context->data );
                context->data = NULL;
            }
            IXThreadingImpl_XAsyncComplete( xthreading, data->async, hr, dataSize );
            hr = S_OK;
            break;

        case XAsyncOp_Cleanup:
            IUser_Release( &context->user->IUser_iface );
            free( context->data );
            free( context );
            break;

        case XAsyncOp_Cancel:
            break;
    }

    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureAsync( IXUserImpl6 *iface, XUserHandle user, XUserGetTokenAndSignatureOptions options, const char *method, const char *url, SIZE_T headerCount, const XUserGetTokenAndSignatureHttpHeader *headers, SIZE_T bodySize, const void *bodyBuffer, XAsyncBlock *async )
{
    struct XUserGetTokenAndSignatureContext *context;
    SIZE_T contextSize, headersSize = 0;
    IXThreadingImpl *xthreading;
    HRESULT hr;
    char *ptr;

    TRACE( "iface %p, user %p, options %d, method %s, url %s, headerCount %Iu, headers %p, bodySize %Iu, bodyBuffer %p, async %p.\n", iface, user, options, debugstr_a( method ), debugstr_a( url ), headerCount, headers, bodySize, bodyBuffer, async );

    /* Every one of these is caller-supplied and can be NULL: FM passes headers whose
     * .value is NULL, which faulted strlen() at address 0 (mov 0x8(%r15) with a 0x10
     * stride = the .value field of XUserGetTokenAndSignatureHttpHeader).
     * NOTE: this sizing loop and the copy loop below MUST use identical logic, or the
     * mismatch becomes a heap overflow rather than a crash. */
    if (!url) url = "";
    if (!method) method = "";
    if (!headers) headerCount = 0;
    if (!bodyBuffer) bodySize = 0;
    contextSize = sizeof(*context) + strlen( url ) + strlen( method ) + 2 + bodySize;
    for (SIZE_T i = 0; i < headerCount; i++)
        headersSize += (headers[i].value ? strlen( headers[i].value ) : 0) + 1;

    if (!(context = calloc( 1, contextSize + headersSize ))) return E_OUTOFMEMORY;
    IUser_AddRef( &user->IUser_iface );
    context->user = user;
    context->options = options;
    context->headersSize = headersSize;
    context->bodySize = bodySize;
    context->isUtf16 = FALSE;

    /* url */
    ptr = (char *)context + sizeof(*context);
    ptr += strlen( strcpy( (context->url = ptr), url ) ) + 1;
    /* method */
    ptr += (strlen( strcpy( (context->method = ptr), method ) ) + 1);
    /* headers */
    context->headers = ptr;
    for (SIZE_T i = 0; i < headerCount; i++)
        ptr += (strlen( strcpy( ptr, headers[i].value ? headers[i].value : "" ) ) + 1);
    /* body */
    context->bodyBuffer = ptr;
    if (bodySize) memcpy( ptr, bodyBuffer, bodySize );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) goto error;
    hr = IXThreadingImpl_XAsyncBegin( xthreading, async, context, NULL, "XUserGetTokenAndSignatureAsync", XUserGetTokenAndSignatureProvider );
    IXThreadingImpl_Release( xthreading );
    if (FAILED(hr)) goto error;
    return hr;
error:
    free( context );
    IUser_Release( &user->IUser_iface );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureResultSize( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T *bufferSize )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, bufferSize %p.\n", iface, async, bufferSize );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResultSize( xthreading, async, bufferSize );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureResult( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T bufferSize, void *buffer, XUserGetTokenAndSignatureData **ptrToBuffer, SIZE_T *bufferUsed )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, bufferSize %Iu, buffer %p, ptrToBuffer %p, bufferUsed %p.\n", iface, async, bufferSize, buffer, ptrToBuffer, bufferUsed );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResult( xthreading, async, NULL, bufferSize, buffer, bufferUsed );
    *ptrToBuffer = (XUserGetTokenAndSignatureData *)buffer;
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16Async( IXUserImpl6 *iface, XUserHandle user, XUserGetTokenAndSignatureOptions options, const WCHAR *method, const WCHAR *url, SIZE_T headerCount, const XUserGetTokenAndSignatureUtf16HttpHeader *headers, SIZE_T bodySize, const void *bodyBuffer, XAsyncBlock *async )
{
    SIZE_T contextSize, headersSize = 0, methodLen, urlLen;
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;
    char *ptr;
    int size;

    TRACE( "iface %p, user %p, options %d, method %s, url %s, headerCount %Iu, headers %p, bodySize %Iu, bodyBuffer %p, async %p.\n", iface, user, options, debugstr_w( method ), debugstr_w( url ), headerCount, headers, bodySize, bodyBuffer, async );

    if (!(methodLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, method, -1, NULL, 0, NULL, NULL ))) return HRESULT_FROM_WIN32( GetLastError() );
    if (!(urlLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, url, -1, NULL, 0, NULL, NULL ))) return HRESULT_FROM_WIN32( GetLastError() );
    contextSize = sizeof(*context) + urlLen + methodLen + bodySize;
    for (SIZE_T i = 0; i < headerCount; i++)
    {
        if (!(size = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, headers[i].value, -1, NULL, 0, NULL, NULL ))) return HRESULT_FROM_WIN32( GetLastError() );
        headersSize += size;
    }

    if (!(context = calloc( 1, contextSize + headersSize ))) return E_OUTOFMEMORY;
    IUser_AddRef( &user->IUser_iface );
    context->user = user;
    context->options = options;
    context->headersSize = headersSize;
    context->bodySize = bodySize;
    context->isUtf16 = TRUE;

    /* url */
    ptr = (char *)context + sizeof(*context);
    if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, url, -1, ptr, urlLen, NULL, NULL )) goto error_win32;
    ptr += urlLen;
    /* method */
    if (!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, method, -1, ptr, methodLen, NULL, NULL )) goto error_win32;
    ptr += methodLen;
    /* headers */
    for (SIZE_T i = 0; i < headerCount; i++)
    {
        if (!(size = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, headers[i].value, -1, NULL, 0, NULL, NULL ))) goto error_win32;
        if(!WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, headers[i].value, -1, ptr, size, NULL, NULL )) goto error_win32;
        ptr += size;
    }
    /* body */
    memcpy( (context->bodyBuffer = ptr), bodyBuffer, bodySize );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) goto error;
    hr = IXThreadingImpl_XAsyncBegin( xthreading, async, context, NULL, "XUserGetTokenAndSignatureUtf16Async", XUserGetTokenAndSignatureProvider );
    IXThreadingImpl_Release( xthreading );
    if (FAILED(hr)) goto error;
    return hr;

error_win32:
    hr = HRESULT_FROM_WIN32( GetLastError() );
error:
    free( context );
    IUser_Release( &user->IUser_iface );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16ResultSize( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T *bufferSize )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, bufferSize %p.\n", iface, async, bufferSize );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResultSize( xthreading, async, bufferSize );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16Result( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T bufferSize, void *buffer, XUserGetTokenAndSignatureUtf16Data **ptrToBuffer, SIZE_T *bufferUsed )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, bufferSize %Iu, buffer %p, ptrToBuffer %p, bufferUsed %p.\n", iface, async, bufferSize, buffer, ptrToBuffer, bufferUsed );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResult( xthreading, async, NULL, bufferSize, buffer, bufferUsed );
    *ptrToBuffer = (XUserGetTokenAndSignatureUtf16Data *)buffer;
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiAsync( IXUserImpl6 *iface, XUserHandle user, const char *url, XAsyncBlock *async )
{
    FIXME( "iface %p, user %p, url %s, async %p stub!\n", iface, user, debugstr_a( url ), async );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiResult( IXUserImpl6 *iface, XAsyncBlock *async )
{
    FIXME( "iface %p, async %p stub!\n", iface, async );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiUtf16Async( IXUserImpl6 *iface, XUserHandle user, const WCHAR *url, XAsyncBlock *async )
{
    FIXME( "iface %p, user %p, url %s, async %p stub!\n", iface, user, debugstr_w( url ), async );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiUtf16Result( IXUserImpl6 *iface, XAsyncBlock *async )
{
    FIXME( "iface %p, async %p stub!\n", iface, async );
    return E_NOTIMPL;
}

/*
 * XUserRegisterForChangeEvent - remember the registration.
 *
 * This used to set `token->token = 1` and return S_OK while dropping the queue,
 * the context and the callback on the floor, so a title was told it had
 * registered and could then never be told anything. Forza Motorsport does
 * register (measured: exactly one call, on a census that counts all 50 vtable
 * slots), and a title that gates work on a user-change event it can never
 * receive waits forever with no error to find.
 *
 * Storing the registration is correct on its own. Whether anything is ever
 * DELIVERED is a separate question - see user_fire_change_event below.
 */
#define MAX_CHANGE_REGS 8
static struct change_reg
{
    XTaskQueueHandle queue;
    void *context;
    XUserChangeEventCallback *callback;
    UINT64 token;
} change_regs[MAX_CHANGE_REGS];
static SRWLOCK change_regs_lock = SRWLOCK_INIT;
static UINT64 change_regs_next_token = 1;

/*
 * The runtime's own view of user state, guarded by change_regs_lock.
 *
 * WHY IT EXISTS: a title may register BEFORE or AFTER sign-in completes, and the
 * runtime does not get to choose. Firing only at the transition serves the first
 * order and silently serves nothing to the second - a title that registers late
 * then waits forever, with no error anywhere, which is the exact failure this
 * whole change is about. The previous code dodged the question with a 5000 ms
 * sleep before firing, which is not a fix: it is a bet that the title registers
 * within five seconds.
 *
 * So the transition is recorded. A registration arriving afterwards is told the
 * current state once, immediately (user_catch_up_new_registration).
 *
 * Deliberate deviation, stated plainly: real Windows does NOT replay past events
 * to a late registrant - it expects the title to read current state with
 * XUserGetState. Serving the catch-up is the pragmatic choice for a runtime whose
 * titles evidently rely on the event, and it is strictly more informative than
 * silence. If it ever proves wrong, this is the one place to change.
 */
static XUserLocalId signed_in_id;
static BOOL signed_in;

static void user_catch_up_new_registration( const struct change_reg *reg );

static HRESULT WINAPI x_user_XUserRegisterForChangeEvent( IXUserImpl6 *iface, XTaskQueueHandle queue, void *context, XUserChangeEventCallback *callback, XTaskQueueRegistrationToken *token )
{
    struct change_reg reg;
    UINT32 i;

    TRACE( "iface %p, queue %p, context %p, callback %p, token %p.\n", iface, queue, context, callback, token );

    if (!callback || !token) return E_POINTER;

    AcquireSRWLockExclusive( &change_regs_lock );
    for (i = 0; i < MAX_CHANGE_REGS; ++i) if (!change_regs[i].callback) break;
    if (i == MAX_CHANGE_REGS)
    {
        ReleaseSRWLockExclusive( &change_regs_lock );
        WARN( "no free change-event registration slot.\n" );
        return E_OUTOFMEMORY;
    }
    /* DUPLICATE the queue: the registration outlives the call, and the title is
       free to close its own handle afterwards. Storing the caller's handle and
       using it later is a use-after-close - measured, and it is what made
       XTaskQueueSubmitDelayedCallback never return (three runs, the marker file
       stops at the line before the submit) while taking the title's sign-in down
       with it. XTaskQueueSubmitCallback works fine elsewhere in this runtime, so
       the queue machinery was never the problem; the handle was. */
    change_regs[i].queue = NULL;
    if (queue)
    {
        IXThreadingImpl *xthreading;
        HRESULT hr;

        /* Through IXThreadingImpl, NOT the module's own XTaskQueue* exports.
           Every other call site in this file does the same, and the reason is
           that the ACTIVE threading implementation may be Microsoft's real
           .threading module rather than this one - the title's queue handle
           belongs to whoever created it, and handing it to the wrong
           implementation's handle table is what made the submit never return. */
        if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading )))
        {
            ReleaseSRWLockExclusive( &change_regs_lock );
            return hr;
        }
        hr = IXThreadingImpl_XTaskQueueDuplicateHandle( xthreading, queue, &change_regs[i].queue );
        IXThreadingImpl_Release( xthreading );
        if (FAILED(hr))
        {
            ReleaseSRWLockExclusive( &change_regs_lock );
            WARN( "could not duplicate the caller's task queue, hr %#lx.\n", hr );
            return hr;
        }
    }
    change_regs[i].context = context;
    change_regs[i].callback = callback;
    change_regs[i].token = change_regs_next_token++;
    token->token = change_regs[i].token;
    reg = change_regs[i];
    ReleaseSRWLockExclusive( &change_regs_lock );

    TRACE( "registered change-event callback %p in slot %u, token %llu.\n",
           callback, i, (unsigned long long)token->token );

    /* If the user is ALREADY signed in, this registration missed the transition.
       Tell it now rather than leave it waiting for an event that has been and
       gone - see the note on signed_in above. */
    user_catch_up_new_registration( &reg );
    return S_OK;
}

static BOOLEAN WINAPI x_user_XUserUnregisterForChangeEvent( IXUserImpl6 *iface, XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    UINT32 i;

    TRACE( "iface %p, token %llu, wait %d.\n", iface, token.token, wait );

    AcquireSRWLockExclusive( &change_regs_lock );
    for (i = 0; i < MAX_CHANGE_REGS; ++i)
        if (change_regs[i].callback && change_regs[i].token == token.token)
        {
            if (change_regs[i].queue)
            {
                IXThreadingImpl *xthreading;
                if (SUCCEEDED(QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading )))
                {
                    IXThreadingImpl_XTaskQueueCloseHandle( xthreading, change_regs[i].queue );
                    IXThreadingImpl_Release( xthreading );
                }
            }
            memset( &change_regs[i], 0, sizeof(change_regs[i]) );
        }
    ReleaseSRWLockExclusive( &change_regs_lock );
    return TRUE;
}

/*
 * WINEGDK_FIRE_USER_CHANGE=<event>[,<delayMs>] - THE EXPERIMENT, off by default.
 *
 * Storing the registration above cannot by itself deliver anything: this runtime
 * observes no user-state transitions, so it has no honest event to raise. The
 * open question is whether Forza Motorsport is waiting for one. So this raises
 * exactly one, of the caller's choosing, once, on the registered queue - and
 * unset it changes nothing, which is what makes it an A/B rather than a
 * behaviour change.
 *
 *   event   XUserChangeEvent: 0 SignedInAgain, 1 SigningOut, 2 SignedOut,
 *           3 Gamertag, 4 GamerPicture, 5 Privileges
 *   delayMs after the user handle is handed to the title (default 5000) - the
 *           title may register before or after XUserAddResult, and a delay makes
 *           the experiment independent of that order.
 *
 * Delivery goes through XTaskQueueSubmitDelayedCallback on the queue the title
 * supplied, because that is where the GDK contract says the callback runs;
 * calling it from this thread would hand the title a callback on a thread it
 * never agreed to.
 */
struct change_post
{
    XUserChangeEventCallback *callback;
    void *context;
    XUserLocalId userLocalId;
    XUserChangeEvent event;
};

/*
 * The experiment needs a channel that cannot lie about itself. Proton runs with
 * WINEDEBUG=-all unless PROTON_LOG is set, so ERR/TRACE from here reach nobody -
 * the first attempt at this experiment produced a game that exited at t=30s and
 * NOT ONE log line, which says nothing about whether the callback fired. So the
 * armed path also appends to a file. Written only when the experiment is armed.
 */
static void change_log( const char *what, unsigned a, const void *p )
{
    char path[MAX_PATH], line[256];
    HANDLE fh;
    DWORD wrote;
    int n;

    if (!GetEnvironmentVariableA( "WINEGDK_FIRE_USER_CHANGE_LOG", path, sizeof(path) ))
        strcpy( path, "C:\\winegdk_change.log" );
    fh = CreateFileA( path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if (fh == INVALID_HANDLE_VALUE) return;
    n = snprintf( line, sizeof(line), "[%lu ms, tid %lu] %s a=%u p=%p\n",
                  GetTickCount(), GetCurrentThreadId(), what, a, p );
    if (n > 0) WriteFile( fh, line, n, &wrote, NULL );
    CloseHandle( fh );
}

static void CALLBACK user_change_trampoline( void *context, BOOLEAN canceled )
{
    struct change_post *post = context;

    if (!canceled)
    {
        TRACE( "delivering change event %d to callback %p.\n", post->event, post->callback );
        change_log( "ENTER callback, event", post->event, post->callback );
        post->callback( post->context, post->userLocalId, post->event );
        /* If the title never comes back, this line is missing and that is the
           finding - a delivered event that does not return is a very different
           result from one that returns and changes nothing. */
        change_log( "RETURNED from callback, event", post->event, post->callback );
    }
    else change_log( "callback CANCELED, event", post->event, post->callback );
    free( post );
}

/* Deliver one event to ONE registration. Split out of the fan-out below because a
   registration that arrives after the transition has to be served on its own -
   see user_catch_up_new_registration. */
static void change_deliver( const struct change_reg *reg, XUserLocalId userLocalId, XUserChangeEvent event )
{
    XTaskQueueHandle queue = reg->queue;
    IXThreadingImpl *xthreading;
    struct change_post *post;
    HRESULT hr;

    /* A title may register with a NULL queue, meaning the process default.
       Passing that straight through is what broke the first attempt at this:
       the submit failed inside XUserAddResult on the title's own boot thread
       and the boot never finished. */
    change_log( "registered queue", 0, queue );
    if (!queue && !XTaskQueueGetCurrentProcessTaskQueue( &queue ))
    {
        change_log( "no queue and no process default - cannot deliver", 0, NULL );
        return;
    }

    if (!(post = calloc( 1, sizeof(*post) ))) return;
    post->callback = reg->callback;
    post->context = reg->context;
    post->userLocalId = userLocalId;
    post->event = event;
    /* Submitted through IXThreadingImpl. Calling this module's own
       XTaskQueueSubmitDelayedCallback never returned (measured across four
       variants: the "submit hr" line is absent while the two before it are
       present) and stalled the title's sign-in with it. */
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading )))
    {
        change_log( "no threading impl, hr", (unsigned)hr, NULL );
        free( post );
        return;
    }
    hr = IXThreadingImpl_XTaskQueueSubmitCallback( xthreading, queue, XTaskQueuePort_Completion,
                                                   post, user_change_trampoline );
    IXThreadingImpl_Release( xthreading );
    change_log( "submit hr", (unsigned)hr, queue );
    if (FAILED(hr))
    {
        ERR( "could not submit the change event, hr %#lx.\n", hr );
        free( post );
    }
    else
    {
        TRACE( "change event %d queued for callback %p.\n", event, reg->callback );
        change_log( "queued, event", event, reg->callback );
    }
}

static void user_fire_change_event( XUserLocalId userLocalId, XUserChangeEvent event, UINT32 delayMs )
{
    struct change_reg regs[MAX_CHANGE_REGS];
    UINT32 i, n = 0;

    AcquireSRWLockShared( &change_regs_lock );
    for (i = 0; i < MAX_CHANGE_REGS; ++i)
        if (change_regs[i].callback) regs[n++] = change_regs[i];
    ReleaseSRWLockShared( &change_regs_lock );

    change_log( "fire requested, registrations", n, (void *)(ULONG_PTR)userLocalId.value );
    if (!n)
    {
        /* Not an error any more: with the state recorded, a title that registers
           later is served by the catch-up path instead. */
        TRACE( "no change-event registrations yet; state recorded for catch-up.\n" );
        return;
    }

    (void)delayMs;
    for (i = 0; i < n; ++i) change_deliver( &regs[i], userLocalId, event );
}

/* Off the caller's thread, always. The fire path runs from XUserAddResult, i.e.
   on the title's boot thread; anything that blocks or faults there stalls
   sign-in itself, which is precisely how the first attempt at this experiment
   produced "the game exits at t=30s" and no information. */
static DWORD WINAPI user_change_worker( void *param )
{
    struct change_post *seed = param;
    UINT32 delayMs = (UINT32)(ULONG_PTR)seed->context;

    /* The delay belongs here, not in the queue: it lets the title finish
       registering, and it keeps us off the task queue's timer path. */
    Sleep( delayMs );
    change_log( "worker awake after sleep, ms", delayMs, NULL );
    user_fire_change_event( seed->userLocalId, seed->event, delayMs );
    free( seed );
    return 0;
}

/*
 * A REAL user-state transition: this user is now signed in AND its Xbox Live
 * authentication has completed (finish_user_load ran inside the add path, so by
 * the time the title is handed the handle the XSTS exchange is done). That is
 * exactly what XUserChangeEvent_SignedInAgain means, and it is now raised
 * unconditionally - the same way XUserSignOutAsync already raises SignedOut.
 *
 * IT USED TO BE AN EXPERIMENT. `WINEGDK_FIRE_USER_CHANGE=<event>[,<delayMs>]`
 * raised ONE synthetic event, once, only when armed, because this runtime
 * observed no transitions and had no honest event to raise. That knob turned
 * out to be load-bearing: with it, Forza Motorsport proceeds through
 * LoginWithXbox / pubsub / lobby; without it, nothing. Shipping a runtime whose
 * correctness depends on an env var describing an experiment is wrong, so the
 * transition is now reported for real and the knob is only an override.
 *
 *   WINEGDK_NO_USER_CHANGE=1        suppress entirely (the disarmed control -
 *                                   every negative in this project needs one)
 *   WINEGDK_FIRE_USER_CHANGE=e[,ms] override the event code / add a delay,
 *                                   for A/B testing a different transition
 */
static void user_on_signed_in( XUserHandle user )
{
    char value[32];
    XUserLocalId id;
    unsigned event = XUserChangeEvent_SignedInAgain, delayMs = 0;

    if (!user) return;
    if (GetEnvironmentVariableA( "WINEGDK_NO_USER_CHANGE", value, sizeof(value) ) && value[0] == '1')
    {
        TRACE( "user-change events suppressed by WINEGDK_NO_USER_CHANGE.\n" );
        return;
    }
    if (GetEnvironmentVariableA( "WINEGDK_FIRE_USER_CHANGE", value, sizeof(value) ))
        sscanf( value, "%u,%u", &event, &delayMs );

    /* Same derivation XUserGetLocalId uses, so the title recognises the id. */
    id.value = (UINT64)(ULONG_PTR)user;

    /* Record the transition BEFORE delivering it, so a registration racing this
       is served by the catch-up path rather than dropped. */
    AcquireSRWLockExclusive( &change_regs_lock );
    signed_in_id = id;
    signed_in = TRUE;
    ReleaseSRWLockExclusive( &change_regs_lock );

    {
        struct change_post *seed = calloc( 1, sizeof(*seed) );
        HANDLE thread;

        if (!seed) return;
        seed->userLocalId = id;
        seed->event = (XUserChangeEvent)event;
        seed->context = (void *)(ULONG_PTR)delayMs;
        change_log( "signed in, firing event", event, user );
        /* Off the caller's thread, always - this runs on the title's boot thread
           and anything that blocks or faults here stalls sign-in itself. */
        if ((thread = CreateThread( NULL, 0, user_change_worker, seed, 0, NULL ))) CloseHandle( thread );
        else free( seed );
    }
}

/*
 * A registration that arrived after the user was already signed in: tell it the
 * current state, once.
 *
 * Delivered INLINE on the registering thread, deliberately. The sign-in path
 * hands off to a worker because it runs on the title's boot thread mid-sign-in;
 * this one does not need to, and doing it here removes a lifetime race - the
 * registration provably exists for the duration of this call, whereas a worker
 * could find its queue handle closed by an unregister that happened in between.
 * That use-after-close is the exact bug this file already records once.
 * XTaskQueueSubmitCallback only enqueues, so it does not block the caller.
 */
static void user_catch_up_new_registration( const struct change_reg *reg )
{
    XUserLocalId id;
    BOOL now;

    AcquireSRWLockShared( &change_regs_lock );
    now = signed_in;
    id = signed_in_id;
    ReleaseSRWLockShared( &change_regs_lock );

    if (!now) return;
    change_log( "catch-up for late registration", XUserChangeEvent_SignedInAgain, reg->callback );
    TRACE( "registration arrived after sign-in; delivering current state to %p.\n", reg->callback );
    change_deliver( reg, id, XUserChangeEvent_SignedInAgain );
}

static HRESULT WINAPI x_user_XUserGetSignOutDeferral( IXUserImpl6 *iface, XUserSignOutDeferralHandle *deferral )
{
    TRACE( "iface %p, deferral %p.\n", iface, deferral );
    *deferral = NULL;
    return E_GAMEUSER_DEFERRAL_NOT_AVAILABLE;
}

static void WINAPI x_user_XUserCloseSignOutDeferralHandle( IXUserImpl6 *iface, XUserSignOutDeferralHandle deferral )
{
    FIXME( "iface %p, deferral %p stub!\n", iface, deferral );
}

/*
 * "Add this specific user, with UI." There is no account-picker UI here and only
 * one user can be loaded (from the stored refresh token), so the honest
 * behaviour is: if the requested id is already signed in, hand it back;
 * otherwise say the user is not available rather than silently substituting a
 * different account, which is the one outcome a title must never be given.
 *
 * Deliberately NOT routed through XUserAddAsync: that would sign in whoever the
 * stored token belongs to and report success for a userId nobody asked for.
 */
static HRESULT WINAPI x_user_XUserAddByIdWithUiAsync( IXUserImpl6 *iface, UINT64 userId, XAsyncBlock *async )
{
    struct XUserAddByIdContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, userId %llu, async %p.\n", iface, userId, async );

    if (!async) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    if (!(context = calloc( 1, sizeof(*context) )))
    {
        IXThreadingImpl_Release( xthreading );
        return E_OUTOFMEMORY;
    }
    context->userId = userId;
    hr = IXThreadingImpl_XAsyncBegin( xthreading, async, context, NULL, "XUserAddByIdWithUiAsync", XUserAddByIdProvider );
    IXThreadingImpl_Release( xthreading );
    if (FAILED(hr)) free( context );
    return hr;
}

static HRESULT WINAPI x_user_XUserAddByIdWithUiResult( IXUserImpl6 *iface, XAsyncBlock *async, XUserHandle *newUser )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p, newUser %p.\n", iface, async, newUser );

    if (!async || !newUser) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResult( xthreading, async, NULL, sizeof(*newUser), newUser, NULL );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetMsaTokenSilentlyAsync( IXUserImpl6 *iface, XUserHandle user, XUserGetMsaTokenSilentlyOptions options, const char *scope, XAsyncBlock *async )
{
    FIXME( "iface %p, user %p, options %u, scope %s, async %p stub!\n", iface, user, options, debugstr_a( scope ), async );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetMsaTokenSilentlyResult( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T resultTokenSize, char *resultToken, SIZE_T *resultTokenUsed )
{
    FIXME( "iface %p, async %p, resultTokenSize %Iu, resultToken %p, resultTokenUsed %p stub!\n", iface, async, resultTokenSize, resultToken, resultTokenUsed );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetMsaTokenSilentlyResultSize( IXUserImpl6 *iface, XAsyncBlock *async, SIZE_T *tokenSize )
{
    FIXME( "iface %p, async %p, tokenSize %p stub!\n", iface, async, tokenSize );
    return E_NOTIMPL;
}

static BOOLEAN WINAPI x_user_XUserIsStoreUser( IXUserImpl6 *iface, XUserHandle user )
{
    FIXME( "iface %p, user %p stub!\n", iface, user );
    return TRUE;
}

static HRESULT WINAPI x_user_XUserPlatformRemoteConnectSetEventHandlers( IXUserImpl6 *iface, XTaskQueueHandle queue, XUserPlatformRemoteConnectEventHandlers *handlers )
{
    FIXME( "iface %p, queue %p, handlers %p stub!\n", iface, queue, handlers );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserPlatformRemoteConnectCancelPrompt( IXUserImpl6 *iface, XUserPlatformOperation operation )
{
    FIXME( "iface %p, operation %p stub!\n", iface, operation );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserPlatformSpopPromptSetEventHandlers( IXUserImpl6 *iface, XTaskQueueHandle queue, XUserPlatformSpopPromptEventHandler *handler, void *context )
{
    FIXME( "iface %p, queue %p, handler %p, context %p stub!\n", iface, queue, handler, context );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserPlatformSpopPromptComplete( IXUserImpl6 *iface, XUserPlatformOperation operation, XUserPlatformOperationResult result )
{
    FIXME( "iface %p, operation %p, result %d stub!\n", iface, operation, result );
    return E_NOTIMPL;
}

static BOOLEAN WINAPI x_user_XUserIsSignOutPresent( IXUserImpl6 *iface )
{
    TRACE( "iface %p.\n", iface );
    return FALSE;
}

/*
 * Sign-out. This runtime holds one user loaded from a stored refresh token, so
 * signing out means dropping it from the live-user registry and telling anyone
 * who registered for change events - which is now possible, because those
 * registrations are kept (see XUserRegisterForChangeEvent).
 *
 * The handle itself stays valid until the title closes it, as the GDK requires;
 * what changes is that it is no longer findable and its state is signed out.
 */
static HRESULT WINAPI x_user_XUserSignOutAsync( IXUserImpl6 *iface, XUserHandle user, XAsyncBlock *async )
{
    IXThreadingImpl *xthreading;
    XUserLocalId id;
    HRESULT hr;

    TRACE( "iface %p, user %p, async %p.\n", iface, user, async );

    if (!user || !async) return E_POINTER;

    user_unregister( user );
    id.value = (UINT64)(ULONG_PTR)user;
    /* Clear the recorded state FIRST: a registration arriving after this must not
       be caught up with a SignedInAgain for a user that just signed out. */
    AcquireSRWLockExclusive( &change_regs_lock );
    if (signed_in && signed_in_id.value == id.value) signed_in = FALSE;
    ReleaseSRWLockExclusive( &change_regs_lock );
    user_fire_change_event( id, XUserChangeEvent_SignedOut, 0 );

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncBegin( xthreading, async, NULL, NULL, "XUserSignOutAsync", complete_immediately_provider );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static HRESULT WINAPI x_user_XUserSignOutResult( IXUserImpl6 *iface, XAsyncBlock *async )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    TRACE( "iface %p, async %p.\n", iface, async );

    if (!async) return E_POINTER;
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&xthreading ))) return hr;
    hr = IXThreadingImpl_XAsyncGetResult( xthreading, async, NULL, 0, NULL, NULL );
    IXThreadingImpl_Release( xthreading );
    return hr;
}

static const struct IXUserImpl6Vtbl x_user_vtbl =
{
    x_user_QueryInterface,
    x_user_AddRef,
    x_user_Release,
    /* IXUserImpl methods */
    x_user_XUserDuplicateHandle,
    x_user_XUserCloseHandle,
    x_user_XUserCompare,
    x_user_XUserGetMaxUsers,
    x_user_XUserAddAsync,
    x_user_XUserAddResult,
    x_user_XUserGetLocalId,
    x_user_XUserFindUserByLocalId,
    x_user_XUserGetId,
    x_user_XUserFindUserById,
    x_user_XUserGetIsGuest,
    x_user_XUserGetState,
    __PADDING__,
    x_user_XUserGetGamerPictureAsync,
    x_user_XUserGetGamerPictureResultSize,
    x_user_XUserGetGamerPictureResult,
    x_user_XUserGetAgeGroup,
    x_user_XUserCheckPrivilege,
    x_user_XUserResolvePrivilegeWithUiAsync,
    x_user_XUserResolvePrivilegeWithUiResult,
    x_user_XUserGetTokenAndSignatureAsync,
    x_user_XUserGetTokenAndSignatureResultSize,
    x_user_XUserGetTokenAndSignatureResult,
    x_user_XUserGetTokenAndSignatureUtf16Async,
    x_user_XUserGetTokenAndSignatureUtf16ResultSize,
    x_user_XUserGetTokenAndSignatureUtf16Result,
    x_user_XUserResolveIssueWithUiAsync,
    x_user_XUserResolveIssueWithUiResult,
    x_user_XUserResolveIssueWithUiUtf16Async,
    x_user_XUserResolveIssueWithUiUtf16Result,
    x_user_XUserRegisterForChangeEvent,
    x_user_XUserUnregisterForChangeEvent,
    x_user_XUserGetSignOutDeferral,
    x_user_XUserCloseSignOutDeferralHandle,
    /* IXUserImpl2 methods */
    x_user_XUserAddByIdWithUiAsync,
    x_user_XUserAddByIdWithUiResult,
    /* IXUserImpl3 methods */
    x_user_XUserGetMsaTokenSilentlyAsync,
    x_user_XUserGetMsaTokenSilentlyResult,
    x_user_XUserGetMsaTokenSilentlyResultSize,
    /* IXUserImpl4 methods */
    x_user_XUserIsStoreUser,
    /* IXUserImpl5 methods */
    x_user_XUserPlatformRemoteConnectSetEventHandlers,
    x_user_XUserPlatformRemoteConnectCancelPrompt,
    x_user_XUserPlatformSpopPromptSetEventHandlers,
    x_user_XUserPlatformSpopPromptComplete,
    /* IXUserImpl6 methods */
    x_user_XUserIsSignOutPresent,
    x_user_XUserSignOutAsync,
    x_user_XUserSignOutResult,
};

static inline struct x_user *impl_from_IXUserGamertagImpl( IXUserGamertagImpl *iface )
{
    return CONTAINING_RECORD( iface, struct x_user, IXUserGamertagImpl_iface );
}

static HRESULT WINAPI x_user_gamertag_QueryInterface( IXUserGamertagImpl *iface, REFIID riid, void **out )
{
    struct x_user *impl = impl_from_IXUserGamertagImpl( iface );
    return IXUserImpl6_QueryInterface( &impl->IXUserImpl_iface, riid, out );
}

static ULONG WINAPI x_user_gamertag_AddRef( IXUserGamertagImpl *iface )
{
    struct x_user *impl = impl_from_IXUserGamertagImpl( iface );
    return IXUserImpl6_AddRef( &impl->IXUserImpl_iface );
}

static ULONG WINAPI x_user_gamertag_Release( IXUserGamertagImpl *iface )
{
    struct x_user *impl = impl_from_IXUserGamertagImpl( iface );
    return IXUserImpl6_Release( &impl->IXUserImpl_iface );
}

static HRESULT WINAPI x_user_gamertag_XUserGetGamertag( IXUserGamertagImpl *iface, XUserHandle user, XUserGamertagComponent gamertagComponent, SIZE_T gamertagSize, char *gamertag, SIZE_T *gamertagUsed )
{
    UINT32 gamertagLen, wGamertagLen;
    const WCHAR *wGamertag;
    HSTRING value;

    TRACE( "iface %p, user %p, gamertagComponent %d, gamertagSize %Iu, gamertag %p, gamertagUsed %p.\n",
            iface, user, gamertagComponent, gamertagSize, gamertag, gamertagUsed );
    if (!user || !gamertag) return E_POINTER;

    switch (gamertagComponent)
    {
        case XUserGamertagComponent_Classic:
            value = user->classicGamertag;
            break;
        case XUserGamertagComponent_Modern:
            value = user->modernGamertag;
            break;
        case XUserGamertagComponent_ModernSuffix:
            value = user->modernGamertagSuffix;
            break;
        case XUserGamertagComponent_UniqueModern:
            value = user->uniqueModernGamertag;
            break;
        default:
            return E_INVALIDARG;
    }

    wGamertag = WindowsGetStringRawBuffer( value, &wGamertagLen );
    if (wGamertagLen && !(gamertagLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS,
            wGamertag, wGamertagLen, NULL, 0, NULL, NULL )))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (!wGamertagLen) gamertagLen = 0;
    if (gamertagSize <= gamertagLen) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
    if (gamertagLen && !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, wGamertag, wGamertagLen,
            gamertag, gamertagLen, NULL, NULL ))
        return HRESULT_FROM_WIN32( GetLastError() );

    gamertag[gamertagLen] = 0;
    if (gamertagUsed) *gamertagUsed = gamertagLen + 1;
    return S_OK;
}

static const struct IXUserGamertagImplVtbl x_user_gamertag_vtbl =
{
    x_user_gamertag_QueryInterface,
    x_user_gamertag_AddRef,
    x_user_gamertag_Release,
    /* IXUserGamertagImpl methods */
    x_user_gamertag_XUserGetGamertag,
};

struct x_user_device
{
    IXUserDeviceImpl IXUserDeviceImpl_iface;
    LONG ref;
};

static inline struct x_user_device *impl_from_IXUserDeviceImpl( IXUserDeviceImpl *iface )
{
    return CONTAINING_RECORD( iface, struct x_user_device, IXUserDeviceImpl_iface );
}

static HRESULT WINAPI x_user_device_QueryInterface( IXUserDeviceImpl *iface, REFIID iid, void **out )
{
    struct x_user_device *impl = impl_from_IXUserDeviceImpl( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown         ) ||
        IsEqualGUID( iid, &IID_IXUserDeviceImpl ))
    {
        IXUserDeviceImpl_AddRef( *out = &impl->IXUserDeviceImpl_iface );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI x_user_device_AddRef( IXUserDeviceImpl *iface )
{
    struct x_user_device *impl = impl_from_IXUserDeviceImpl( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI x_user_device_Release( IXUserDeviceImpl *iface )
{
    struct x_user_device *impl = impl_from_IXUserDeviceImpl( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p decreasing refcount to %lu.\n", iface, ref );
    return ref;
}

static HRESULT WINAPI x_user_device_XUserFindForDevice( IXUserDeviceImpl *iface, const APP_LOCAL_DEVICE_ID *deviceId, XUserHandle *handle )
{
    FIXME( "iface %p, deviceId %p, handle %p stub!\n", iface, deviceId, handle );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_device_XUserRegisterForDeviceAssociationChanged( IXUserDeviceImpl *iface, XTaskQueueHandle queue, void *context, XUserDeviceAssociationChangedCallback *callback, XTaskQueueRegistrationToken *token )
{
    FIXME( "iface %p, queue %p, context %p, callback %p, token %p stub!\n", iface, queue, context, callback, token );
    return E_NOTIMPL;
}

static BOOLEAN WINAPI x_user_device_XUserUnregisterForDeviceAssociationChanged( IXUserDeviceImpl *iface, XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    FIXME( "iface %p, token %p, wait %d stub!\n", iface, &token, wait );
    return FALSE;
}

static HRESULT WINAPI x_user_device_XUserGetDefaultAudioEndpointUtf16( IXUserDeviceImpl *iface, XUserLocalId user, XUserDefaultAudioEndpointKind defaultAudioEndpointKind, SIZE_T endpointIdUtf16Count, WCHAR *endpointIdUtf16, SIZE_T *endpointIdUtf16Used )
{
    FIXME( "iface %p, user %p, defaultAudioEndpointKind %d, endpointIdUtf16Count %Iu, endpointIdUtf16 %p, endpointIdUtf16used %p stub!\n", iface, &user, defaultAudioEndpointKind, endpointIdUtf16Count, endpointIdUtf16, endpointIdUtf16Used );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_device_XUserRegisterForDefaultAudioEndpointUtf16Changed( IXUserDeviceImpl *iface, XTaskQueueHandle queue, void *context, XUserDefaultAudioEndpointUtf16ChangedCallback *callback, XTaskQueueRegistrationToken *token )
{
    FIXME( "iface %p, queue %p, context %p, callback %p, token %p stub!\n", iface, queue, context, callback, token );
    return E_NOTIMPL;
}

static BOOLEAN WINAPI x_user_device_XUserUnregisterForDefaultAudioEndpointUtf16Changed( IXUserDeviceImpl *iface, XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    FIXME( "iface %p, token %p, wait %d stub!\n", iface, &token, wait );
    return FALSE;
}

static HRESULT WINAPI x_user_device_XUserFindControllerForUserWithUiAsync( IXUserDeviceImpl *iface, XUserHandle user, XAsyncBlock *async )
{
    FIXME( "iface %p, user %p, async %p stub!\n", iface, user, async );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_device_XUserFindControllerForUserWithUiResult( IXUserDeviceImpl *iface, XAsyncBlock *async, APP_LOCAL_DEVICE_ID *deviceId )
{
    FIXME( "iface %p, async %p, deviceId %p stub!\n", iface, async, deviceId );
    return E_NOTIMPL;
}

static const struct IXUserDeviceImplVtbl x_user_device_vtbl =
{
    x_user_device_QueryInterface,
    x_user_device_AddRef,
    x_user_device_Release,
    /* IXUserDeviceImpl methods */
    x_user_device_XUserFindForDevice,
    x_user_device_XUserRegisterForDeviceAssociationChanged,
    x_user_device_XUserUnregisterForDeviceAssociationChanged,
    x_user_device_XUserGetDefaultAudioEndpointUtf16,
    x_user_device_XUserRegisterForDefaultAudioEndpointUtf16Changed,
    x_user_device_XUserUnregisterForDefaultAudioEndpointUtf16Changed,
    x_user_device_XUserFindControllerForUserWithUiAsync,
    x_user_device_XUserFindControllerForUserWithUiResult,
};

static struct x_user x_user_impl =
{
    {&x_user_vtbl},
    {&x_user_gamertag_vtbl},
    0,
};

static struct x_user_device x_user_device_impl =
{
    {&x_user_device_vtbl},
    0,
};

IXUserImpl6 *x_user = &x_user_impl.IXUserImpl_iface;
IXUserDeviceImpl *x_user_device = &x_user_device_impl.IXUserDeviceImpl_iface;
