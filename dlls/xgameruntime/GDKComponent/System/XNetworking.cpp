/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XNetworking
 * 
 * Written by Weather
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

#include "../../private.h"

#include <cstring>
#include <atomic>
#include <winhttp.h>

WINE_DEFAULT_DEBUG_CHANNEL(gdkc);

static HRESULT WINAPI security_information_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    IXThreadingImpl *threading;
    HRESULT hr;

    TRACE( "op %u, asyncBlock %p, bufferSize %Iu, buffer %p.\n",
            static_cast<unsigned int>(op), data->async, data->bufferSize, data->buffer );
    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
        return hr;

    switch (op)
    {
        case XAsyncOp::Begin:
            hr = threading->XAsyncSchedule( data->async, 0 );
            break;
        case XAsyncOp::DoWork:
            threading->XAsyncComplete( data->async, S_OK, sizeof(XNetworkingSecurityInformation) );
            hr = S_OK;
            break;
        case XAsyncOp::GetResult:
        {
            auto *securityInformation = static_cast<XNetworkingSecurityInformation *>(data->buffer);
            securityInformation->enabledHttpSecurityProtocolFlags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1
                    | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
            securityInformation->thumbprintCount = 0;
            securityInformation->thumbprints = nullptr;
            hr = S_OK;
            break;
        }
        case XAsyncOp::Cancel:
        case XAsyncOp::Cleanup:
            hr = S_OK;
            break;
    }

    threading->Release();
    return hr;
}



/*
 * The preferred local UDP multiplayer port.
 *
 * On a console this is managed by the system network stack, which reserves a
 * port for title multiplayer traffic and can change it at runtime. Off-console
 * there is no such manager, and the correct answer is not E_NOTIMPL: a title
 * that asks for its multiplayer port and is told the call does not exist has no
 * port to bind, and this is the family Forza Motorsport's missing multiplayer
 * step (ListBuildSummariesV2 / ListQosServersForTitle) would reach for.
 *
 * 3074 is the port Xbox Live multiplayer has used since the original Xbox and is
 * what the GDK documents as the default; WINEGDK_MP_PORT overrides it for anyone
 * who needs a different one. The value never changes here, which is why the
 * "changed" registration below is accepted and simply never fires - there is no
 * system manager to change it.
 */
#define DEFAULT_MP_PORT 3074

static UINT16 preferred_mp_port( void )
{
    char value[16];
    if (GetEnvironmentVariableA( "WINEGDK_MP_PORT", value, sizeof(value) ))
    {
        int port = atoi( value );
        if (port > 0 && port < 65536) return (UINT16)port;
    }
    return DEFAULT_MP_PORT;
}

static HRESULT WINAPI preferred_port_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    IXThreadingImpl *threading;
    HRESULT hr;

    if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
        return hr;

    switch (op)
    {
        case XAsyncOp::Begin:
            hr = threading->XAsyncSchedule( data->async, 0 );
            break;
        case XAsyncOp::DoWork:
            threading->XAsyncComplete( data->async, S_OK, sizeof(UINT16) );
            hr = S_OK;
            break;
        case XAsyncOp::GetResult:
            *static_cast<UINT16 *>(data->buffer) = preferred_mp_port();
            hr = S_OK;
            break;
        default:
            hr = S_OK;
            break;
    }

    threading->Release();
    return hr;
}

class XNetworkingImpl : 
    public IXNetworkingImpl
{
public:
    HRESULT WINAPI QueryInterface( REFIID iid, void **out )
    {
        TRACE( "iface %p, iid %s, out %p.\n", this, debugstr_guid( &iid ), out );

        if (!out) return E_POINTER;
        *out = nullptr;

        if ( iid == __uuidof( IUnknown ) ||
             iid == __uuidof( IInspectable ) ||
             iid == __uuidof( IAgileObject ) ||
             iid == __uuidof( IXNetworkingImpl ) ||
             iid == __uuidof( IXNetworkingImpl2 ) )
        {
            AddRef();
            *out = static_cast<IXNetworkingImpl *>(this);
            return S_OK;
        }

        FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( &iid ) );
        *out = nullptr;
        return E_NOINTERFACE;
    }

    ULONG WINAPI 
    AddRef() noexcept override
    {
        ULONG curr = static_cast<ULONG>(++ref);
        TRACE( "iface %p increasing refcount to %lu.\n", this, curr );
        return curr;
    }

    ULONG WINAPI 
    Release() noexcept override
    {
        ULONG curr = static_cast<ULONG>(--ref);
        TRACE( "iface %p decreasing refcount to %lu.\n", this, curr );

        // Polymorphic classes should not be deleted.
        /*
        if ( !curr )
            delete this;
        */

        return curr;
    }

    HRESULT WINAPI XNetworkingQueryPreferredLocalUdpMultiplayerPort( UINT16 *preferredLocalUdpMultiplayerPort ) override
    {
        TRACE( "preferredLocalUdpMultiplayerPort %p.\n", preferredLocalUdpMultiplayerPort );
        if (!preferredLocalUdpMultiplayerPort) return E_POINTER;
        *preferredLocalUdpMultiplayerPort = preferred_mp_port();
        return S_OK;
    }

    HRESULT WINAPI XNetworkingQueryPreferredLocalUdpMultiplayerPortAsync( XAsyncBlock *asyncBlock ) override
    {
        IXThreadingImpl *threading;
        HRESULT hr;

        TRACE( "asyncBlock %p.\n", asyncBlock );
        if (!asyncBlock) return E_POINTER;
        if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
            return hr;
        hr = threading->XAsyncBegin( asyncBlock, nullptr, nullptr,
                                     "XNetworkingQueryPreferredLocalUdpMultiplayerPortAsync",
                                     preferred_port_provider );
        threading->Release();
        return hr;
    }

    HRESULT WINAPI XNetworkingQueryPreferredLocalUdpMultiplayerPortAsyncResult( XAsyncBlock *asyncBlock, UINT16 *preferredLocalUdpMultiplayerPort ) override
    {
        IXThreadingImpl *threading;
        HRESULT hr;

        TRACE( "asyncBlock %p, preferredLocalUdpMultiplayerPort %p.\n",
               asyncBlock, preferredLocalUdpMultiplayerPort );
        if (!asyncBlock || !preferredLocalUdpMultiplayerPort) return E_POINTER;
        if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
            return hr;
        hr = threading->XAsyncGetResult( asyncBlock, nullptr, sizeof(UINT16),
                                         preferredLocalUdpMultiplayerPort, nullptr );
        threading->Release();
        return hr;
    }

    /* Accepted and recorded, but it can never fire: this port is a constant here,
       and there is no system network manager to change it. Returning a valid
       token is still right - the title's registration succeeds, and it simply
       never hears about a change that never happens. */
    HRESULT WINAPI XNetworkingRegisterPreferredLocalUdpMultiplayerPortChanged( XTaskQueueHandle queue, PVOID context, XNetworkingPreferredLocalUdpMultiplayerPortChangedCallback *callback, XTaskQueueRegistrationToken *token ) override
    {
        TRACE( "queue %p, context %p, callback %p, token %p.\n", queue, context, callback, token );
        if (!callback || !token) return E_POINTER;
        token->token = 1;
        return S_OK;
    }

    BOOLEAN WINAPI XNetworkingUnregisterPreferredLocalUdpMultiplayerPortChanged( XTaskQueueRegistrationToken token, BOOLEAN wait ) override
    {
        FIXME( "token %p, wait %d stub!\n", &token, wait );
        return FALSE;
    }

    HRESULT WINAPI XNetworkingQuerySecurityInformationForUrlAsync( LPCSTR url, XAsyncBlock *asyncBlock ) override
    {
        IXThreadingImpl *threading;
        HRESULT hr;

        TRACE( "url %s, asyncBlock %p.\n", debugstr_a( url ), asyncBlock );
        if (!url || !asyncBlock) return E_POINTER;
        if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
            return hr;
        hr = threading->XAsyncBegin( asyncBlock, nullptr, nullptr,
                "XNetworkingQuerySecurityInformationForUrlAsync", security_information_provider );
        threading->Release();
        return hr;
    }

    HRESULT WINAPI XNetworkingQuerySecurityInformationForUrlAsyncResultSize( XAsyncBlock *asyncBlock, SIZE_T *securityInformationBufferByteCount ) override
    {
        IXThreadingImpl *threading;
        HRESULT hr;

        TRACE( "asyncBlock %p, securityInformationBufferByteCount %p.\n", asyncBlock, securityInformationBufferByteCount );
        if (!asyncBlock || !securityInformationBufferByteCount) return E_POINTER;
        if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
            return hr;
        hr = threading->XAsyncGetResultSize( asyncBlock, securityInformationBufferByteCount );
        threading->Release();
        return hr;
    }

    HRESULT WINAPI XNetworkingQuerySecurityInformationForUrlAsyncResult( XAsyncBlock *asyncBlock, SIZE_T securityInformationBufferByteCount, SIZE_T *securityInformationBufferByteCountUsed, UINT8 *securityInformationBuffer, XNetworkingSecurityInformation **securityInformation ) override
    {
        IXThreadingImpl *threading;
        HRESULT hr;

        TRACE( "asyncBlock %p, securityInformationBufferByteCount %Iu, securityInformationBufferByteCountUsed %p, securityInformationBuffer %p, securityInformation %p.\n",
                asyncBlock, securityInformationBufferByteCount, securityInformationBufferByteCountUsed, securityInformationBuffer, securityInformation );
        if (!asyncBlock || !securityInformationBuffer || !securityInformation) return E_POINTER;
        if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
            return hr;
        if (SUCCEEDED(hr = threading->XAsyncGetResult( asyncBlock, nullptr, securityInformationBufferByteCount,
                securityInformationBuffer, securityInformationBufferByteCountUsed )))
            *securityInformation = reinterpret_cast<XNetworkingSecurityInformation *>(securityInformationBuffer);
        threading->Release();
        return hr;
    }

    HRESULT WINAPI XNetworkingQuerySecurityInformationForUrlUtf16Async( LPCWSTR url, XAsyncBlock *asyncBlock ) override
    {
        IXThreadingImpl *threading;
        HRESULT hr;

        TRACE( "url %s, asyncBlock %p.\n", debugstr_w( url ), asyncBlock );
        if (!url || !asyncBlock) return E_POINTER;
        if (FAILED(hr = QueryApiImpl( &CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading )))
            return hr;
        hr = threading->XAsyncBegin( asyncBlock, nullptr, nullptr,
                "XNetworkingQuerySecurityInformationForUrlUtf16Async", security_information_provider );
        threading->Release();
        return hr;
    }

    HRESULT WINAPI XNetworkingQuerySecurityInformationForUrlUtf16AsyncResultSize( XAsyncBlock *asyncBlock, SIZE_T *securityInformationBufferByteCount ) override
    {
        return XNetworkingQuerySecurityInformationForUrlAsyncResultSize( asyncBlock, securityInformationBufferByteCount );
    }

    HRESULT WINAPI XNetworkingQuerySecurityInformationForUrlUtf16AsyncResult( XAsyncBlock *asyncBlock, SIZE_T securityInformationBufferByteCount, SIZE_T *securityInformationBufferByteCountUsed, UINT8 *securityInformationBuffer, XNetworkingSecurityInformation **securityInformation ) override
    {
        return XNetworkingQuerySecurityInformationForUrlAsyncResult( asyncBlock, securityInformationBufferByteCount,
                securityInformationBufferByteCountUsed, securityInformationBuffer, securityInformation );
    }

    HRESULT WINAPI XNetworkingVerifyServerCertificate( PVOID requestHandle, const XNetworkingSecurityInformation *securityInformation ) override
    {
        FIXME( "requestHandle %p, securityInformation %p stub!\n", requestHandle, securityInformation );
        return S_OK;
    }

    HRESULT WINAPI XNetworkingGetConnectivityHint( XNetworkingConnectivityHint *connectivityHint ) override
    {
        XNetworkingConnectivityHint hint;

        TRACE( "connectivityHint %p\n", connectivityHint );

        /*
         * IANA ifType. 0 IS NOT A VALID VALUE - the IANA registry starts at 1
         * (other), and 6 is ethernetCsmacd. A title that sanity-checks the
         * interface it has been handed sees 0 as "no interface" and can conclude
         * it is not really on a network, which is indistinguishable from being
         * offline no matter how well the rest of the stack works.
         *
         * There is still no way to read the NDIS type from userspace here, so
         * this reports the honest common case rather than an impossible one:
         * a wired Ethernet adapter. WINEGDK_IANA_IFTYPE overrides it (71 =
         * ieee80211 for Wi-Fi).
         */
        hint.ianaInterfaceType = 6; // ethernetCsmacd
        {
            char value[16];
            if (GetEnvironmentVariableA( "WINEGDK_IANA_IFTYPE", value, sizeof(value) ))
            {
                int t = atoi( value );
                if (t > 0 && t < 300) hint.ianaInterfaceType = (UINT32)t;
            }
        }
        hint.roaming = FALSE;
        hint.overDataLimit = FALSE;
        hint.networkInitialized = TRUE;
        hint.approachingDataLimit = FALSE;
        hint.connectivityLevel = XNetworkingConnectivityLevelHint::InternetAccess;
        hint.connectivityCost = XNetworkingConnectivityCostHint::Unrestricted;

        *connectivityHint = hint;

        return S_OK;
    }

    HRESULT WINAPI XNetworkingRegisterConnectivityHintChanged( XTaskQueueHandle queue, PVOID context, XNetworkingConnectivityHintChangedCallback *callback, XTaskQueueRegistrationToken *token ) override
    {
        XNetworkingConnectivityHint hint;

        TRACE( "queue %p, context %p, callback %p, token %p.\n", queue, context, callback, token );
        if (!callback || !token) return E_POINTER;
        /* Delivered inline rather than on the caller's queue - the connectivity
           here never changes, so this one call IS the whole notification, and a
           title that waits for it gets it before this returns. */
        XNetworkingGetConnectivityHint( &hint );
        callback( context, &hint );
        token->token = 1;
        return S_OK;
    }

    /* Returning FALSE said "the registration could not be removed", which is
       wrong - there is nothing to remove, and a title that checks the result can
       treat a failed unregister as a leak it must work around. */
    BOOLEAN WINAPI XNetworkingUnregisterConnectivityHintChanged( XTaskQueueRegistrationToken token, BOOLEAN wait ) override
    {
        TRACE( "token %llu, wait %d.\n", token.token, wait );
        return TRUE;
    }

private:
    std::atomic_long ref{ 1 };
};

static XNetworkingImpl g_x_networking;

IXNetworkingImpl *x_networking = static_cast<IXNetworkingImpl*>(&g_x_networking);