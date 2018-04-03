// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/tlsio_options.h"
#include "tls_direct.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFError.h>
#include <CFNetwork/CFSocketStream.h>
#include <Security/SecureTransport.h>

typedef struct TLS_DIRECT_CONTEXT_TAG
{
    CFReadStreamRef sockRead;
    CFWriteStreamRef sockWrite;
} TLS_DIRECT_CONTEXT;

// No error checking needed here - handled by the caller
TLS_DIRECT_CONTEXT_HANDLE tls_direct_create()
{
    TLS_DIRECT_CONTEXT_HANDLE result = malloc(sizeof(TLS_DIRECT_CONTEXT));
    if (result != NULL)
    {
        result->sockRead = NULL;
        result->sockWrite = NULL;
    }
    return result;
}


TLS_ASYNC_RESULT tls_direct_open(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance)
{
    TLS_ASYNC_RESULT result;
    TLS_DIRECT_CONTEXT* context = (TLS_DIRECT_CONTEXT*)tls_direct_instance->context;
    
    CFStringRef hostname;
    // This will pretty much only fail if we run out of memory
    if (NULL == (hostname = CFStringCreateWithCString(NULL, tls_direct_instance->hostname, kCFStringEncodingUTF8)))
    {
        /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
        LogError("CFStringCreateWithCString failed");
        result = TLS_ASYNC_RESULT_FAILURE;
    }
    else
    {
        CFStreamCreatePairWithSocketToHost(NULL, hostname, tls_direct_instance->port, &context->sockRead, &context->sockWrite);
        if (context->sockRead != NULL && context->sockWrite != NULL)
        {
            if (CFReadStreamSetProperty(context->sockRead, kCFStreamPropertySSLSettings, kCFStreamSocketSecurityLevelNegotiatedSSL))
            {
                if (CFReadStreamOpen(context->sockRead) && CFWriteStreamOpen(context->sockWrite))
                {
                    result = TLS_ASYNC_RESULT_SUCCESS;
                }
                else
                {
                    CFErrorRef readError = CFReadStreamCopyError(context->sockRead);
                    CFErrorRef writeError = CFWriteStreamCopyError(context->sockWrite);

                    LogInfo("Error opening streams - read error=%d;write error=%d", CFErrorGetCode(readError), CFErrorGetCode(writeError));
                    result = TLS_ASYNC_RESULT_FAILURE;
                }
            }
            else
            {
                LogError("Failed to set socket properties");
                result = TLS_ASYNC_RESULT_FAILURE;
            }
        }
        else
        {
            LogError("Unable to create socket pair");
            result = TLS_ASYNC_RESULT_FAILURE;
        }
    }
    return result;
}


// Returns 0 for waiting, positive for chars read, or TLS_ASYNC_RW_RESULT_FAILURE
// Guaranteed to be in the open state, so no need to check for NULLs
int tls_direct_read(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance, uint8_t* buffer, uint32_t buffer_size)
{
    int rcv_bytes;
    TLS_DIRECT_CONTEXT* context = (TLS_DIRECT_CONTEXT*)tls_direct_instance->context;
    if (CFReadStreamHasBytesAvailable(tls_direct_instance->context->sockRead))
    {
        // The buffer_size is guaranteed by the calling framweork to be less than INT_MAX
        // in order to ensure that this cast is safe
        rcv_bytes = (int)CFReadStreamRead(context->sockRead, buffer, (CFIndex)(sizeof(buffer)));
    }
    else
    {
        rcv_bytes = 0;
    }
    return rcv_bytes;
}

// Returns 0 for waiting, positive for chars writted, or TLS_ASYNC_RW_RESULT_FAILURE
int tls_direct_write(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance, const uint8_t* buffer, uint32_t count)
{
    int result;
    TLS_DIRECT_CONTEXT* context = (TLS_DIRECT_CONTEXT*)tls_direct_instance->context;
    // Check to see if the socket will not block
    if (CFWriteStreamCanAcceptBytes(context->sockWrite))
    {
        // The count is guaranteed by the calling framweork to be less than INT_MAX
        // in order to ensure that this cast is safe
        result = (int)CFWriteStreamWrite(context->sockWrite, buffer, count);
        if (result <= 0)
        {
            // The write did not succeed. It may be busy, or it may be broken
            CFErrorRef write_error = CFWriteStreamCopyError(context->sockWrite);
            if (CFErrorGetCode(write_error) != errSSLWouldBlock)
            {
                LogInfo("Hard error from CFWriteStreamWrite: %d", CFErrorGetCode(write_error));
                result = TLS_ASYNC_RW_RESULT_FAILURE;
            }
            else
            {
                // The errSSLWouldBlock error is defined as a recoverable error and should just be retried
                LogInfo("errSSLWouldBlock on write");
                result = 0;
            }
        }
    }
    else
    {
        result = 0;
    }

    return result;
}

// No need to check tls_direct_instance or its context for NULL
void tls_direct_close(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance)
{
    TLS_DIRECT_CONTEXT* context = (TLS_DIRECT_CONTEXT*)tls_direct_instance->context;
    if (context->sockRead != NULL)
    {
        CFReadStreamClose(context->sockRead);
        CFRelease(context->sockRead);
        context->sockRead = NULL;
    }

    if (context->sockWrite != NULL)
    {
        CFWriteStreamClose(context->sockWrite);
        CFRelease(context->sockWrite);
        context->sockWrite = NULL;
    }
}

