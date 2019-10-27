/*
 * Copyright 2011 Samuel Serapión
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
 *
 */
#include "ntlmssp.h"
#include "ciphers.h"
#include "protocol.h"
#include "smbdefs.h"
#include "smbhelper.h"
#include "smbincludes.h"
#include "samba/lib/talloc/talloc.h"

#include "wine/debug.h"
WINE_DEFAULT_DEBUG_CHANNEL(ntlm);

/***********************************************************************
 *             EncryptMessage
 */
SECURITY_STATUS SEC_ENTRY EncryptMessage(PCtxtHandle phContext,
        ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
    #ifdef USE_SAMBA

    PNTLMSSP_CONTEXT_SVR ctx;
    PSecBuffer data_buffer = NULL;
    PSecBuffer signature_buffer = NULL;
    int index;
    NTSTATUS st;
    DATA_BLOB sig;
    struct gensec_security *gs;
    struct ntlmssp_state *state;
    struct gensec_ntlmssp_context *gensec_ntlmssp;

    ERR("EncryptMessage(%p %d %p %d)\n", phContext, fQOP, pMessage, MessageSeqNo);

    if(fQOP)
        FIXME("Ignoring fQOP\n");

    if(!phContext)
        return SEC_E_INVALID_HANDLE;

    ctx = NtlmReferenceContextSvr(phContext->dwLower);
    if (!ctx)
    {
        ERR("no context\n");
        return SEC_E_INVALID_HANDLE;
    }

    TRACE("pMessage->cBuffers %d\n", pMessage->cBuffers);
    /* extract data and signature buffers */
    for (index = 0; index < (int) pMessage->cBuffers; index++)
    {
        TRACE("pMessage->pBuffers[index].BufferType %d\n", pMessage->pBuffers[index].BufferType);
        if (pMessage->pBuffers[index].BufferType == SECBUFFER_DATA)
            data_buffer = &pMessage->pBuffers[index];
        else if (pMessage->pBuffers[index].BufferType == SECBUFFER_TOKEN)
            signature_buffer = &pMessage->pBuffers[index];
    }

    gs = ctx->samba_gs;

	gensec_ntlmssp = talloc_get_type_abort(gs->private_data,
				                           struct gensec_ntlmssp_context);
    state = gensec_ntlmssp->ntlmssp_state;

__debugbreak();
    st = ntlmssp_seal_packet(state, NULL,
                             data_buffer->pvBuffer, data_buffer->cbBuffer,
                             data_buffer->pvBuffer, data_buffer->cbBuffer,
                             &sig);
    if (!NT_STATUS_IS_OK(st))
        return error_nt2sec(st);

    if (signature_buffer->cbBuffer < sig.length)
        return SEC_E_INSUFFICIENT_MEMORY;
    signature_buffer->cbBuffer = sig.length;
    memcpy(signature_buffer->pvBuffer, sig.data, sig.length);

    talloc_free(sig.data);

    return SEC_E_OK;
    #else
    SECURITY_STATUS ret = SEC_E_OK;
    BOOL bRet;
    PSecBuffer data_buffer = NULL;
    PSecBuffer signature_buffer = NULL;
    prc4_key pSealHandle;
    PBYTE pSignKey;
    //PNTLMSSP_CONTEXT_MSG cli_msg;
    PULONG pSeqNum;
    ULONG index, cli_NegFlg;

    ERR("EncryptMessage(%p %d %p %d)\n", phContext, fQOP, pMessage, MessageSeqNo);

    if(fQOP)
        FIXME("Ignoring fQOP\n");

    if(!phContext)
        return SEC_E_INVALID_HANDLE;

    if(!pMessage || !pMessage->pBuffers || pMessage->cBuffers < 2)
        return SEC_E_INVALID_TOKEN;

    /* get context, need to free it later! */
    /*cli_msg = */NtlmReferenceContextMsg(phContext->dwLower, TRUE,
                                      &cli_NegFlg, &pSealHandle, &pSignKey, &pSeqNum);
    /*if (!ctxMsg->SendSealKey)
    {
        TRACE("context->SendSealKey is NULL\n");
        ret = SEC_E_INVALID_TOKEN;
        goto exit;
    }*/

    TRACE("pMessage->cBuffers %d\n", pMessage->cBuffers);
    /* extract data and signature buffers */
    for (index = 0; index < (int) pMessage->cBuffers; index++)
    {
        TRACE("pMessage->pBuffers[index].BufferType %d\n", pMessage->pBuffers[index].BufferType);
        if (pMessage->pBuffers[index].BufferType == SECBUFFER_DATA)
            data_buffer = &pMessage->pBuffers[index];
        else if (pMessage->pBuffers[index].BufferType == SECBUFFER_TOKEN)
            signature_buffer = &pMessage->pBuffers[index];
    }

    if (!data_buffer || !signature_buffer)
    {
        ERR("No data or tokens provided!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto exit;
    }

    if (signature_buffer->cbBuffer < sizeof(NTLMSSP_MESSAGE_SIGNATURE))
    {
        ret = SEC_E_BUFFER_TOO_SMALL;
        goto exit;
    }

    //printf("SealingKey (Client)\n");
    //NtlmPrintHexDump(cli_msg->ClientSealingKey, NTLM_SEALINGKEY_LENGTH);
    //printf("SealingKey (Server)\n");
    //NtlmPrintHexDump(cli_msg->ServerSealingKey, NTLM_SEALINGKEY_LENGTH);
    //printf("SigningKey (Client)\n");
    //NtlmPrintHexDump(cli_msg->ClientSigningKey, NTLM_SIGNKEY_LENGTH);
    //printf("SigningKey (Server)\n");
    //NtlmPrintHexDump(cli_msg->ServerSigningKey, NTLM_SIGNKEY_LENGTH);

    bRet = SEAL(cli_NegFlg, pSealHandle, (UCHAR*)pSignKey,
                NTLM_SIGNKEY_LENGTH, pSeqNum,
                data_buffer->pvBuffer, data_buffer->cbBuffer,
                signature_buffer->pvBuffer, &signature_buffer->cbBuffer);
    if (!bRet)
    {
        ret = SEC_E_INTERNAL_ERROR;
        goto exit;
    }

    //memcpy(signature_buffer->pvBuffer, (PBYTE)(data)+datalen-16, 16);
    //memcpy(data_buffer->pvBuffer, (PBYTE)(data), datalen-16);
    NtlmPrintHexDump(signature_buffer->pvBuffer, signature_buffer->cbBuffer);
    NtlmPrintHexDump(data_buffer->pvBuffer, data_buffer->cbBuffer);

exit:
    NtlmDereferenceContext(phContext->dwLower);
    return ret;
    #endif
}

/***********************************************************************
 *             DecryptMessage
 */
SECURITY_STATUS SEC_ENTRY DecryptMessage(PCtxtHandle phContext,
        PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
    SECURITY_STATUS ret = SEC_E_OK;
    BOOL bRet;
    PSecBuffer data_buffer = NULL;
    PSecBuffer signature_buffer = NULL;
    prc4_key pSealHandle;
    PBYTE pSignKey;
    //PNTLMSSP_CONTEXT_MSG cli_msg;
    PULONG pSeqNum;
    ULONG index, cli_NegFlg, expectedSignLen;
    NTLMSSP_MESSAGE_SIGNATURE expectedSign;

    ERR("DecryptMessage(%p %p %d)\n", phContext, pMessage, MessageSeqNo);

    if(!phContext)
        return SEC_E_INVALID_HANDLE;

    if(!pMessage || !pMessage->pBuffers || pMessage->cBuffers < 2)
        return SEC_E_INVALID_TOKEN;

    /* get context, need to free it later! */
    /*cli_msg = */NtlmReferenceContextMsg(phContext->dwLower, FALSE,
                                      &cli_NegFlg, &pSealHandle, &pSignKey, &pSeqNum);
    /*if (!ctxMsg->SendSealKey)
    {
        TRACE("context->SendSealKey is NULL\n");
        ret = SEC_E_INVALID_TOKEN;
        goto exit;
    }*/

    TRACE("pMessage->cBuffers %d\n", pMessage->cBuffers);
    /* extract data and signature buffers */
    for (index = 0; index < (int) pMessage->cBuffers; index++)
    {
        TRACE("pMessage->pBuffers[index].BufferType %d\n", pMessage->pBuffers[index].BufferType);
        if (pMessage->pBuffers[index].BufferType == SECBUFFER_DATA)
            data_buffer = &pMessage->pBuffers[index];
        else if (pMessage->pBuffers[index].BufferType == SECBUFFER_TOKEN)
            signature_buffer = &pMessage->pBuffers[index];
    }

    if (!data_buffer || !signature_buffer)
    {
        ERR("No data or tokens provided!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto exit;
    }

    if (signature_buffer->cbBuffer < sizeof(NTLMSSP_MESSAGE_SIGNATURE))
    {
        ret = SEC_E_BUFFER_TOO_SMALL;
        goto exit;
    }

    //printf("SealingKey (Client)\n");
    //NtlmPrintHexDump(cli_msg->ClientSealingKey, NTLM_SEALINGKEY_LENGTH);
    //printf("SealingKey (Server)\n");
    //NtlmPrintHexDump(cli_msg->ServerSealingKey, NTLM_SEALINGKEY_LENGTH);
    //printf("SigningKey (Client)\n");
    //NtlmPrintHexDump(cli_msg->ClientSigningKey, NTLM_SIGNKEY_LENGTH);
    //printf("SigningKey (Server)\n");
    //NtlmPrintHexDump(cli_msg->ServerSigningKey, NTLM_SIGNKEY_LENGTH);

    expectedSignLen = sizeof(expectedSign);
    bRet = UNSEAL(cli_NegFlg, pSealHandle, (UCHAR*)pSignKey,
                  NTLM_SIGNKEY_LENGTH, pSeqNum,
                  data_buffer->pvBuffer, data_buffer->cbBuffer,
                  (UCHAR*)&expectedSign, &expectedSignLen);
    if (!bRet)
    {
        ret = SEC_E_INTERNAL_ERROR;
        goto exit;
    }

    printf("sign ...\n");
    NtlmPrintHexDump((UCHAR*)&expectedSign, 16);
    NtlmPrintHexDump(signature_buffer->pvBuffer, 16);

    /* validate signature */
    if ((expectedSignLen != signature_buffer->cbBuffer) ||
        (memcmp(&expectedSign, signature_buffer->pvBuffer, expectedSignLen) != 0))
    {
        ret = SEC_E_MESSAGE_ALTERED;
        goto exit;
    }

    //memcpy(signature_buffer->pvBuffer, (PBYTE)(data)+datalen-16, 16);
    //memcpy(data_buffer->pvBuffer, (PBYTE)(data), datalen-16);
    NtlmPrintHexDump(signature_buffer->pvBuffer, signature_buffer->cbBuffer);
    NtlmPrintHexDump(data_buffer->pvBuffer, data_buffer->cbBuffer);

exit:
    NtlmDereferenceContext(phContext->dwLower);
    return ret;
}
