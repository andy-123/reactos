/*
 * Copyright 2011 Samuel Serapi�n
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

#define USE_SAMBA

#include "ntlmssp.h"
#include "protocol.h"
#include "ciphers.h"

#ifdef USE_SAMBA
#include "smbhelper.h"
#include "smbincludes.h"
#include "samba/source4/auth/auth.h"
#include "samba/lib/param/loadparm.h"
#include "samba/lib/tevent/tevent_internal.h"
#endif

#include "wine/debug.h"
WINE_DEFAULT_DEBUG_CHANNEL(ntlm);


/* Returns true if all Flags in <Flags> are supported!
 * RemoveUnsupportedFlags = TRUE will remove all unsupported
 * flags from *pFlags. So result is always TRUE.*/
BOOL
ValidateNegFlg(
    IN ULONG SupportedFlags,
    IN OUT PULONG pFlags,
    IN BOOL RemoveUnsupportedFlags,
    IN BOOL ValidateLMKeyFlag)
{
    ULONG UnsupportedFlags = *pFlags & (~SupportedFlags);
    if (UnsupportedFlags)
    {
        TRACE("Flags not supported:\n");
        NtlmPrintNegotiateFlags(UnsupportedFlags);
        if (!RemoveUnsupportedFlags)
            return FALSE;
        TRACE("Removing this flags ...\n");
        *pFlags &= (~UnsupportedFlags);
    }
    /* check flag consistency MS-NLMP 2.2.2.5 NEGOTIATE */
    if (ValidateLMKeyFlag &&
        (*pFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) &&
        (*pFlags & NTLMSSP_NEGOTIATE_LM_KEY))
    {
        TRACE("Cant have both: NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_LM_KEY\n");
        if (!RemoveUnsupportedFlags)
            return FALSE;
        *pFlags &= (~NTLMSSP_NEGOTIATE_LM_KEY);
    }
    return TRUE;
}

VOID
NtlmMsgSetVersion(
    IN ULONG NegFlg,
    OUT PNTLM_WINDOWS_VERSION pVer)
{
    if (!(NegFlg & NTLMSSP_NEGOTIATE_VERSION))
    {
        memset(pVer, 0, sizeof(NTLM_WINDOWS_VERSION));
        return;
    }

    /* values for windows 2003 */
    pVer->ProductMajor = 5;
    pVer->ProductMinor = 2;
    pVer->ProductBuild = 3790;
    memset(&pVer->Reserved, 0, sizeof(pVer->Reserved));
    pVer->NtlmRevisionCurrent = NTLMSSP_REVISION_W2K3;
}

SECURITY_STATUS
CliGenerateNegotiateMessage(
    IN PNTLMSSP_CONTEXT_CLI context,
    IN ULONG ISCContextReq,
    OUT PSecBuffer OutputToken)
{
    #ifdef USE_SAMBA
    SECURITY_STATUS ret;
    NTSTATUS st;
    DATA_BLOB dataIn, dataOut;
    ULONG dummyAttr;//FIxME ... return
    struct gensec_security *gs;

    if(!OutputToken)
    {
        ERR("No output token!\n");
        return SEC_E_BUFFER_TOO_SMALL;
    }

    if(!(OutputToken->pvBuffer))
    {
        /* according to wine test */
        ERR("No output buffer!\n");
        return SEC_E_INTERNAL_ERROR;
    }

    printf("FIXME check if context->samba_gs = null / if not - reuse!\n");

    /*evctx = tevent_context_init(ctx);
    st = auth_context_create(ctx, evctx, NULL, NULL,
                             &authctx);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("auth_context_create_methods failed\n");
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }*/
    gs = context->hdr.samba_gs;
    if (!gs)
    {
        ERR("gs is NULL\n");
        return SEC_E_INTERNAL_ERROR;
    }

    st = gensec_ntlmssp_client_start(gs);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("gensec_client_start failed\n");
        return SEC_E_INTERNAL_ERROR;
    }


    dataIn.length = 0;
    dataIn.data = NULL;
    st = ntlmssp_client_initial(gs, NULL, dataIn, &dataOut);

    /* NT_STATUS_MORE_PROCESSING_REQUIRED is what we expect */
    if ((st != NT_STATUS_OK) &&
        (st != NT_STATUS_MORE_PROCESSING_REQUIRED))
    {
        ERR("ntlmssp_client_initial faield %x\n", st);
        return SEC_E_INTERNAL_ERROR; //TODO be more specific
    }

    st = CopySmbBlobToSecBuffer(ISCContextReq, &dummyAttr, &dataOut, OutputToken);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("CopySmbBlobToSecBuffer faield %x\n", st);
        return SEC_E_INTERNAL_ERROR; //TODO be more specific
    }
    
    ret = SEC_I_CONTINUE_NEEDED;
    return ret;
    #else
    PNTLMSSP_CREDENTIAL cred = context->Credential;
    PNEGOTIATE_MESSAGE_X message;
    ULONG messageSize = 0;
    ULONG_PTR offset;
    PNTLMSSP_GLOBALS g = getGlobals();

    if(!OutputToken)
    {
        ERR("No output token!\n");
        return SEC_E_BUFFER_TOO_SMALL;
    }

    if(!(OutputToken->pvBuffer))
    {
        /* according to wine test */
        ERR("No output buffer!\n");
        return SEC_E_INTERNAL_ERROR;
    }

    messageSize = sizeof(NEGOTIATE_MESSAGE_X) +
                  g->NbMachineNameOEM.bUsed +
                  g->NbDomainNameOEM.bUsed;

    /* if should not allocate */
    if (!(ISCContextReq & ISC_REQ_ALLOCATE_MEMORY))
    {
        /* not enough space */
        if(messageSize > OutputToken->cbBuffer)
            return SEC_E_BUFFER_TOO_SMALL;

        OutputToken->cbBuffer = messageSize;
    }
    else
    {
        /* allocate */
        OutputToken->pvBuffer = NtlmAllocate(messageSize);
        OutputToken->cbBuffer = messageSize;

        if(!OutputToken->pvBuffer)
            return SEC_E_INSUFFICIENT_MEMORY;
    }

    /* use allocated memory */
    message = (PNEGOTIATE_MESSAGE_X)OutputToken->pvBuffer;
    offset = (ULONG_PTR)(message+1);

    /* build message */
    strncpy(message->Signature, NTLMSSP_SIGNATURE, sizeof(NTLMSSP_SIGNATURE));
    message->MsgType = NtlmNegotiate;

    TRACE("nego message %p size %lu\n", message, messageSize);
    TRACE("context %p context->NegotiateFlags:\n",context);
    NtlmPrintNegotiateFlags(message->NegotiateFlags);

    /* local connection */
    if((!cred->DomainNameW.Buffer && !cred->UserNameW.Buffer &&
        !cred->PasswordW.Buffer) && cred->SecToken)
    {
        FIXME("try use local cached credentials?\n");
        context->NegFlg |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED |
                           NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;

        NtlmExtStringToBlob((PVOID)message,
                            &g->NbMachineNameOEM,
                            &message->OemWorkstationName,
                            &offset);
        NtlmExtStringToBlob((PVOID)message,
                            &g->NbDomainNameOEM,
                            &message->OemDomainName,
                            &offset);
    }
    else
    {
        NtlmExtStringToBlob((PVOID)message, NULL,
                            &message->OemWorkstationName,
                            &offset);
        NtlmExtStringToBlob((PVOID)message, NULL,
                            &message->OemDomainName,
                            &offset);
    }

    /* set version */
    NtlmMsgSetVersion(context->NegFlg, &message->Version);

    message->NegotiateFlags = context->NegFlg;
    /* set state */
    context->hdr.State = NegotiateSent;
    return SEC_I_CONTINUE_NEEDED;
    #endif
}

SECURITY_STATUS
SvrGenerateChallengeMessageBuildTargetInfo(
    IN OUT PEXT_DATA pTargetInfo)
{
    ULONG AvPairsLen;
    PNTLMSSP_GLOBALS_SVR gsvr = getGlobalsSvr();
#if 0 /* this is > w2k */
    FILETIME ts;
#endif

    /* init global target AV pairs */
    AvPairsLen = gsvr->NbDomainName.bUsed + //fix me: domain controller name
                 gsvr->NbMachineName.bUsed + //computer name
                 gsvr->DnsMachineName.bUsed + //dns computer name
                 gsvr->DnsMachineName.bUsed + //fix me: dns domain name
#if 0 /* this is > w2k */
                 sizeof(ts) +
                 sizeof(MSV1_0_AV_PAIR)*6;
#else
                 sizeof(MSV1_0_AV_PAIR)*5;
#endif
    if (!NtlmAvlInit(pTargetInfo, AvPairsLen))
    {
        ERR("failed to allocate NtlmAvTargetInfo\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* generate av-list */
    if (gsvr->NbMachineName.bUsed > 0)
        NtlmAvlAdd(pTargetInfo, MsvAvNbComputerName,
                   gsvr->NbMachineName.Buffer, gsvr->NbMachineName.bUsed);
    if (gsvr->NbDomainName.bUsed > 0)
        NtlmAvlAdd(pTargetInfo, MsvAvNbDomainName,
                   gsvr->NbDomainName.Buffer, gsvr->NbDomainName.bUsed);
    if (gsvr->DnsMachineName.bUsed > 0)
        NtlmAvlAdd(pTargetInfo, MsvAvDnsComputerName,
                   gsvr->DnsMachineName.Buffer, gsvr->DnsMachineName.bUsed);
    /* FIXME: This is not correct! - (same value as above??) */
    if (gsvr->DnsMachineName.bUsed > 0)
        NtlmAvlAdd(pTargetInfo, MsvAvDnsDomainName,
                   gsvr->DnsMachineName.Buffer, gsvr->DnsMachineName.bUsed);
#if 0 /* this is > w2k */
    /* timestamp */
    GetSystemTimeAsFileTime(&ts);
    NtlmAvlAdd(pTargetInfo, MsvAvTimestamp, &ts, sizeof(ts));
#endif
    /* eol */
    NtlmAvlAdd(pTargetInfo, MsvAvEOL, NULL, 0);
    //TODO: MsvAvDnsTreeName

    ERR("avlTargetInfo len 0x%x\n", pTargetInfo->bUsed);
    NtlmPrintAvPairs(pTargetInfo);
    return SEC_E_OK;
}

SECURITY_STATUS
SvrGenerateChallengeMessage(
    IN PNTLMSSP_CONTEXT_SVR Context,
    IN PNTLMSSP_CREDENTIAL Credentials,
    IN ULONG ASCContextReq,
    IN ULONG ASCRequestedFlags,
    IN ULONG negoMsgNegotiateFlags,
    OUT PSecBuffer OutputToken)
{
    SECURITY_STATUS ret = SEC_E_OK;
    PCHALLENGE_MESSAGE_X chaMessage = NULL;
    EXT_DATA avlTargetInfo;
    EXT_DATA TargetNameRef;
    ULONG messageSize, offset, chaMsgNegFlg;
    PNTLMSSP_GLOBALS_SVR gsvr = getGlobalsSvr();
    PNTLMSSP_GLOBALS g = getGlobals();

    ExtDataInit(&avlTargetInfo, NULL, 0);
    ExtDataInit(&TargetNameRef, NULL, 0);

    ret = SvrGenerateChallengeMessageBuildTargetInfo(&avlTargetInfo);
    if (ret != SEC_E_OK)
        goto done;

    /* Anyway i think spec (3.2.5.1.1) is here misleading
     * It says set
     * - chaMessage->NegotiateFlags to gsrv-CfgFlg | supported flags from nego-message
     * - In CfgFlg we SHOULD have all supported flags. So we can ignore nego-message-flags?
     * -> Sould be true for DATAGRAM-Mode
     * 2.2.1.2 should be the right way to do (not DTAGRAM).
     * - select supported flags from nego message flags
     * -> connection oriented mode (not DATAGRAM)
     * */
    /* CONNECTION-MODE -> not gsvr-CfgFlg -> nur was supported!
     * + SYNC WITH CONTEXT!
     * */
    if (ASCContextReq & ASC_REQ_DATAGRAM)
    {
        /* ignore negoMsgNegotiateFlags - should be 0 */
        chaMsgNegFlg = gsvr->CfgFlg |
                       NTLMSSP_REQUEST_TARGET |
                       NTLMSSP_NEGOTIATE_NTLM |
                       NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                       NTLMSSP_NEGOTIATE_UNICODE;
    }
    else
    {
        chaMsgNegFlg = negoMsgNegotiateFlags;
        ValidateNegFlg(gsvr->CfgFlg, &chaMsgNegFlg, TRUE, TRUE);
        /* check: do we use all requested flags */
        if (!ValidateNegFlg(chaMsgNegFlg, &ASCRequestedFlags, FALSE, TRUE))
        {
            ERR("Server-App request for flags that are not negotiated!\n");
            ret = SEC_E_INVALID_TOKEN;
            goto done;
        }
        // MS-NLMP 3.2.5.1.1
        //If (NTLMSSP_NEGOTIATE_UNICODE is set in NEGOTIATE.NegotiateFlags)
        //Set the NTLMSSP_NEGOTIATE_UNICODE flag in
        //CHALLENGE_MESSAGE.NegotiateFlags
        //ElseIf (NTLMSSP_NEGOTIATE_OEM flag is set in NEGOTIATE.NegotiateFlag)
        //Set the NTLMSSP_NEGOTIATE_OEM flag in
        //CHALLENGE_MESSAGE.NegotiateFlags
        //EndIf
        if (negoMsgNegotiateFlags & NTLMSSP_NEGOTIATE_OEM)
        {
            chaMsgNegFlg |= NTLMSSP_NEGOTIATE_UNICODE;
            chaMsgNegFlg &= (~NTLMSSP_NEGOTIATE_OEM);
        }
        else
        {
            chaMsgNegFlg |= NTLMSSP_NEGOTIATE_OEM;
            chaMsgNegFlg &= (~NTLMSSP_NEGOTIATE_UNICODE);
        }
        // **************TODO**********
        //If (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag
        //is set in NEGOTIATE.NegotiateFlags)
        //Set the NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag in
        //CHALLENGE_MESSAGE.NegotiateFlags
        //ElseIf (NTLMSSP_NEGOTIATE_LM_KEY flag is set in NEGOTIATE.NegotiateFlag)
        //Set the NTLMSSP_NEGOTIATE_LM_KEY flag in
        //CHALLENGE_MESSAGE.NegotiateFlags
        //EndIf
        // ************************

        //If (Server is domain joined)
        //Set CHALLENGE_MESSAGE.TargetName to NbDomainName
        //Set the NTLMSSP_TARGET_TYPE_DOMAIN flag in
        //CHALLENGE_MESSAGE.NegotiateFlags
        //Else
        //Set CHALLENGE_MESSAGE.TargetName to NbMachineName
        //Set the NTLMSSP_TARGET_TYPE_SERVER flag in
        //CHALLENGE_MESSAGE.NegotiateFlags
        //EndIf
        if (/*isdomainjoined*/FALSE)
        {
            chaMsgNegFlg |= NTLMSSP_TARGET_TYPE_DOMAIN;
        }
        else
        {
            if (chaMsgNegFlg & NTLMSSP_NEGOTIATE_UNICODE)
                TargetNameRef = gsvr->NbMachineName;
            else
                TargetNameRef = g->NbMachineNameOEM;
            chaMsgNegFlg |= NTLMSSP_TARGET_TYPE_SERVER;
        }

        //Set the NTLMSSP_NEGOTIATE_TARGET_INFO and NTLMSSP_REQUEST_TARGET flags in
        //CHALLENGE_MESSAGE.NegotiateFlags
        chaMsgNegFlg |= NTLMSSP_NEGOTIATE_TARGET_INFO |
                        NTLMSSP_REQUEST_TARGET;
    }

    /* compute message size */
    messageSize = sizeof(CHALLENGE_MESSAGE_X) +
                  avlTargetInfo.bUsed +
                  TargetNameRef.bUsed;

    ERR("generating chaMessage of size %lu\n", messageSize);

    if (ASCContextReq & ASC_REQ_ALLOCATE_MEMORY)
    {
        if (messageSize > NTLM_MAX_BUF)
        {
            ret = SEC_E_INSUFFICIENT_MEMORY;
            goto done;
        }
        /*
         * according to tests ntlm does not listen to ASC_REQ_ALLOCATE_MEMORY
         * or lack thereof, furthermore the buffer size is always NTLM_MAX_BUF
         */
        OutputToken->pvBuffer = NtlmAllocate(NTLM_MAX_BUF);
        OutputToken->cbBuffer = NTLM_MAX_BUF;
    }
    else
    {
        if (OutputToken->cbBuffer < messageSize)
        {
            ret = SEC_E_BUFFER_TOO_SMALL;
            goto done;
        }
    }

    /* check allocation */
    if(!OutputToken->pvBuffer)
    {
        ret = SEC_E_INSUFFICIENT_MEMORY;
        goto done;
    }

    /* use allocated memory */
    chaMessage = (PCHALLENGE_MESSAGE_X)OutputToken->pvBuffer;

    /* build message
     * MS-NLMP 3.2.5.1.1 */
    strncpy(chaMessage->Signature, NTLMSSP_SIGNATURE, sizeof(NTLMSSP_SIGNATURE));
    chaMessage->MsgType = NtlmChallenge;
    chaMessage->NegotiateFlags = chaMsgNegFlg;

    /* generate server challenge */
    NtlmGenerateRandomBits(chaMessage->ServerChallenge, MSV1_0_CHALLENGE_LENGTH);
    /* save in context ... we need it later (AUTHENTICATE_MESSAGE) */
    memcpy(Context->ServerChallenge, chaMessage->ServerChallenge, MSV1_0_CHALLENGE_LENGTH);

    /* point to the end of chaMessage */
    offset = ((ULONG_PTR)chaMessage) + sizeof(CHALLENGE_MESSAGE_X);

    /* set target information */
    ERR("set target information chaMessage %p to len %d, offset %x\n",
        chaMessage, TargetNameRef.bUsed, offset);
    NtlmExtStringToBlob((PVOID)chaMessage, &TargetNameRef, &chaMessage->TargetName, &offset);

    ERR("set target information %p, len 0x%x\n, offset 0x%x\n", chaMessage,
        avlTargetInfo.bUsed, offset);
    NtlmExtStringToBlob((PVOID)chaMessage, &avlTargetInfo, &chaMessage->TargetInfo, &offset);

    /* set version */
    NtlmMsgSetVersion(chaMessage->NegotiateFlags, &chaMessage->Version);

    /* set state */
    Context->hdr.State = ChallengeSent;
    Context->cli_NegFlg = chaMessage->NegotiateFlags;

done:
    ExtStrFree(&avlTargetInfo);
    if (ret == SEC_E_OK)
        ret = SEC_I_CONTINUE_NEEDED;
    return ret;
}

SECURITY_STATUS
SvrHandleNegotiateMessage(
    IN ULONG_PTR hCredential,
    IN OUT PULONG_PTR phContext,
    IN ULONG ASCContextReq,
    IN PSecBuffer InputToken,
    IN PSecBuffer InputToken2,
    OUT PSecBuffer OutputToken,
    OUT PSecBuffer OutputToken2,
    OUT PULONG pASCContextAttr,
    OUT PTimeStamp ptsExpiry)
#ifdef USE_SAMBA
{
    SECURITY_STATUS ret;
    PNTLMSSP_CREDENTIAL cred = NULL;

    struct gensec_security *gs;
    struct gensec_settings *settings;
    //struct gensec_ntlmssp_context *gsctx;
    struct tevent_context *evctx;
    struct auth4_context* authctx;
    TALLOC_CTX *ctx = NULL;

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;
    NTSTATUS st;

    PNTLMSSP_CONTEXT_SVR context = NULL;
    if (*phContext == 0)
    {
        if(!(context = NtlmAllocateContextSvr()))
        {
            ret = SEC_E_INSUFFICIENT_MEMORY;
            ERR("SEC_E_INSUFFICIENT_MEMORY!\n");
            goto done;
        }

        *phContext = (ULONG_PTR)context;

        TRACE("NtlmHandleNegotiateMessage NEW hContext %lx\n", *phContext);
    }
    context = NtlmReferenceContextSvr(*phContext);

    /* get credentials */
    if (!(cred = NtlmReferenceCredential(hCredential)))
    {
        ERR("failed to get credentials!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto done;
    }
    /* must be an incomming request */
    if(!(cred->UseFlags & SECPKG_CRED_INBOUND))
    {
        ret = SEC_E_UNSUPPORTED_FUNCTION;
        goto done;
    }

    settings = smbGetGensecSettigs();

    evctx = tevent_context_init(ctx);
    st = auth_context_create(ctx, evctx, NULL, NULL,
                             &authctx);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("auth_context_create_methods failed\n");
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }
    st = gensec_server_start(NULL, settings, authctx, &gs);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("gensec_server_start faield\n");
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }
    /* todo -> move to dll init */
    st = gensec_ntlmssp_server_start(gs);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("gensec_ntlmssp_server_start faield\n");
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }

    context->hdr.samba_gs = gs;

    dataIn.data = InputToken->pvBuffer;
    dataIn.length = InputToken->cbBuffer;

    //gs.auth_context.challenge.setby = "hack";
    //gs.auth_context.challenge.data = NULL;
    //--gs.auth_context = malloc(sizeof(struct auth4_context));
    //--gs.auth_context->get_ntlm_challenge = NULL;

    //gsctx = talloc_zero(NULL, struct gensec_ntlmssp_context);
    //gs->private_data = gsctx;
    //gsctx->ntlmssp_state = talloc_zero(NULL, struct ntlmssp_state);

    st = gensec_ntlmssp_server_negotiate(gs, ctx, dataIn, &dataOut);
    /* NT_STATUS_MORE_PROCESSING_REQUIRED is what we expect */
    if ((st != NT_STATUS_OK) &&
        (st != NT_STATUS_MORE_PROCESSING_REQUIRED))
    {
        ERR("gensec_ntlmssp_server_negotiate faield %x\n", st);
        ret = SEC_E_INTERNAL_ERROR; //TODO be more specific
        goto done;
    }
    ret = SEC_I_CONTINUE_NEEDED;

    if (ASCContextReq & ASC_REQ_ALLOCATE_MEMORY)
    {
        OutputToken->cbBuffer = dataOut.length;
        OutputToken->pvBuffer = NtlmAllocate(dataOut.length);
    }
    else if (OutputToken->cbBuffer < dataOut.length)
    {
        ERR("buffer to small\n");
        ret = SEC_E_BUFFER_TOO_SMALL;
        goto done;
    }
    memcpy(OutputToken->pvBuffer, dataOut.data, dataOut.length);

    talloc_free(dataOut.data);

    //smb_iconv_open_ex(NULL, NULL, NULL, TRUE);
    //convert_string_talloc(NULL, 0,0,NULL,0,NULL,NULL);

    //talloc_free(gsctx);
    //talloc_free(&settings->lp_ctx);
    //talloc_free(settings);

done:
    if (context)
        NtlmDereferenceContext((ULONG_PTR)context);
    if (cred)
        NtlmDereferenceCredential((ULONG_PTR)cred);
    return ret;
}

#else
{
    SECURITY_STATUS ret = SEC_E_OK;
    PNEGOTIATE_MESSAGE_X negoMessage = NULL;
    PNTLMSSP_CREDENTIAL cred = NULL;
    PNTLMSSP_CONTEXT_SVR context = NULL;
    EXT_STRING_A OemDomainName, OemWorkstationName;
    ULONG ASCRequestedFlags = 0;

    ExtAStrInit(&OemDomainName, NULL);
    ExtAStrInit(&OemWorkstationName, NULL);

    if (*phContext == 0)
    {
        if(!(context = NtlmAllocateContextSvr()))
        {
            ret = SEC_E_INSUFFICIENT_MEMORY;
            ERR("SEC_E_INSUFFICIENT_MEMORY!\n");
            goto exit;
        }

        *phContext = (ULONG_PTR)context;

        TRACE("NtlmHandleNegotiateMessage NEW hContext %lx\n", *phContext);
    }

    context = NtlmReferenceContextSvr(*phContext);

    /* InputToken should contain a negotiate message */
    if(InputToken->cbBuffer > NTLM_MAX_BUF ||
        InputToken->cbBuffer < sizeof(NEGOTIATE_MESSAGE_X))
    {
        ERR("Input wrong size!!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto exit;
    }

    /* allocate a buffer for it */
    if(!(negoMessage = NtlmAllocate(sizeof(NEGOTIATE_MESSAGE_X))))
    {
        ret = SEC_E_INSUFFICIENT_MEMORY;
        goto exit;
    }

    /* copy it */
    memcpy(negoMessage, InputToken->pvBuffer, sizeof(NEGOTIATE_MESSAGE_X));

    /* validate it */
    if ((memcmp(negoMessage->Signature, NTLMSSP_SIGNATURE, 8) != 0) ||
        (negoMessage->MsgType != NtlmNegotiate))
    {
        ERR("Input message not valid!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto exit;
    }

    TRACE("Got valid nego message! with flags:\n");
    NtlmPrintNegotiateFlags(negoMessage->NegotiateFlags);

    /* get credentials */
    if(!(cred = NtlmReferenceCredential(hCredential)))
    {
        ERR("failed to get credentials!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto exit;
    }

    /* must be an incomming request */
    if(!(cred->UseFlags & SECPKG_CRED_INBOUND))
    {
        ret = SEC_E_UNSUPPORTED_FUNCTION;
        goto exit;
    }

    /* in connection oriented mode (non-DATAGRAM)
     * most of the ContextReq-flags are ignored.
     * So we have to implement only the following flags
     *   ASC_REQ_DATAGRAM - TODO
     *   ASC_REQ_LICENSING - maybe no need to implement
     *   ASC_REQ_ALLOW_NULL_SESSION - TODO
     *   ASC_REQ_ALLOCATE_MEMORY - works */
    if (ASCContextReq & ASC_REQ_DATAGRAM)
    {
        /* FIXME */
        FIXME("DATAGRAM authentication not supported!\n");
        ret = SEC_E_UNSUPPORTED_FUNCTION;
        goto exit;
    }
    if (ASCContextReq & ASC_REQ_LICENSING)
        TRACE("Ignoring ContextReq ASC_REQ_LICENSING!\n");
    if (ASCContextReq & ASC_REQ_ALLOW_NULL_SESSION)
    {
        ret = SEC_E_UNSUPPORTED_FUNCTION;
        goto exit;
    }

    /* convert flags
     * Commented out ... code has no effect ...
     * I have to figure out what to do with these flags ...
     * Seems these dosn't have any effet. Maybe this
     * changes if ASC_REQ_DATAGRAM is included ...
     * and maybe the logic is the same as for
     * InitializeSecurityContext ... todo figure out
     */
    /*if(ASCContextReq & ASC_REQ_IDENTIFY)
    {
        *pASCContextAttr |= ASC_RET_IDENTIFY;
        context->ASCRetContextFlags |= ASC_RET_IDENTIFY;
    }

    if(ASCContextReq & ASC_REQ_DATAGRAM)
    {
        *pASCContextAttr |= ASC_RET_DATAGRAM;
        context->ASCRetContextFlags |= ASC_RET_DATAGRAM;
    }

    if(ASCContextReq & ASC_REQ_CONNECTION)
    {
        *pASCContextAttr |= ASC_RET_CONNECTION;
        context->ASCRetContextFlags |= ASC_RET_CONNECTION;
    }

    if(ASCContextReq & ASC_REQ_INTEGRITY)
    {
        *pASCContextAttr |= ASC_RET_INTEGRITY;
        context->ASCRetContextFlags |= ASC_RET_INTEGRITY;
    }

    if(ASCContextReq & ASC_REQ_REPLAY_DETECT)
    {
        *pASCContextAttr |= ASC_RET_REPLAY_DETECT;
        context->ASCRetContextFlags |= ASC_RET_REPLAY_DETECT;
    }

    if(ASCContextReq & ASC_REQ_SEQUENCE_DETECT)
    {
        *pASCContextAttr |= ASC_RET_SEQUENCE_DETECT;
        context->ASCRetContextFlags |= ASC_RET_SEQUENCE_DETECT;
    }

    if(ASCContextReq & ASC_REQ_ALLOW_NULL_SESSION)
    {
        context->ASCRetContextFlags |= ASC_REQ_ALLOW_NULL_SESSION;
    }

    if(ASCContextReq & ASC_REQ_ALLOW_NON_USER_LOGONS)
    {
        *pASCContextAttr |= ASC_RET_ALLOW_NON_USER_LOGONS;
        context->ASCRetContextFlags |= ASC_RET_ALLOW_NON_USER_LOGONS;
    }*/

    /*if (negoMessage->NegotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY ||
        negoMessage->NegotiateFlags & NTLMSSP_REQUEST_TARGET)
    {
        //negotiateFlags |= NTLMSSP_TARGET_TYPE_SERVER;
        if (negoMessage->NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE)
        {
            TargetNameRef = gsvr->NbMachineName;
        }
        else if (negoMessage->NegotiateFlags & NTLMSSP_NEGOTIATE_OEM)
        {
            //negotiateFlags |= NTLMSSP_NEGOTIATE_OEM;
            TargetNameRef = g->NbMachineNameOEM;
        }
        else
        {
            ret = SEC_E_INVALID_TOKEN;
            ERR("flags invalid!\n");
            goto exit;
        }
    }*/

    /* check for local call */
    /*if ((negotiateFlags & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) &&
        (negotiateFlags & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED))
    {
        NtlmCreateExtAStrFromBlob(InputToken, negoMessage->OemDomainName,
                                  &OemDomainName);
        NtlmCreateExtAStrFromBlob(InputToken, negoMessage->OemWorkstationName,
                                  &OemWorkstationName);

        if (ExtAStrIsEqual1(&OemWorkstationName, &g->NbMachineNameOEM) &&
            ExtAStrIsEqual1(&OemDomainName, &g->NbDomainNameOEM))
        {
            TRACE("local negotiate detected!\n");
            negotiateFlags |= NTLMSSP_NEGOTIATE_LOCAL_CALL;
        }
    }*/

    //if(negoMessage->NegotiateFlags & NTLMSSP_REQUEST_INIT_RESP)
    //{
    //    *pASCContextAttr |= ASC_RET_IDENTIFY;
    //    context->ASCRetContextFlags |= ASC_RET_IDENTIFY;
    //    negotiateFlags |= NTLMSSP_REQUEST_INIT_RESP;
    //}

    /* convert ASCContextReq to flags we MUST support! */
    if (ASCContextReq & ASC_REQ_CONFIDENTIALITY)
        ASCRequestedFlags |= NTLMSSP_NEGOTIATE_SEAL;
    if (ASCContextReq & ASC_REQ_INTEGRITY)
        ASCRequestedFlags |= NTLMSSP_NEGOTIATE_SIGN;

    ret = SvrGenerateChallengeMessage(context,
                                      cred,
                                      ASCContextReq,
                                      ASCRequestedFlags,
                                      negoMessage->NegotiateFlags,
                                      OutputToken);

    /* It seems these flags are always returned */
    *pASCContextAttr = ASC_RET_REPLAY_DETECT |
                       ASC_RET_SEQUENCE_DETECT;


    /* keep similar to code in  CliGenerateAuthenticationMessage */
    if (context->cli_NegFlg & NTLMSSP_NEGOTIATE_SEAL)
        *pASCContextAttr |= ASC_RET_CONFIDENTIALITY;
    //if (context->cli_NegFlg & NTLMSSP_NEGOTIATE_SIGN)
    //    *pASCContextAttr |= ASC_RET_INTEGRITY;

exit:
    if(negoMessage) NtlmFree(negoMessage);
    if(cred) NtlmDereferenceCredential((ULONG_PTR)cred);
    if (context) NtlmDereferenceContext((ULONG_PTR)context);
    ExtStrFree(&OemDomainName);
    ExtStrFree(&OemWorkstationName);

    return ret;
}
#endif

SECURITY_STATUS
CliGenerateAuthenticationMessage(
    IN ULONG_PTR hContext,
    IN ULONG ISCContextReq,
    IN PSecBuffer InputToken1,
    IN PSecBuffer InputToken2,
    IN OUT PSecBuffer OutputToken1,
    IN OUT PSecBuffer OutputToken2,
    OUT PULONG pISCContextAttr,
    OUT PTimeStamp ptsExpiry)
{
    #ifdef USE_SAMBA
    SECURITY_STATUS ret = SEC_E_OK;
    NTSTATUS st;
    PNTLMSSP_CONTEXT_CLI context;
    struct gensec_security *gs;
    DATA_BLOB dataIn, dataOut;

    /* get context */
    context = NtlmReferenceContextCli(hContext);
    //?? if (!context || !context->Credential)
    if (!context)
    {
        ERR("CliGenerateAuthenticationMessage invalid context!\n");
        ret = SEC_E_INVALID_HANDLE;
        goto done;
    }

    gs = context->hdr.samba_gs;

    dataIn.data = InputToken1->pvBuffer;
    dataIn.length = InputToken1->cbBuffer;

    st = ntlmssp_client_challenge(gs, NULL, dataIn, &dataOut);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("ntlmssp_client_challenge failed 0x%x\n", st);
        return SEC_E_INTERNAL_ERROR;
    }

    ret = CopySmbBlobToSecBuffer(ISCContextReq, pISCContextAttr, &dataOut, OutputToken1);
done:
    if (context)
        NtlmDereferenceContext((ULONG_PTR)context);
    return ret;
    #else
    SECURITY_STATUS ret = SEC_E_OK;
    PNTLMSSP_CONTEXT_CLI context = NULL;
    PCHALLENGE_MESSAGE_X challenge = NULL;
    PNTLMSSP_CREDENTIAL cred = NULL;
    BOOL isUnicode;
    BOOL Anonymouse;
    EXT_STRING_W ServerName;
    EXT_STRING_W WorkstationName;
    EXT_DATA NtResponseData;
    EXT_DATA LmResponseData; /* LM2_RESPONSE / RESPONSE */
    EXT_DATA EncryptedRandomSessionKey; //USER_SESSION_KEY
    EXT_DATA AvDataTmp;
    ULONGLONG NtResponseTimeStamp;
    UCHAR ResponseKeyLM[MSV1_0_NTLM3_OWF_LENGTH];
    UCHAR ResponseKeyNT[MSV1_0_NT_OWF_PASSWORD_LENGTH];
    UCHAR ChallengeFromClient[MSV1_0_CHALLENGE_LENGTH];
    PNTLMSSP_GLOBALS_SVR gsvr = getGlobalsSvr();
    PNTLMSSP_GLOBALS_CLI gcli = getGlobalsCli();

    PAUTHENTICATE_MESSAGE_X authmessage = NULL;
    ULONG_PTR offset;
    ULONG messageSize, NegFlg;
    BOOL sendLmChallengeResponse;
    BOOL sendMIC;
    USER_SESSION_KEY SessionBaseKey;

    TRACE("NtlmHandleChallengeMessage hContext %lx\n", hContext);

    /* It seems these flags are always returned */
    *pISCContextAttr = ISC_RET_REPLAY_DETECT |
                       ISC_RET_SEQUENCE_DETECT |
                       ISC_RET_INTEGRITY;

    ExtDataInit(&NtResponseData, NULL, 0);
    ExtDataInit(&AvDataTmp, NULL, 0);
    ExtDataInit(&LmResponseData, NULL, 0);
    ExtDataInit(&EncryptedRandomSessionKey, NULL, 0);
    ExtWStrInit(&WorkstationName, (WCHAR*)gsvr->NbMachineName.Buffer);
    ExtWStrInit(&ServerName, NULL);

    /* get context */
    context = NtlmReferenceContextCli(hContext);
    if(!context || !context->Credential)
    {
        ERR("NtlmHandleChallengeMessage invalid handle!\n");
        ret = SEC_E_INVALID_HANDLE;
        goto quit;
    }

    /* re-authenticate call */
    if(context->hdr.State == AuthenticateSent)
    {
        UNIMPLEMENTED;
        goto quit;
    }
    else if(context->hdr.State != NegotiateSent)
    {
        ERR("Context not in correct state!\n");
        ret = SEC_E_OUT_OF_SEQUENCE;
        goto quit;
    }

    /* InputToken1 should contain a challenge message */
    if(InputToken1->cbBuffer > NTLM_MAX_BUF ||
        InputToken1->cbBuffer < sizeof(CHALLENGE_MESSAGE_X))
    {
        ERR("Input token invalid!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    challenge = (PCHALLENGE_MESSAGE_X)InputToken1->pvBuffer;

    /* validate it */
    if ((memcmp(challenge->Signature, NTLMSSP_SIGNATURE, 8) != 0) ||
        (challenge->MsgType != NtlmChallenge))
    {
        ERR("Input message not valid!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    TRACE("Got valid challege message! with flags:\n");
    NtlmPrintNegotiateFlags(challenge->NegotiateFlags);

    /* validate NegotiateFlags */
    NegFlg = challenge->NegotiateFlags;
    if (NegFlg & NTLMSSP_NEGOTIATE_DATAGRAM)
    {
        /* connection-less - this is the coice the client has made
         * from our last CHALLENGE message */
        if (!ValidateNegFlg(gcli->ClientConfigFlags, &NegFlg, TRUE, TRUE))
        {
            ret = SEC_E_INVALID_TOKEN;
            goto quit;
        }
    }
    else
    {
        /* connection oriented - flags are negotiated now, so
         * fail if client wants something we do not support */
        if (!ValidateNegFlg(gcli->ClientConfigFlags, &NegFlg, FALSE, FALSE))
        {
            ret = SEC_E_INVALID_TOKEN;
            goto quit;
        }
    }
    context->NegFlg = NegFlg;

    /* print challenge message and payloads */
    NtlmPrintHexDump((PBYTE)InputToken1->pvBuffer, InputToken1->cbBuffer);

    isUnicode = (challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE);

    /* should we really change the input-buffer? */
    /* if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_DATAGRAM)
    {
        / * take out bad flags * /
        challenge->NegotiateFlags &=
            (context->NegotiateFlags |
            NTLMSSP_NEGOTIATE_TARGET_INFO |
            NTLMSSP_TARGET_TYPE_SERVER |
            NTLMSSP_TARGET_TYPE_DOMAIN |
            NTLMSSP_NEGOTIATE_LOCAL_CALL);
    }*/

    // FIXME move elsewhere ... here, only in DATAGRAM-mode
    // flags need to be "negotiated"
    /*if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_TARGET_INFO)
        context->NegFlg |= NTLMSSP_NEGOTIATE_TARGET_INFO;
    else
        context->NegFlg &= ~(NTLMSSP_NEGOTIATE_TARGET_INFO);

    / * if caller supports unicode prefer it over oem * /
    if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE)
    {
        context->NegFlg |= NTLMSSP_NEGOTIATE_UNICODE;
        context->NegFlg &= ~NTLMSSP_NEGOTIATE_OEM;
        isUnicode = TRUE;
    }
    else if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_OEM)
    {
        context->NegFlg |= NTLMSSP_NEGOTIATE_OEM;
        context->NegFlg &= ~NTLMSSP_NEGOTIATE_UNICODE;
        / * we have to convert all strings to OEM ...
         * maybe targetinfo-strings too!? * /
        FIXME("OEM will not work ...\n");
        isUnicode = FALSE;
    }
    else
    {
        / * these flags must be bad! * /
        ERR("challenge flags did not specify unicode or oem!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    / * support ntlm2 * /
    if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
    {
        challenge->NegotiateFlags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
        context->NegFlg &= ~NTLMSSP_NEGOTIATE_LM_KEY;
    }
    else
    {
        / * did not support ntlm2 * /
        context->NegFlg &= ~(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);

        / * did not support ntlm * /
        if(!(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_NTLM))
        {
            ERR("netware authentication not supported!!!\n");
            ret = SEC_E_UNSUPPORTED_FUNCTION;
            goto quit;
        }
    }

    / * did not support 128bit encryption * /
    if(!(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_128))
        context->NegFlg &= ~(NTLMSSP_NEGOTIATE_128);

    / * did not support 56bit encryption * /
    if(!(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_56))
        context->NegFlg &= ~(NTLMSSP_NEGOTIATE_56);

    / * did not support lm key * /
    if(!(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_LM_KEY))
        context->NegFlg &= ~(NTLMSSP_NEGOTIATE_LM_KEY);

    / * did not support key exchange * /
    if(!(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_KEY_EXCH))
        context->NegFlg &= ~(NTLMSSP_NEGOTIATE_KEY_EXCH);

    / * should sign * /
    if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)
        context->NegFlg |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
    else
        context->NegFlg &= ~(NTLMSSP_NEGOTIATE_ALWAYS_SIGN);

    / * obligatory key exchange * /
    if((context->NegFlg & NTLMSSP_NEGOTIATE_DATAGRAM) &&
        (context->NegFlg & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)))
        context->NegFlg |= NTLMSSP_NEGOTIATE_KEY_EXCH;

    / * unimplemented * /
    if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_LOCAL_CALL)
        ERR("NTLMSSP_NEGOTIATE_LOCAL_CALL set!\n"); */

    /* get params we need for auth message */
    /* extract target info */
    NtResponseTimeStamp = 0;
    if(challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_TARGET_INFO)
    {
        PVOID data;
        ULONG len;

        ERR("NTLMSSP_NEGOTIATE_TARGET_INFO\n");
        ret = NtlmCreateExtWStrFromBlob(InputToken1, challenge->TargetInfo,
                                        &AvDataTmp);
        if (!NT_SUCCESS(ret))
        {
            ERR("could not get target info!\n");
            goto quit;
        }

        //FIXME...
        //NtlmPrintAvPairs(ptr);
        //NtlmPrintHexDump(InputToken1->pvBuffer, InputToken1->cbBuffer);

        if (!NtlmAvlGet(&AvDataTmp, MsvAvNbDomainName, &data, &len))
        {
            ERR("could not get domainname from target info!\n");
            goto quit;
        }

        /* FIXME: Convert to unicode or do we need it as it is? */
        if(!isUnicode)
            FIXME("convert to unicode!\n");

        ExtWStrSetN(&ServerName, (WCHAR*)data, len / sizeof(WCHAR));

        if (NtlmAvlGet(&AvDataTmp, MsvAvTimestamp, &data, &len))
            NtResponseTimeStamp = *(PULONGLONG)data;
    }
    else
    {
        //FIXME: where to get ...
        ExtWStrInit(&ServerName, L"fixme");
        /* SEEMS WRONG ... */
        /* spec: "A server that is a member of a domain returns the domain of which it
         * is a member, and a server that is not a member of a domain returns
         * the server name." how to tell?? */
        /*ret = NtlmBlobToUnicodeStringRef(InputToken1,
                                         challenge->TargetInfo,
                                         //challenge->TargetName,
                                         &ServerName);
        if(!NT_SUCCESS(ret))
        {
            ERR("could not get target info!\n");
            goto fail;
        }
        if(!isUnicode)
            FIXME("convert to unicode!\n");*/
    }
    /* MS NLSP 3.1.5.1.2 */
    if ((context->UseNTLMv2) &&
        (NtResponseTimeStamp == 0))
    {
        if (!NT_SUCCESS(NtQuerySystemTime((PLARGE_INTEGER)&NtResponseTimeStamp)))
            NtResponseTimeStamp = 0;
    }

    if(!(cred = NtlmReferenceCredential((ULONG_PTR)context->Credential)))
        goto quit;

    /* unscramble password */
    NtlmUnProtectMemory(cred->PasswordW.Buffer, cred->PasswordW.bUsed);

    /* HACK */
    ExtWStrSet(&cred->PasswordW, L"ROSauth!");

    TRACE("cred: %s %s %s %s\n", debugstr_w((WCHAR*)cred->UserNameW.Buffer),
        debugstr_w((WCHAR*)cred->PasswordW.Buffer),
        debugstr_w((WCHAR*)cred->DomainNameW.Buffer),
        debugstr_w((WCHAR*)ServerName.Buffer));

    /* elaborate which data to send ... */
    sendLmChallengeResponse = !context->UseNTLMv2;
    /* MS-NLSP 3.2.5.1.2 says
       * An AUTHENTICATE_MESSAGE indicates the presence of a
         MIC field if the TargetInfo field has an AV_PAIR
         structure whose two field
       * not supported in Win2k3 */
    sendMIC = FALSE;
    /* FIXME/TODO: CONNECTIONLESS
    / * MS-NLSP - 3.1.5.2.1
     * We SHOULD not set LmChallengeResponse if TargetInfo
     * is set and NTLMv2 is used. */
    /*if ((challenge->NegotiateFlags & NTLMSSP_NEGOTIATE_TARGET_INFO) &&
        (!context->UseNTLMv2))
        sendLmChallengeResponse = FALSE;*/

    Anonymouse = FALSE;
    if ((cred->UserNameW.bUsed == 0) &&
        (cred->PasswordW.bUsed == 0))
        Anonymouse = TRUE;

    /* MS-NLMP 3.1.5.1.2 nonce */
    NtlmGenerateRandomBits(ChallengeFromClient, MSV1_0_CHALLENGE_LENGTH);

    if (!CliComputeResponseKeys(context->UseNTLMv2,
                                &cred->UserNameW,
                                &cred->PasswordW,
                                &cred->DomainNameW,
                                ResponseKeyLM,
                                ResponseKeyNT))
        goto quit;

    /* MS-NLMP 3.1.5.1.2 */
    if (!ComputeResponse(context->NegFlg,
                         context->UseNTLMv2,
                         Anonymouse,
                         &cred->DomainNameW,
                         ResponseKeyLM,
                         ResponseKeyNT,
                         &ServerName,
                         ChallengeFromClient,
                         challenge->ServerChallenge,
                         NtResponseTimeStamp,
                         &NtResponseData,
                         &LmResponseData,
                         &SessionBaseKey))
    {
        ERR("ComputeResponse error\n");
        return FALSE;
    }
    if (!CliComputeKeys(challenge->NegotiateFlags,
                        &SessionBaseKey,
                        &LmResponseData,
                        &NtResponseData,
                        challenge->ServerChallenge,
                        ResponseKeyLM,
                        &EncryptedRandomSessionKey,
                        &context->msg))
    {
        ERR("CliComputeKeys error\n");
        return FALSE;
    }
    TRACE("=== NtResponse ===\n");
    NtlmPrintHexDump(NtResponseData.Buffer, NtResponseData.bUsed);

    /* calc message size */
    messageSize = sizeof(AUTHENTICATE_MESSAGE_X) +
                  cred->DomainNameW.bUsed +
                  cred->UserNameW.bUsed +
                  WorkstationName.bUsed +
                  NtResponseData.bUsed +
                  EncryptedRandomSessionKey.bUsed/*+
                  LmSessionKeyString.Length*/;
    if (sendLmChallengeResponse)
        messageSize += LmResponseData.bUsed;
    if (!sendMIC)
        messageSize -= sizeof(AUTHENTICATE_MESSAGE_X) -
                       FIELD_OFFSET(AUTHENTICATE_MESSAGE_X, MIC);
    /* if should not allocate */
    if (!(ISCContextReq & ISC_REQ_ALLOCATE_MEMORY))
    {
        /* not enough space */
        if(messageSize > OutputToken1->cbBuffer)
        {
            ret = SEC_E_BUFFER_TOO_SMALL;
            goto quit;
        }
        OutputToken1->cbBuffer = messageSize; /* says wine test */
    }
    else
    {
        /* allocate */
        if(!(OutputToken1->pvBuffer = NtlmAllocate(messageSize)))
        {
            ret = SEC_E_INSUFFICIENT_MEMORY;
            goto quit;
        }
    }
    authmessage = (PAUTHENTICATE_MESSAGE_X)OutputToken1->pvBuffer;

    /* fill auth message */
    strncpy(authmessage->Signature, NTLMSSP_SIGNATURE, sizeof(NTLMSSP_SIGNATURE));
    authmessage->MsgType = NtlmAuthenticate;
    authmessage->NegotiateFlags = context->NegFlg;

    /* calc blob offset */
    offset = (ULONG_PTR)(authmessage+1);
    if (!sendMIC)
        offset -= sizeof(AUTHENTICATE_MESSAGE_X) -
                  FIELD_OFFSET(AUTHENTICATE_MESSAGE_X, MIC);

    NtlmExtStringToBlob((PVOID)authmessage,
                        &cred->DomainNameW,
                        &authmessage->DomainName,
                        &offset);

    NtlmExtStringToBlob((PVOID)authmessage,
                        &cred->UserNameW,
                        &authmessage->UserName,
                        &offset);

    NtlmExtStringToBlob((PVOID)authmessage,
                         &gsvr->NbMachineName,
                         &authmessage->WorkstationName,
                         &offset);

    if (sendLmChallengeResponse)
    {
        NtlmExtStringToBlob((PVOID)authmessage,
                            &LmResponseData,
                            &authmessage->LmChallengeResponse,
                            &offset);
    }
    else
    {
        NtlmExtStringToBlob((PVOID)authmessage, NULL,
                            &authmessage->LmChallengeResponse,
                            &offset);
    }

    NtlmExtStringToBlob((PVOID)authmessage,
                        &NtResponseData,
                        &authmessage->NtChallengeResponse,
                        &offset);

    NtlmExtStringToBlob((PVOID)authmessage,
                         &EncryptedRandomSessionKey,
                         &authmessage->EncryptedRandomSessionKey,
                         &offset);

    if (messageSize != ( (ULONG)offset - (ULONG)authmessage) )
        WARN("messageSize is %ld, really needed %ld\n", messageSize, (ULONG)offset - (ULONG)authmessage);

    /* set version */
    NtlmMsgSetVersion(context->NegFlg, &authmessage->Version);

    /* keep similar to code in Svr CliGenerateAuthenticationMessage */
    if (context->NegFlg & NTLMSSP_NEGOTIATE_SEAL)
        *pISCContextAttr |= ASC_RET_CONFIDENTIALITY;

    context->hdr.State = AuthenticateSent;
    ret = SEC_E_OK;
quit:
    if (ret != SEC_E_OK)
    {
        /* maybe free authmessage */
        if ((ISCContextReq & ISC_REQ_ALLOCATE_MEMORY) &&
            (authmessage))
            NtlmFree(authmessage);
    }
    if(context) NtlmDereferenceContext((ULONG_PTR)context);
    if(cred) NtlmDereferenceCredential((ULONG_PTR)cred);
    ExtStrFree(&NtResponseData);
    ExtStrFree(&ServerName);
    ExtStrFree(&AvDataTmp);
    ExtStrFree(&LmResponseData);
    ExtStrFree(&EncryptedRandomSessionKey);
    ExtStrFree(&WorkstationName);
    ERR("handle challenge end\n");
    return ret;
    #endif
}


/* internal data for autentication process */
typedef struct _AUTH_DATA
{
    PSecBuffer InputToken;
    PAUTHENTICATE_MESSAGE_X authMessage;
    EXT_DATA EncryptedRandomSessionKey;
    EXT_DATA LmChallengeResponse;
    EXT_DATA NtChallengeResponse;
    //FIXME: Is DomainName = UserDom?
    EXT_STRING_W UserName;
    EXT_STRING_W Workstation, DomainName;
    //BOOLEAN isUnicode;

} AUTH_DATA, *PAUTH_DATA;

/* MS-NLSP 3.2.5.1.2 */
SECURITY_STATUS
SvrAuthMsgProcessData(
    IN PNTLMSSP_CONTEXT_SVR context,
    IN OUT PAUTH_DATA ad)
{
    // TODO/CHECK 3.2.5.1.2
    // -> evtl checks in SvrAtuhMsgValidateData ... PreProcess
    // * username + response empty -> ANONYMOUSE
    // * client security features not strong enough -> error
    // --
    // * obtain response key by looking up the name in a database
    // * with nt + lm response key + client challenge compute expected response
    //   * if it matches -> generate
    //     * session, singing, and sealing keys
    //   * if not -> error access denied
    //
    // * NTLM servers SHOULD support NTLM clients which
    //   incorrectly use NIL for the UserDom for calculating
    //   ResponseKeyNT and ResponseKeyLM.

    // following code based on pseudocode
    // (MS-NLMP 3.2.5.1.2)

    /*
    -- Input:
    --
    OK CHALLENGE_MESSAGE.ServerChallenge - The ServerChallenge field
    OK from the server CHALLENGE_MESSAGE in section 3.2.5.1.1
    --
    OK NegFlg - Defined in section 3.1.1.
    --
    OK ServerName - The NETBIOS or the DNS name of the server.
    --
    An NTLM NEGOTIATE_MESSAGE whose message fields are defined
    in section 2.2.1.1.
    --
    OK An NTLM AUTHENTICATE_MESSAGE whose message fields are defined
    OK in section 2.2.1.3.
    OK --- An NTLM AUTHENTICATE_MESSAGE whose message fields are
    OK defined in section 2.2.1.3 with the MIC field set to 0.
    --
    OPTIONAL ServerChannelBindingsUnhashed - Defined in
    section 3.2.1.2* /

    ---- Output:
    Result of authentication
    --
    ClientHandle - The handle to a key state structure corresponding
    --
    to the current state of the ClientSealingKey
    --
    ServerHandle - The handle to a key state structure corresponding
    --
    to the current state of the ServerSealingKey
    --
    The following NTLM keys generated by the server are defined in
    section 3.1.1:
    --
    ExportedSessionKey, ClientSigningKey, ClientSealingKey,
    ServerSigningKey, and ServerSealingKey.
    ---- Temporary variables that do not pass over the wire are defined
    below:
    --
    KeyExchangeKey, ResponseKeyNT, ResponseKeyLM, SessionBaseKey
    -
    Temporary variables used to store 128-bit keys.
    --
    MIC - message integrity for the NTLM NEGOTIATE_MESSAGE,
    CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE
    --
    MessageMIC - Temporary variable used to hold the original value of
    the MIC field to compare the computed value.
    --
    OK Time - Temporary variable used to hold the 64-bit current time from the
    OK NTLMv2_CLIENT_CHALLENGE.Timestamp, in the format of a
    OK FILETIME as defined in [MS-DTYP] section 2.3.1.
    --
    ChallengeFromClient – Temporary variable to hold the client's 8-byte
    challenge, if used.
    --
    ExpectedNtChallengeResponse
    - Temporary variable to hold results
    returned from ComputeResponse.
    --
    ExpectedLmChallengeResponse
    - Temporary variable to hold results
    returned from ComputeResponse.
    --
    NullSession – Temporary variable to denote whether client has
    explicitly requested to be anonymously authenticated.
    ---- Functions used:
    --
    ComputeResponse
    - Defined in section 3.3
    --
    KXKEY, SIGNKEY, SEALKEY
    - Defined in sections 3.4.5, 3.4.6, and 3.4.7
    --
    GetVersion(), NIL - Defined in section 6
     */

    // Set NullSession to FALSE
    /* BOOL NullSession = FALSE; unused */
    SECURITY_STATUS ret = SEC_E_OK;
    UCHAR ResponseKeyNt[MSV1_0_NTLM3_OWF_LENGTH];
    UCHAR ResponseKeyLM[MSV1_0_LM_OWF_PASSWORD_LENGTH];
    UCHAR KeyExchangeKey[NTLM_KEYEXCHANGE_KEY_LENGTH];
    UCHAR* ChallengeFromClient;
    EXT_STRING_W ServerName;
    ULONGLONG TimeStamp = {0};
    EXT_DATA ExpectedNtChallengeResponse;
    EXT_DATA ExpectedLmChallengeResponse;
    EXT_DATA EncryptedRandomSessionKey;
    EXT_DATA SessionBaseKey;
    BOOL UseNTLMv2;
    //BOOL NullSession; /* anonymouse */
    /* UCHAR* MessageMIC; unused */
    UCHAR MIC[16];
    //MSV1_0_NTLM3_RESPONSE NtResponse;
    UCHAR ExportedSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    PNTLMSSP_GLOBALS_SVR gsvr = getGlobalsSvr();

    ExtDataInit(&ExpectedNtChallengeResponse, NULL, 0);
    ExtDataInit(&ExpectedLmChallengeResponse, NULL, 0);
    ExtDataInit(&EncryptedRandomSessionKey, NULL, 0);
    ExtDataInit(&SessionBaseKey, NULL, 0);
    ExtDataSetLength(&SessionBaseKey, MSV1_0_USER_SESSION_KEY_LENGTH, TRUE);
    /* Servername is NetBIOS Name or DNS Hostname */
    ExtWStrInit(&ServerName, (WCHAR*)gsvr->NbMachineName.Buffer);

    //if (AUTHENTICATE_MESSAGE.UserNameLen == 0 AND
    //AUTHENTICATE_MESSAGE.NtChallengeResponse.Length == 0 AND
    //(AUTHENTICATE_MESSAGE.LmChallengeResponse == Z(1)
    //OR
    //AUTHENTICATE_MESSAGE.LmChallengeResponse.Length == 0))
    //NullSession = FALSE;
    if ((ad->UserName.bUsed == 0) &&
        (ad->NtChallengeResponse.bUsed == 0) &&
        // lt spec == ' ' or '0' ... mabye v this will not work...
        ( (ad->LmChallengeResponse.bUsed == 0) ||
          (memcmp(&ad->LmChallengeResponse, " ", 1) == 0)))
    {
        //-- Special case: client requested anonymous authentication
        //Set NullSession to TRUE
        /* NullSession = TRUE; unused? */
    }
    else
    {
        //TODO
        //Retrieve the ResponseKeyNT and ResponseKeyLM from the local user
        //  account database using the UserName and DomainName specified in the
        //  AUTHENTICATE_MESSAGE.
        // ** BEG-HACK: Use Fake NT/LM-Response key for the moment okay... **
        WCHAR* passwd = L"ROSauth!";
        if (ad->NtChallengeResponse.bUsed > 0x0018)
        {
            /* we calc the respnsekeyNT / LM with user credentials! */
            if (!NTOWFv2((WCHAR*)passwd, (WCHAR*)ad->UserName.Buffer,
                         (WCHAR*)ad->DomainName.Buffer, ResponseKeyNt))
            {
                ERR("NTOWFv2 failed\n");
                return FALSE;
            }
            #ifdef VALIDATE_NTLMv2
            //TRACE("**** VALIDATE **** ResponseKeyNT\n");
            //NtlmPrintHexDump(ResponseKeyNT, MSV1_0_NTLM3_RESPONSE_LENGTH);
            #endif

            //Set ResponseKeyLM to LMOWFv2(Passwd, User, UserDom)
            if (!LMOWFv2((WCHAR*)passwd, (WCHAR*)ad->UserName.Buffer,
                         (WCHAR*)ad->DomainName.Buffer, ResponseKeyLM))
            {
                ERR("LMOWFv2 failed\n");
                return FALSE;
            }
        }
        else
        {
            /* we calc the respnsekeyNT / LM with user credentials! */
            if (!NTOWFv1((WCHAR*)passwd, ResponseKeyNt))
            {
                ERR("NTOWFv1 failed\n");
                return FALSE;
            }
            LMOWFv1("ROSauth!", ResponseKeyLM);
        }
        // ** END-HACK: Use Fake NT/LM-Response key for the moment okay... **

        //If AUTHENTICATE_MESSAGE.NtChallengeResponseFields.NtChallengeResponseLen > 0x0018
        //Set ChallengeFromClient to NTLMv2_RESPONSE.NTLMv2_CLIENT_CHALLENGE.ChallengeFromClient
        //ElseIf NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set in NegFlg
        //Set ChallengeFromClient to LM_RESPONSE.Response[0..7]
        //Else
        //Set ChallengeFromClient to NIL
        //EndIf
        UseNTLMv2 = FALSE;
        if (ad->NtChallengeResponse.bUsed > 0x0018)
        {
            PMSV1_0_NTLM3_RESPONSE ntResp = (PMSV1_0_NTLM3_RESPONSE)ad->NtChallengeResponse.Buffer;
            ChallengeFromClient = ntResp->ChallengeFromClient;
            //Time.dwHighDateTime = ntResp->TimeStamp >> 32;
            //Time.dwLowDateTime = ntResp->TimeStamp && 0xffffffff;
            TimeStamp = ntResp->TimeStamp;
            UseNTLMv2 = TRUE;
        }
        else if (context->cli_NegFlg & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
            ChallengeFromClient = (UCHAR*)ad->LmChallengeResponse.Buffer;
        else
            ChallengeFromClient = NULL;

        TRACE("context->cli_NegFlg\n");
        NtlmPrintNegotiateFlags(context->cli_NegFlg);
        // Set ExpectedNtChallengeResponse, ExpectedLmChallengeResponse,
        // SessionBaseKey to ComputeResponse(NegFlg, ResponseKeyNT,
        // ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge,
        // ChallengeFromClient, Time, ServerName)
        if (!ComputeResponse(
            context->cli_NegFlg,
            UseNTLMv2,
            FALSE,
            &ad->DomainName,
            ResponseKeyLM,
            ResponseKeyNt,
            &ServerName,
            ChallengeFromClient,
            context->ServerChallenge,
            TimeStamp,
            &ExpectedNtChallengeResponse,
            &ExpectedLmChallengeResponse,
            (PUSER_SESSION_KEY)SessionBaseKey.Buffer))
        {
            ret = SEC_E_INTERNAL_ERROR;
            goto quit;
        }
        // Set KeyExchangeKey to KXKEY(SessionBaseKey,
        // AUTHENTICATE_MESSAGE.LmChallengeResponse, CHALLENGE_MESSAGE.ServerChallenge)
        KXKEY(context->cli_NegFlg, (PUCHAR)SessionBaseKey.Buffer,
              &ad->LmChallengeResponse,
              &ad->NtChallengeResponse,
              context->ServerChallenge, ResponseKeyLM, KeyExchangeKey);
        TRACE("KeyExchangeKey\n");
        NtlmPrintHexDump(KeyExchangeKey, 16);

        TRACE("NTChallengeResponse\n");
        NtlmPrintHexDump(ad->NtChallengeResponse.Buffer, ad->NtChallengeResponse.bUsed);
        TRACE("NTChallengeResponse (expected)\n");
        NtlmPrintHexDump(ExpectedNtChallengeResponse.Buffer, ExpectedNtChallengeResponse.bUsed);

        TRACE("LmChallengeResponse\n");
        NtlmPrintHexDump(ad->LmChallengeResponse.Buffer, ad->LmChallengeResponse.bUsed);
        TRACE("LmChallengeResponse (expected)\n");
        NtlmPrintHexDump(ExpectedLmChallengeResponse.Buffer, ExpectedLmChallengeResponse.bUsed);

        // If (AUTHENTICATE_MESSAGE.NtChallengeResponse !=
        // ExpectedNtChallengeResponse)
        // If (AUTHENTICATE_MESSAGE.LmChallengeResponse !=
        // ExpectedLmChallengeResponse)
        if (!ExtDataIsEqual1(&ad->NtChallengeResponse, &ExpectedNtChallengeResponse) ||
           ((ad->LmChallengeResponse.bUsed != 0) &&
            (!ExtDataIsEqual1(&ad->LmChallengeResponse, &ExpectedLmChallengeResponse))))
        {
            // Retry using NIL for the domain name: Retrieve the ResponseKeyNT
            // and ResponseKeyLM from the local user account database using
            // the UserName specified in the AUTHENTICATE_MESSAGE and
            // NIL for the DomainName.
            FIXME("2nd try not implemented (DomainName = NIL).");
            //Set ExpectedNtChallengeResponse, ExpectedLmChallengeResponse,
            //SessionBaseKey to ComputeResponse(NegFlg, ResponseKeyNT,
            //ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge,
            //ChallengeFromClient, Time, ServerName)
            //Set KeyExchangeKey to KXKEY(SessionBaseKey,
            //AUTHENTICATE_MESSAGE.LmChallengeResponse,
            //CHALLENGE_MESSAGE.ServerChallenge)
            //If (AUTHENTICATE_MESSAGE.NtChallengeResponse !=
            //ExpectedNtChallengeResponse)
            //If (AUTHENTICATE_MESSAGE.LmChallengeResponse !=
            //ExpectedLmChallengeResponse)
            {
                //Return INVALID message error
                ret = SEC_E_INVALID_TOKEN;
                goto quit;
                //EndIf
                //EndIf
            //EndIf
            //EndIf
            }
        //EndIf
        }
    }

    //Set MessageMIC to AUTHENTICATE_MESSAGE.MIC
    /* MessageMIC = ad->authMessage->MIC; unused should compared with?? */
    //Set AUTHENTICATE_MESSAGE.MIC to Z(16)

    //If (NTLMSSP_NEGOTIATE_KEY_EXCH flag is set in NegFlg
    //AND (NTLMSSP_NEGOTIATE_SIGN OR NTLMSSP_NEGOTIATE_SEAL are set in NegFlg) )
    if ((context->cli_NegFlg & NTLMSSP_NEGOTIATE_KEY_EXCH) &&
        (context->cli_NegFlg & (NTLMSSP_NEGOTIATE_SIGN |
                                NTLMSSP_NEGOTIATE_SEAL)))
    {
        //Set ExportedSessionKey to RC4K(KeyExchangeKey,
        //AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey)
        TRACE("EncryptedRandomSessionKey...\n");
        NtlmPrintHexDump(ad->EncryptedRandomSessionKey.Buffer, ad->EncryptedRandomSessionKey.bUsed);
        // Assert nötig, da ExportedSessionKey auch 16 Bytes ist ...
        ASSERT(ad->authMessage->EncryptedRandomSessionKey.Length == MSV1_0_USER_SESSION_KEY_LENGTH);
        RC4K(KeyExchangeKey, ARRAYSIZE(KeyExchangeKey),
             ad->EncryptedRandomSessionKey.Buffer,
             ad->EncryptedRandomSessionKey.bUsed,
             ExportedSessionKey);
    }
    else
    {
        //Set ExportedSessionKey to KeyExchangeKey
        memcpy(ExportedSessionKey, KeyExchangeKey, MSV1_0_USER_SESSION_KEY_LENGTH);
    }
    TRACE("ExportedSessionKey\n");
    NtlmPrintHexDump(ExportedSessionKey, 16);
    //Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(
    //NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE,
    //AUTHENTICATE_MESSAGE))
    FIXME("need NEGO/CHALLENGE and Auth-Message for MIC!\n");
    memset(&MIC, 0, 16);
    //Set ClientSigningKey to SIGNKEY(NegFlg, ExportedSessionKey , "Client")
    SIGNKEY(ExportedSessionKey, TRUE, context->cli_msg.ClientSigningKey);
    //Set ServerSigningKey to SIGNKEY(NegFlg, ExportedSessionKey , "Server")
    SIGNKEY(ExportedSessionKey, FALSE, context->cli_msg.ServerSigningKey);
    //Set ClientSealingKey to SEALKEY(NegFlg, ExportedSessionKey , "Client")
    SEALKEY(context->cli_NegFlg, ExportedSessionKey, TRUE, context->cli_msg.ClientSealingKey);
    //Set ServerSealingKey to SEALKEY(NegFlg, ExportedSessionKey , "Server")
    SEALKEY(context->cli_NegFlg, ExportedSessionKey, FALSE, context->cli_msg.ServerSealingKey);
    //RC4Init(ClientHandle, ClientSealingKey)
    RC4Init(&context->cli_msg.ClientHandle, context->cli_msg.ClientSealingKey, 16);//sizeof(context->cli_msg.ClientSealingKey));
    //RC4Init(ServerHandle, ServerSealingKey)
    RC4Init(&context->cli_msg.ServerHandle, context->cli_msg.ServerSealingKey, 16);//sizeof(context->cli_msg.ServerSealingKey));

    PrintSignSealKeyInfo(&context->cli_msg);
quit:
    ExtStrFree(&SessionBaseKey);
    ExtStrFree(&ExpectedLmChallengeResponse);
    ExtStrFree(&ExpectedNtChallengeResponse);
    ExtStrFree(&EncryptedRandomSessionKey);
    ExtStrFree(&ServerName);
    return ret;
}

/* MS-NLSP 3.2.5.1.2 */
SECURITY_STATUS
SvrAuthMsgExtractData(
    IN PNTLMSSP_CONTEXT_SVR context,
    IN OUT PAUTH_DATA ad)
{
    PNTLMSSP_GLOBALS_SVR gsvr = getGlobalsSvr();
    SECURITY_STATUS ret = SEC_E_OK;

    /* Check if client sends only supported flags
     * (we have negotiated it!)
     * TODO: check is wrong in DATAGRAM-Mode!
     * */
    if (!ValidateNegFlg(gsvr->CfgFlg, &ad->authMessage->NegotiateFlags, FALSE, TRUE))
    {
        /* flags set that we do not support */
        ERR("Unsupported flags!\n");
        ERR("NEG %x\n",ad->authMessage->NegotiateFlags);
        ERR("CFG %x\n",gsvr->CfgFlg);
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    /* set client Negotiation flags */
    context->cli_NegFlg = ad->authMessage->NegotiateFlags;

    /* datagram */
    if(context->cli_NegFlg & NTLMSSP_NEGOTIATE_DATAGRAM)
    {
        /* need a key */
        if(context->cli_NegFlg & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL))
            context->cli_NegFlg |= NTLMSSP_NEGOTIATE_KEY_EXCH;

        /* remove lm key */
        if (context->cli_NegFlg & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
            context->cli_NegFlg &= ~NTLMSSP_NEGOTIATE_LM_KEY;
    }

    /* supports unicode */
    if(context->cli_NegFlg & NTLMSSP_NEGOTIATE_UNICODE)
    {
        context->cli_NegFlg &= ~NTLMSSP_NEGOTIATE_OEM;
        //isUnicode = TRUE;
    }
    else if(context->cli_NegFlg & NTLMSSP_NEGOTIATE_OEM)
    {
        context->cli_NegFlg &= ~NTLMSSP_NEGOTIATE_UNICODE;
        //isUnicode = FALSE;
    }
    else
    {
        /* these flags must be bad! */
        ERR("authenticate flags did not specify unicode or oem!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    if(!NT_SUCCESS(NtlmCreateExtWStrFromBlob(ad->InputToken,
        ad->authMessage->LmChallengeResponse, &ad->LmChallengeResponse)))
    {
        ERR("cant get blob data\n");
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    if(!NT_SUCCESS(NtlmCreateExtWStrFromBlob(ad->InputToken,
        ad->authMessage->NtChallengeResponse, &ad->NtChallengeResponse)))
    {
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    if(!NT_SUCCESS(NtlmCreateExtWStrFromBlob(ad->InputToken,
        ad->authMessage->UserName, &ad->UserName)))
    {
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    if(!NT_SUCCESS(NtlmCreateExtWStrFromBlob(ad->InputToken,
        ad->authMessage->WorkstationName, &ad->Workstation)))
    {
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    if(!NT_SUCCESS(NtlmCreateExtWStrFromBlob(ad->InputToken,
        ad->authMessage->DomainName, &ad->DomainName)))
    {
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    if (context->cli_NegFlg & NTLMSSP_NEGOTIATE_KEY_EXCH)
    {
        if(!NT_SUCCESS(NtlmCreateExtWStrFromBlob(ad->InputToken,
            ad->authMessage->EncryptedRandomSessionKey,
            &ad->EncryptedRandomSessionKey)))
        {
            ret = SEC_E_INVALID_TOKEN;
            goto quit;
        }
    }
    else
        ExtDataInit(&ad->EncryptedRandomSessionKey, NULL, 0);

quit:
    return ret;
}

/* MS-NLSP 3.2.5.1.2 */
SECURITY_STATUS
SvrHandleAuthenticateMessage(
    IN ULONG_PTR hContext,
    IN ULONG ASCContextReq,
    IN PSecBuffer InputToken,
    OUT PSecBuffer OutputToken,
    OUT PULONG pASCContextAttr,
    OUT PTimeStamp ptsExpiry,
    OUT PUCHAR pSessionKey,
    OUT PULONG pfUserFlags)
{
#ifdef USE_SAMBA
    SECURITY_STATUS ret = SEC_E_OK;
    PNTLMSSP_CONTEXT_SVR context = NULL;
    NTSTATUS st, reqst;
    struct tevent_req *evReq;

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;

    struct gensec_security *gs;
    struct tevent_context *ev;

    if (!(context = NtlmReferenceContextSvr(hContext)))
    {
        ret = SEC_E_INVALID_HANDLE;
        goto done;
    }
    gs = context->hdr.samba_gs;
    ev = gs->auth_context->event_ctx;

    dataIn.data = InputToken->pvBuffer;
    dataIn.length = InputToken->cbBuffer;

    evReq = ntlmssp_server_auth_send(NULL, ev, gs, dataIn);
    if (evReq == NULL)
    {
        ERR("ntlmssp_server_auth_send failed\n");
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }

    /* hacky but ... ok for now */
    st = _tevent_loop_wait(ev, "here!");
    printf("tevent loop %lx\n", st);

    st = ntlmssp_server_auth_recv(evReq, &reqst, &dataOut);
    if (!NT_STATUS_IS_OK(st))
    {
        ERR("ntlmssp_server_auth_recv failed\n");
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }

    if (!NT_STATUS_IS_OK(reqst))
    {
        ERR("ntlmssp_server_auth_recv failed\n");
        ERR("TODO status -> nt error\n");
        ret =  reqst;//TODO ntstatus -> sec status
        goto done;
    }

    /* succes ... return data in dataOut */
    if (dataOut.length > 0)
    {
        if (ASCContextReq & ASC_REQ_ALLOCATE_MEMORY)
        {
            OutputToken->cbBuffer = dataOut.length;
            OutputToken->pvBuffer = NtlmAllocate(dataOut.length);
        }
        else if (OutputToken->cbBuffer < dataOut.length)
        {
            ERR("buffer to small\n");
            ret = SEC_E_BUFFER_TOO_SMALL;
            goto done;
        }
        memcpy(OutputToken->pvBuffer, dataOut.data, dataOut.length);
    }
    OutputToken->cbBuffer = dataOut.length;

    goto done;

done:
    if (dataOut.length > 0)
        talloc_free(dataOut.data);
    return ret;
#else
    SECURITY_STATUS ret = SEC_E_OK;
    PNTLMSSP_CONTEXT_SVR context = NULL;
    AUTH_DATA ad = {0};

    /* It seems these flags are always returned */
    *pASCContextAttr = ASC_RET_INTEGRITY |
                       ASC_RET_REPLAY_DETECT |
                       ASC_RET_SEQUENCE_DETECT |
                       ASC_RET_CONFIDENTIALITY;

    ExtDataInit(&ad.LmChallengeResponse, NULL, 0);
    ExtDataInit(&ad.NtChallengeResponse, NULL, 0);
    ExtWStrInit(&ad.UserName, NULL);
    ExtWStrInit(&ad.Workstation, NULL);
    ExtWStrInit(&ad.DomainName, NULL);

    ad.InputToken = InputToken;

    TRACE("NtlmHandleAuthenticateMessage hContext %x!\n", hContext);
    /* get context */
    if(!(context = NtlmReferenceContextSvr(hContext)))
    {
        ret = SEC_E_INVALID_HANDLE;
        goto quit;
    }

    TRACE("context->State %d\n", context->hdr.State);
    if(context->hdr.State != ChallengeSent && context->hdr.State != Authenticated)
    {
        ERR("Context not in correct state!\n");
        ret = SEC_E_OUT_OF_SEQUENCE;
        goto quit;
    }

    /* re-authorize */
    if(context->hdr.State == Authenticated)
        UNIMPLEMENTED;

    /* InputToken1 should contain a authenticate message */
    TRACE("input token size %lx\n", InputToken->cbBuffer);
    if(InputToken->cbBuffer > NTLM_MAX_BUF ||
        InputToken->cbBuffer < sizeof(AUTHENTICATE_MESSAGE))
    {
        ERR("Input token invalid!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    /* allocate a buffer for it */
    if(!(ad.authMessage = NtlmAllocate(sizeof(AUTHENTICATE_MESSAGE))))
    {
        ERR("failed to allocate authMessage buffer!\n");
        ret = SEC_E_INSUFFICIENT_MEMORY;
        goto quit;
    }

    /* copy it */
    memcpy(ad.authMessage, InputToken->pvBuffer, sizeof(AUTHENTICATE_MESSAGE));

    /* validate it */
    if ((memcmp(ad.authMessage->Signature, NTLMSSP_SIGNATURE, 8) != 0) ||
        (ad.authMessage->MsgType != NtlmAuthenticate))
    {
        ERR("Input message not valid!\n");
        ret = SEC_E_INVALID_TOKEN;
        goto quit;
    }

    ret = SvrAuthMsgExtractData(context, &ad);
    if (ret != SEC_E_OK)
        goto quit;

    ret = SvrAuthMsgProcessData(context, &ad);
    if (ret != SEC_E_OK)
        goto quit;

    ret = SEC_I_COMPLETE_NEEDED;

quit:
    NtlmDereferenceContext((ULONG_PTR)context);
    ExtStrFree(&ad.LmChallengeResponse);
    ExtStrFree(&ad.NtChallengeResponse);
    ExtStrFree(&ad.UserName);
    ExtStrFree(&ad.Workstation);
    ExtStrFree(&ad.DomainName);
    return ret;
#endif
}

