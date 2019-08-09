//
// MSDN Example "Using SSPI with a Windows Sockets Client"
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa380536(v=vs.85).aspx
//

//--------------------------------------------------------------------
//  Client-side program to establish an SSPI socket connection
//  with a server and exchange messages.

//--------------------------------------------------------------------
//  Define macros and constants.

#include "client_server.h"

#define BIG_BUFF    2048

#define cbMaxMessage 12000
#define MessageAttribute ISC_REQ_CONFIDENTIALITY

typedef struct _CLI_PARAMS
{
    WCHAR* ServerName;
    int ServerPort;
    WCHAR* TargetName;
    WCHAR* PackageName;
    WCHAR* user;
    WCHAR* pass;
} CLI_PARAMS, *PCLI_PARAMS;

BOOL
client2_DoAuthentication(
    IN PCLI_PARAMS pcp,
    IN SOCKET s,
    IN PCredHandle hCred,
    IN PSecHandle  hcText);
BOOL
client2_DoAuthenticationOverSMB(
    IN PCLI_PARAMS pcp,
    IN SOCKET s,
    IN PCredHandle hCred,
    IN PSecHandle  hcText);

BOOL
GenClientContext(
    PBYTE pIn,
    DWORD cbIn,
    PBYTE pOut,
    DWORD *pcbOut,
    BOOL  *pfDone,
    PCLI_PARAMS pcp,
    PCredHandle hCred,
    PSecHandle  hcText);

//--------------------------------------------------------------------
//  ConnectAuthSocket establishes an authenticated socket connection
//  with a server and initializes needed security package resources.

BOOL
client2_ConnectAuthSocket(
    IN  PCLI_PARAMS pcp,
    OUT SOCKET     *s,
    OUT PCredHandle hCred,
    OUT PSecHandle  hcText)
{
    unsigned long  ulAddress;
    struct hostent *pHost;
    SOCKADDR_IN    sin;

#ifdef UNICODE
    char AnsiServerName[256];

    WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR,
        pcp->ServerName, -1, AnsiServerName, _countof(AnsiServerName), NULL, NULL);
#else
#define AnsiServerName ServerName
#endif

    /* Lookup the server's address */
    ulAddress = inet_addr(AnsiServerName);

    if (ulAddress == INADDR_NONE)
    {
        pHost = gethostbyname(AnsiServerName);
        if (!pHost)
        {
            sync_err("Unable to resolve host name.\n");
            goto failed;
        }

        memcpy((char *)&ulAddress, pHost->h_addr, pHost->h_length);
    }

#ifndef UNICODE
#undef AnsiServerName
#endif

    /* Create the socket */
    *s = socket(PF_INET, SOCK_STREAM, 0);
    if (*s == INVALID_SOCKET)
    {
        sync_err("Unable to create socket\n");
        goto failed;
    }

    sync_trace("client socket %x created, port %i.\n", *s, pcp->ServerPort);

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ulAddress;
    sin.sin_port = htons(pcp->ServerPort);

    /* Connect to the server */
    if (connect(*s, (LPSOCKADDR)&sin, sizeof(sin)) != 0)
    {
        sync_err("Connect failed.\n");
        printerr(errno);
        goto failed;
    }

    /* Authenticate the connection */
    if (pcp->ServerPort != 445)
    {
        if (!client2_DoAuthentication(pcp, *s, hCred, hcText))
        {
            sync_err("Authentication failed\n");
            goto failed;
        }
    }
    else
    {
        if (!client2_DoAuthenticationOverSMB(pcp, *s, hCred, hcText))
        {
            sync_err("Authentication failed\n");
            goto failed;
        }
    }

    return TRUE;

failed:
    if (*s != INVALID_SOCKET)
        closesocket(*s);
    return FALSE;
}

BOOL
SendRecvMsgSMB(
    IN SOCKET s,
    IN PBYTE pOutBufSMB,
    IN ULONG cbOutSMB,
    IN OUT PBYTE pInBuf,
    IN OUT PULONG pCbIn,
    OUT PSMB_ERROR pStatus,
    OUT PUSHORT pSessionId)
{
    PSMB_Header psh;

    if (!SendMsgSMB(s, (PBYTE)pOutBufSMB, cbOutSMB))
    {
        sync_err("Send message failed.\n");
        return FALSE;
    }
    /* get response */
    if (!ReceiveMsgSMB(s, pInBuf, cbMaxMessage, pCbIn))
    {
        sync_err("Receive message failed ");
        return FALSE;
    }
    //??psh = (PSMB_Header)pInBuf;
    //??ServerPID = (psh->PIDHigh << 16) + psh->PIDLow;
    PrintHexDump(cbMaxMessage, pInBuf);

    psh = (PSMB_Header)pInBuf;
    /* check status only if pStatus is NULL */
    if ( (pStatus == NULL) &&
         (psh->Status.NT_Status != 0) )
    {
        sync_err("Error NT_Status 0x%x\n", psh->Status.NT_Status);
        return FALSE;
    }
    if (pStatus)
        *pStatus = psh->Status;
    if (pSessionId)
        *pSessionId = psh->UID;
    return TRUE;
}

BOOL
client2_DoAuthenticationOverSMB(
    IN PCLI_PARAMS pcp,
    IN SOCKET s,
    IN PCredHandle hCred,
    IN PSecHandle  hcText)
{
    BOOL Success;
    BOOL    fDone = FALSE;
    ULONG   cbIn = 0;
    DWORD   cbInSMB = 0;
    DWORD   cbOut = 0;
    ULONG   cbOutSMB = 0;
    PBYTE   pInBuf;
    PBYTE   pInBufSMB;
    PBYTE   pOutBuf;
    PBYTE   pOutBufSMB;
    USHORT smbSessionID;
    USHORT smbRequestCounter;
    SMB_ERROR smbStatus;

    if (!(pInBufSMB = (PBYTE)malloc(cbMaxMessage)))
    {
        sync_err("Memory allocation ");
        return FALSE;
    }

    if (!(pOutBuf = (PBYTE)malloc(cbMaxMessage)))
    {
        sync_err("Memory allocation ");
        return FALSE;
    }
    ZeroMemory(pOutBuf, cbMaxMessage);

    if (!(pOutBufSMB = (PBYTE)malloc(cbMaxMessage)))
    {
        sync_err("Memory allocation ");
        return FALSE;
    }
    ZeroMemory(pOutBufSMB, cbMaxMessage);

    /* SMB Negotiate Protocol (0x72 request) */
    cbOutSMB = cbMaxMessage;
    if (!smb_GenComNegoMsg(pOutBufSMB, &cbOutSMB))
    {
        sync_err("smb_GenComNegoMsg failed!\n");
        return FALSE;
    }
    PrintHexDumpMax(cbOutSMB, (PBYTE)pOutBufSMB, cbOutSMB);

    /* fist call ... getting sessionid (smbSessinoID) in response */
    cbInSMB = cbMaxMessage;
    if (!SendRecvMsgSMB(s, (PBYTE)pOutBufSMB, cbOutSMB,
                        pInBufSMB, &cbInSMB, NULL, NULL))
    {
        sync_err("SendRecvMsgSMB failed!\n");
        return FALSE;
    }

    // Gen NTLM Message
    cbOut = 1024;// Hack
    Success = GenClientContext(NULL,
                               0,
                               pOutBuf,
                               &cbOut,
                               &fDone,
                               pcp,
                               hCred,
                               hcText);
    if (!Success)
    {
        sync_err("GenClientContext failed!\n");
        return FALSE;
    }
    NtlmCheckSecBuffer(TESTSEC_CLI_AUTH_INIT, pOutBuf);

    cbOutSMB = cbMaxMessage;
    smbRequestCounter = 0;
    // Session Setup AndX Request (0x73 request)
    if (!smb_GenComSessionSetupMsg(pOutBufSMB, &cbOutSMB,
                                   pOutBuf, cbOut, 0, 0))
    {
        sync_err("smb_GenComSessionSetupMsg failed!\n");
        return FALSE;
    }

    cbInSMB = cbMaxMessage;
    if (!SendRecvMsgSMB(s, (PBYTE)pOutBufSMB, cbOutSMB,
                        pInBufSMB, &cbInSMB, &smbStatus,
                        &smbSessionID))
    {
        sync_err("SendRecvMsgSMB failed!\n");
        return FALSE;
    }
    sync_trace("SMB Status 0x%x\n", smbStatus.NT_Status);
    if (smbStatus.NT_Status != STATUS_MORE_PROCESSING_REQUIRED)
    {
        // STATUS_INVALID_SMB = 0x00010002
        sync_err("Error NT_Status 0x%x\n", smbStatus.NT_Status);
        return FALSE;
    }
    if (!smb_GetNTMLMsg(pInBufSMB, cbInSMB, &pInBuf, &cbIn))
    {
        sync_err("smb_GetNTMLMsg failed!\n");
        return FALSE;
    }
    printf("%li %li\n", cbInSMB, cbIn);
    PrintHexDumpMax(cbInSMB, pInBufSMB, cbInSMB);
    PrintHexDumpMax(cbIn, pInBuf, cbIn);

    while (!fDone)
    {
        cbOut = cbMaxMessage;
        Success = GenClientContext(pInBuf,
                                   cbIn,
                                   pOutBuf,
                                   &cbOut,
                                   &fDone,
                                   pcp,
                                   hCred,
                                   hcText);
        sync_ok(Success, "GenClientContext failed.\n");
        if (!Success)
        {
            sync_err("GenClientContext failed.\n");
            return FALSE;
        }
        NtlmCheckSecBuffer(TESTSEC_CLI_AUTH_FINI, pOutBuf);

        cbOutSMB = cbMaxMessage;
        smbRequestCounter++;
        // Session Setup AndX Request (0x73 request)
        if (!smb_GenComSessionSetupMsg(pOutBufSMB, &cbOutSMB, pOutBuf,
                                       cbOut, smbSessionID,
                                       smbRequestCounter))
        {
            sync_err("smb_GenComSessionSetupMsg failed!\n");
            return FALSE;
        }

        cbInSMB = cbMaxMessage;
        if (!SendRecvMsgSMB(s, (PBYTE)pOutBufSMB, cbOutSMB,
                            pInBufSMB, &cbInSMB, &smbStatus,
                            NULL))
        {
            sync_err("SendRecvMsgSMB failed!\n");
            return FALSE;
        }
        sync_trace("SMB Status 0x%x\n", smbStatus.NT_Status);
        if (smbStatus.NT_Status != STATUS_MORE_PROCESSING_REQUIRED)
        {
            // STATUS_INVALID_SMB = 0x00010002
            sync_err("Error NT_Status 0x%x\n", smbStatus.NT_Status);
            return FALSE;
        }
        if (!smb_GetNTMLMsg(pInBufSMB, cbInSMB, &pInBuf, &cbIn))
        {
            sync_err("smb_GetNTMLMsg failed!\n");
            return FALSE;
        }
    }

    sync_trace("DoAuthentication end\n");
    free(pInBufSMB);
    free(pOutBuf);
    free(pOutBufSMB);
    return TRUE;
}

BOOL
client2_DoAuthentication(
    PCLI_PARAMS pcp,
    IN SOCKET s,
    IN PCredHandle hCred,
    IN PSecHandle  hcText)
{
    BOOL Success;
    BOOL    fDone = FALSE;
    DWORD   cbOut = 0;
    DWORD   cbIn = 0;
    PBYTE   pInBuf;
    PBYTE   pOutBuf;

    if (!(pInBuf = (PBYTE)malloc(cbMaxMessage)))
    {
        sync_err("Memory allocation ");
        return FALSE;
    }

    if (!(pOutBuf = (PBYTE)malloc(cbMaxMessage)))
    {
        sync_err("Memory allocation ");
        return FALSE;
    }

    cbOut = cbMaxMessage;
    Success = GenClientContext(NULL,
                               0,
                               pOutBuf,
                               &cbOut,
                               &fDone,
                               pcp,
                               hCred,
                               hcText);
    sync_ok(Success, "GenClientContext failed\n");
    if (!Success)
    {
        sync_err("GenClientContext failed!\n");
        return FALSE;
    }
    NtlmCheckSecBuffer(TESTSEC_CLI_AUTH_INIT, pOutBuf);

    if (!SendMsg(s, pOutBuf, cbOut))
    {
        sync_err("Send message failed.\n");
        return FALSE;
    }

    while (!fDone)
    {
        if (!ReceiveMsg(s, pInBuf, cbMaxMessage, &cbIn))
        {
            sync_err("Receive message failed ");
            return FALSE;
        }

        cbOut = cbMaxMessage;
        Success = GenClientContext(pInBuf,
                                   cbIn,
                                   pOutBuf,
                                   &cbOut,
                                   &fDone,
                                   pcp,
                                   hCred,
                                   hcText);
        sync_ok(Success, "GenClientContext failed.\n");
        if (!Success)
        {
            sync_err("GenClientContext failed.\n");
            return FALSE;
        }
        NtlmCheckSecBuffer(TESTSEC_CLI_AUTH_FINI, pOutBuf);

        if (!SendMsg(s, pOutBuf, cbOut))
        {
            sync_err("Send message 2 failed.\n");
            return FALSE;
        }
    }

    sync_trace("DoAuthentication end\n");
    free(pInBuf);
    free(pOutBuf);
    return TRUE;
}

BOOL
GenClientContext(
    PBYTE pIn,
    DWORD cbIn,
    PBYTE pOut,
    DWORD *pcbOut,
    BOOL  *pfDone,
    PCLI_PARAMS pcp,
    PCredHandle hCred,
    PSecHandle  hcText)
{
    SECURITY_STATUS ss;
    TimeStamp       Lifetime;
    SecBufferDesc   OutBuffDesc;
    SecBuffer       OutSecBuff;
    SecBufferDesc   InBuffDesc;
    SecBuffer       InSecBuff;
    ULONG           ContextAttributes;

    if (pIn)
    {
        printf("===INPUT===\n");
        PrintHexDump(cbIn, (PBYTE)pIn);
    } else
    {
        printf("===INPUT (EMPTY)===\n");
    }

    if (!pIn)
    {
        ss = AcquireCredentialsHandle(NULL,
                                      pcp->PackageName,
                                      SECPKG_CRED_OUTBOUND,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      hCred,
                                      &Lifetime);
        sync_ok(SEC_SUCCESS(ss), "AcquireCredentialsHandle failed with error 0x%08lx\n", ss);
        if (!SEC_SUCCESS(ss))
        {
            sync_err("AcquireCreds failed ");
            return FALSE;
        }
    }

    //--------------------------------------------------------------------
    //  Prepare the buffers.

    OutBuffDesc.ulVersion = 0;
    OutBuffDesc.cBuffers  = 1;
    OutBuffDesc.pBuffers  = &OutSecBuff;

    OutSecBuff.cbBuffer   = *pcbOut;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer   = pOut;

    /*
     * The input buffer is created only if a message has been received
     * from the server.
     */
    if (pIn)
    {
        InBuffDesc.ulVersion = 0;
        InBuffDesc.cBuffers  = 1;
        InBuffDesc.pBuffers  = &InSecBuff;

        InSecBuff.cbBuffer   = cbIn;
        InSecBuff.BufferType = SECBUFFER_TOKEN;
        InSecBuff.pvBuffer   = pIn;

        PrintISCReqAttr(MessageAttribute);
        ss = InitializeSecurityContext(hCred,
                                       hcText,
                                       pcp->TargetName,
                                       MessageAttribute,
                                       0,
                                       SECURITY_NATIVE_DREP,
                                       &InBuffDesc,
                                       0,
                                       hcText,
                                       &OutBuffDesc,
                                       &ContextAttributes,
                                       &Lifetime);
        sync_ok(ContextAttributes == 0x1001c,
                "ContextAttributes are 0x%x, expected 0x%x\n",
                ContextAttributes, 0x1001c);
        PrintISCRetAttr(ContextAttributes);
    }
    else
    {
        PrintISCReqAttr(MessageAttribute);
        ss = InitializeSecurityContext(hCred,
                                       NULL,
                                       pcp->TargetName,
                                       MessageAttribute,
                                       0,
                                       SECURITY_NATIVE_DREP,
                                       NULL,
                                       0,
                                       hcText,
                                       &OutBuffDesc,
                                       &ContextAttributes,
                                       &Lifetime);
        sync_ok(ContextAttributes == 0x10010,
                "ContextAttributes are 0x%x, expected 0x%x\n",
                ContextAttributes, 0x10010);
        PrintISCRetAttr(ContextAttributes);
    }

    sync_ok(SEC_SUCCESS(ss), "InitializeSecurityContext failed with error 0x%08lx\n", ss);
    if (!SEC_SUCCESS(ss))
    {
        sync_err("InitializeSecurityContext failed ");
        return 0;
    }

    /* If necessary, complete the token */
    if ((ss == SEC_I_COMPLETE_NEEDED) ||
        (ss == SEC_I_COMPLETE_AND_CONTINUE))
    {
        ss = CompleteAuthToken(hcText, &OutBuffDesc);
        sync_ok(SEC_SUCCESS(ss), "CompleteAuthToken failed with error 0x%08lx\n", ss);
        if (!SEC_SUCCESS(ss))
        {
            sync_err("complete failed: 0x%08lx\n", ss);
            return FALSE;
        }
    }

    *pcbOut = OutSecBuff.cbBuffer;

    *pfDone = !((ss == SEC_I_CONTINUE_NEEDED) ||
                (ss == SEC_I_COMPLETE_AND_CONTINUE));

    sync_trace("Token buffer generated (%lu bytes):\n", OutSecBuff.cbBuffer);
    printf("===OUTPUT===\n");
    PrintSecBuffer(&OutSecBuff);

    return TRUE;

}

BOOL
GenClientContextSMB(
    PBYTE pIn,
    DWORD cbIn,
    PBYTE pOut,
    DWORD *pcbOut,
    BOOL  *pfDone,
    PCLI_PARAMS pcp,
    PCredHandle hCred,
    PSecHandle  hcText)
{
    return FALSE;
}


PBYTE
DecryptThis(
    PBYTE   pBuffer,
    LPDWORD pcbMessage,
    PSecHandle hCtxt,
    ULONG   cbSecurityTrailer)
{
    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    PBYTE             pSigBuffer;
    PBYTE             pDataBuffer;
    DWORD             SigBufferSize;

    /*
     * By agreement, the server encrypted the message and set the size
     * of the trailer block to be just what it needed. DecryptMessage
     * needs the size of the trailer block.
     * The size of the trailer is in the first DWORD of the
     * message received.
     */
    SigBufferSize = *((DWORD*)pBuffer);
    sync_trace("data before decryption including trailer (%lu bytes):\n",
          *pcbMessage);
    PrintHexDump(*pcbMessage, (PBYTE)pBuffer);

    /*
     * By agreement, the server placed the trailer at the beginning
     * of the message that was sent immediately following the trailer
     * size DWORD.
     */
    pSigBuffer = pBuffer + sizeof(DWORD);

    /* The data comes after the trailer */
    pDataBuffer = pSigBuffer + SigBufferSize;

    /* *pcbMessage is reset to the size of just the encrypted bytes */
    *pcbMessage = *pcbMessage - SigBufferSize - sizeof(DWORD);

    /*
     * Prepare the buffers to be passed to the DecryptMessage function
     */

    BuffDesc.ulVersion    = 0;
    BuffDesc.cBuffers     = ARRAYSIZE(SecBuff);
    BuffDesc.pBuffers     = SecBuff;

    SecBuff[0].cbBuffer   = SigBufferSize;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer   = pSigBuffer;

    SecBuff[1].cbBuffer   = *pcbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer   = pDataBuffer;

    ss = DecryptMessage(hCtxt, &BuffDesc, 0, &ulQop);
    sync_ok(SEC_SUCCESS(ss), "DecryptMessage failed");

    /* Return a pointer to the decrypted data. The trailer data is discarded. */
    return pDataBuffer;
}

PBYTE
VerifyThis(
    PBYTE   pBuffer,
    LPDWORD pcbMessage,
    PSecHandle hCtxt,
    ULONG   cbMaxSignature)
{
    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    PBYTE             pSigBuffer;
    PBYTE             pDataBuffer;

    /*
     * The global cbMaxSignature is the size of the signature
     * in the message received.
     */
    sync_trace("data before verifying (including signature):\n");
    PrintHexDump(*pcbMessage, pBuffer);

    /*
     * By agreement with the server,
     * the signature is at the beginning of the message received,
     * and the data that was signed comes after the signature.
     */
    pSigBuffer = pBuffer;
    pDataBuffer = pBuffer + cbMaxSignature;

    /* The size of the message is reset to the size of the data only */
    *pcbMessage = *pcbMessage - cbMaxSignature;

    /*
     * Prepare the buffers to be passed to the signature verification function
     */

    BuffDesc.ulVersion    = 0;
    BuffDesc.cBuffers     = ARRAYSIZE(SecBuff);
    BuffDesc.pBuffers     = SecBuff;

    SecBuff[0].cbBuffer   = cbMaxSignature;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer   = pSigBuffer;

    SecBuff[1].cbBuffer   = *pcbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer   = pDataBuffer;

    ss = VerifySignature(hCtxt, &BuffDesc, 0, &ulQop);
    sync_ok(SEC_SUCCESS(ss), "VerifySignature failed with error 0x%08lx\n", ss);
    if (!SEC_SUCCESS(ss))
        sync_err("VerifyMessage failed");
    else
        sync_trace("Message was properly signed.\n");

    return pDataBuffer;
}

BOOL WINAPI
client2_start(
    IN PCLI_PARAMS pcp)
{
    SOCKET          Client_Socket = INVALID_SOCKET;
    BYTE            Data[BIG_BUFF];
    PCHAR           pMessage;
    CredHandle      hCred;
    SecHandle       hCtxt;
    SECURITY_STATUS ss;
    DWORD           cbRead;
    //ULONG           cbMaxSignature;
    ULONG           cbSecurityTrailer;
    SecPkgContext_Sizes           SecPkgContextSizes;
    SecPkgContext_NegotiationInfo SecPkgNegInfo;
    DWORD bRet = FALSE;

    /* Connect to a server */
    if (!client2_ConnectAuthSocket(pcp, &Client_Socket, &hCred, &hCtxt))
    {
        /* do not free garbage (in done) */
        hCtxt.dwLower = 0;
        hCred.dwLower = 0;
        sync_err("Unable to authenticate server connection.\n");
        goto done;
    }

    /*
     * An authenticated session with a server has been established.
     * Receive and manage a message from the server.
     * First, find and display the name of the negotiated
     * SSP and the size of the signature and the encryption
     * trailer blocks for this SSP.
     */
    ss = QueryContextAttributes(&hCtxt,
                                SECPKG_ATTR_NEGOTIATION_INFO,
                                &SecPkgNegInfo);
    sync_ok(SEC_SUCCESS(ss), "QueryContextAttributes failed with error 0x%08lx\n", ss);
    if (!SEC_SUCCESS(ss))
    {
        sync_err("QueryContextAttributes failed.\n");
        goto done;
    }
    else
    {
        sync_trace("Negotiation State: 0x%x\n", SecPkgNegInfo.NegotiationState);
        sync_trace("fCapabilities: 0x%x\n", SecPkgNegInfo.PackageInfo->fCapabilities);
        sync_trace("wVersion/wRPCID: %d/%d\n",
                    SecPkgNegInfo.PackageInfo->wVersion,
                    SecPkgNegInfo.PackageInfo->wRPCID);
        sync_trace("cbMaxToken: %d\n", SecPkgNegInfo.PackageInfo->cbMaxToken);
        sync_trace("Package Name: %S\n", SecPkgNegInfo.PackageInfo->Name);
        sync_trace("Package Comment: %S\n", SecPkgNegInfo.PackageInfo->Comment);
        FreeContextBuffer(SecPkgNegInfo.PackageInfo);
    }

    ss = QueryContextAttributes(&hCtxt,
                                SECPKG_ATTR_SIZES,
                                &SecPkgContextSizes);
    sync_ok(SEC_SUCCESS(ss), "Querycontext2 failed!");

    //cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;


    /*
     * Decrypt and display the message from the server
     */
    if (!ReceiveBytes(Client_Socket,
                      Data,
                      BIG_BUFF,
                      &cbRead))
    {
        sync_err("No response from server.\n");
        goto done;
    }

    sync_ok(cbRead != 0, "Zero bytes received ");

    pMessage = (PCHAR)DecryptThis(Data,
                                  &cbRead,
                                  &hCtxt,
                                  cbSecurityTrailer);
    sync_trace("message len: %ld message: %.*s\n", cbRead, (int)cbRead/sizeof(TCHAR), pMessage);

    bRet = TRUE;
done:
    /* Terminate socket and security package */
    if (hCtxt.dwLower != 0)
        DeleteSecurityContext(&hCtxt);
    if (hCred.dwLower != 0)
        FreeCredentialHandle(&hCred);
    if (Client_Socket != INVALID_SOCKET)
    {
        shutdown(Client_Socket, 2);
        closesocket(Client_Socket);
    }

    return bRet;
}


//DWORD
//client2_main(
//  IN LPCTSTR ServerName,   // ServerName must be defined as the name of the computer running the server sample.    Example: _T("127.0.0.1")
//  IN LPCTSTR TargetName,   // TargetName must be defined as the logon name of the user running the server program. Example: _T("")
//  IN LPCTSTR PackageName)  // Example: _T("NTLM"), or _T("Negotiate")
int client2_main(int argc, WCHAR** argv)
{
    DWORD dwRet = 1;//FAILED
    WSADATA wsaData;
    CLI_PARAMS cp;

    sync_ok(argc == 6, "argumentcount mismatched - aborting\n");
    if (argc != 6)
        goto done;

    cp.ServerName = argv[0];
    cp.ServerPort = _wtoi(argv[1]);
    cp.TargetName = argv[2];
    cp.PackageName = argv[3];
    cp.user = argv[4];
    cp.pass = argv[5];

    //printf("start %S %S %S\n", ServerName, TargetName, PackageName);

    /* Startup WSA */
    if (WSAStartup(0x0101, &wsaData))
    {
        sync_err("Could not initialize winsock.\n");
        goto done;
    }

    /* Start the client */
    dwRet = client2_start(&cp);

done:
    /* Shutdown WSA and return */
    WSACleanup();

    //client_exit();
    return dwRet;
}
