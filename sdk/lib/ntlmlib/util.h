/*
 * PROJECT:     ntlmlib
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     utilities for ntlmlib (header)
 * COPYRIGHT:   Copyright 2011 Samuel Serapión
 *              Copyright 2020 Andreas Maier (staubim@quantentunnel.de)
 *
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#if 0
// Maps a NTSATUS to SECURITY_STATUS
NTSTATUS
NtStatusToSecStatus(
    IN SECURITY_STATUS SecStatus);
#endif

#if 0
// replacement for NtlmCreateExtWStrFromBlob
NTSTATUS
NtlmUStrAllocAndCopyBlob(
    IN PSecBuffer InputBuffer,
    IN PNTLM_BLOB Blob,
    IN OUT PUNICODE_STRING OutputStr);

// replacement for NtlmCreateExtAStrFromBlob
NTSTATUS
NtlmAStrAllocAndCopyBlob(
    IN PSecBuffer InputBuffer,
    IN PNTLM_BLOB Blob,
    IN OUT PSTRING OutputStr);
#endif

#if 0
VOID
NtlmInitExtStrWFromUnicodeString(
    OUT PEXT_STRING_W Dest,
    IN PUNICODE_STRING Src,
    IN BOOLEAN SrcSetToNULL);

VOID
NtlmInitUnicodeStringFromExtStrW(
    OUT PUNICODE_STRING Dest,
    IN PEXT_STRING_W Src,
    IN BOOLEAN SrcSetToNULL);

// SAM Helpers
typedef struct _NTLM_SAM_HANDLES
{
    SAMPR_HANDLE ServerHandle;
    SAMPR_HANDLE DomainHandle;
    SAM_HANDLE UserHandle;
} NTLM_SAM_HANDLES, *PNTLM_SAM_HANDLES;

NTSTATUS
NtlmSamOpenUser(
    IN PUNICODE_STRING UserName,
    IN PUNICODE_STRING UserDom,
    OUT PNTLM_SAM_HANDLES SamHandles);
NTSTATUS
NtlmSamCloseUserHandle(
    IN BOOLEAN UpdateUserLogonState,
    IN NTSTATUS Status,
    IN PNTLM_SAM_HANDLES SamHandles);

/* string helpers */
BOOL
NtlmStructWriteStrA(
    IN PVOID DataStart,
    IN ULONG DataSize,
    OUT PCHAR* DstDataAPtr,
    IN const char* SrcDataA,
    IN ULONG SrcDataLen,
    IN OUT PBYTE* AbsoluteOffsetPtr,
    IN BOOL TerminateWith0);

BOOL
NtlmStructWriteStrW(
    IN PVOID DataStart,
    IN ULONG DataSize,
    OUT PWCHAR* DstDataWPtr,
    IN const WCHAR* SrcDataW,
    IN ULONG SrcDataLen,
    IN OUT PBYTE* AbsoluteOffsetPtr,
    IN BOOL TerminateWith0);

BOOL
NtlmUStrWriteToStruct(
    IN PVOID DataStart,
    IN ULONG DataSize,
    OUT PUNICODE_STRING DstData,
    IN const PUNICODE_STRING SrcData,
    IN OUT PBYTE* AbsoluteOffsetPtr,
    IN BOOL TerminateWith0);

BOOL
NtlmAStrWriteToStruct(
    IN PVOID DataStart,
    IN ULONG DataSize,
    OUT PSTRING DstData,
    IN const PSTRING SrcData,
    IN OUT PBYTE* AbsoluteOffsetPtr,
    IN BOOL TerminateWith0);

/* misc */
BOOL
NtlmFixupAndValidateUStr(
    IN OUT PUNICODE_STRING String,
    IN ULONG_PTR FixupOffset);

BOOL
NtlmFixupAStr(
    IN OUT PSTRING String,
    IN ULONG_PTR FixupOffset);

/* ClientBuffer */
typedef struct _NTLM_CLIENT_BUFFER
{
    PVOID ClientBaseAddress;
    PVOID LocalBuffer;
} NTLM_CLIENT_BUFFER, *PNTLM_CLIENT_BUFFER;

NTSTATUS
NtlmAllocateClientBuffer(
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN ULONG BufferLength,
    IN OUT PNTLM_CLIENT_BUFFER Buffer);

NTSTATUS
NtlmCopyToClientBuffer(
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN ULONG BufferLength,
    IN OUT PNTLM_CLIENT_BUFFER Buffer);

VOID
NtlmFreeClientBuffer(
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN BOOL FreeClientBuffer,
    IN OUT PNTLM_CLIENT_BUFFER Buffer);
#endif

void
PrintHexDumpMax(
    _In_ int length,
    _In_ PBYTE buffer,
    _In_ int printmax);

void
PrintHexDump(
    _In_ DWORD length,
    _In_ PBYTE buffer);

#endif
