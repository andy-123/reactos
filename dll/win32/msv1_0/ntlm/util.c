/*
 * PROJECT:     Authentication Package DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     utils for msv1_0
 * COPYRIGHT:   Copyright 2011 Samuel Serapión
 *              Copyright 2020 Andreas Maier (staubim@quantentunnel.de)
 */

#include <precomp.h>

#include "wine/debug.h"
WINE_DEFAULT_DEBUG_CHANNEL(ntlm);

#define NTLM_ALLOC_TAG "NTLM"
#define NTLM_ALLOC_TAG_SIZE strlen(NTLM_ALLOC_TAG)

PVOID
NtlmAllocate(
    _In_ size_t Size,
    _In_ BOOL UsePrivateLsaHeap)
{
    PVOID buffer = NULL;

    if(Size == 0)
    {
        ERR("Allocating 0 bytes!\n");
        return NULL;
    }

    Size += NTLM_ALLOC_TAG_SIZE;

    switch(NtlmMode)
    {
        case NtlmLsaMode:
        {
            if (UsePrivateLsaHeap)
                buffer = LsaFunctions->AllocatePrivateHeap(Size);
            else
                buffer = LsaFunctions->AllocateLsaHeap(Size);

            if (buffer != NULL)
                RtlZeroMemory(buffer, Size);
            break;
        }
        case NtlmUserMode:
        {
            buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
            break;
        }
        default:
        {
            ERR("NtlmState unknown!\n");
            break;
        }
    }

    memcpy(buffer, NTLM_ALLOC_TAG, NTLM_ALLOC_TAG_SIZE);
    buffer = (PBYTE)buffer + NTLM_ALLOC_TAG_SIZE;

    return buffer;
}

VOID
NtlmFree(
    _In_ PVOID Buffer,
    _In_ BOOL FromPrivateLsaHeap)
{
    if (Buffer)
    {
        Buffer = (PBYTE)Buffer - NTLM_ALLOC_TAG_SIZE;
        ASSERT(memcmp(Buffer, NTLM_ALLOC_TAG, NTLM_ALLOC_TAG_SIZE) == 0);
        *(char*)Buffer = 'D';

        switch (NtlmMode)
        {
            case NtlmLsaMode:
            {
                if (FromPrivateLsaHeap)
                    LsaFunctions->FreePrivateHeap(Buffer);
                else
                    LsaFunctions->FreeLsaHeap(Buffer);
                break;
            }
            case NtlmUserMode:
            {
                HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Buffer);
                break;
            }
            default:
            {
                ERR("NtlmState unknown!\n");
                break;
            }
        }
    }
    else
    {
        ERR("Trying to free NULL!\n");
    }
}

BOOL
NtlmUStrAlloc(
    _Inout_ PUNICODE_STRING Dst,
    _In_ USHORT SizeInBytes,
    _In_ USHORT InitLength)
{
    Dst->Length = InitLength;
    Dst->MaximumLength = SizeInBytes;
    Dst->Buffer = NtlmAllocate(SizeInBytes, FALSE);
    return (Dst->Buffer != NULL);
}

VOID
NtlmUStrFree(
    _In_ PUNICODE_STRING String)
{
    if ((String == NULL) ||
        (String->Buffer == NULL) ||
        (String->MaximumLength == 0))
        return;
    NtlmFree(String->Buffer, FALSE);
    String->Buffer = NULL;
    String->MaximumLength = 0;
}

/**
 * @brief Helper to fill a WCHAR-String in a struct.
 *        The stringdata is append to the struct. The
 *        function does not allocate memory.
 * @param DataStart start addres of the struct
 * @param DataSize size of allocated memory (including payload)
 * @param WriteRelativeOffset If TRUE the address which will be written
 *            to pDataFieldW will be relative to DataStart.
 *            If FALSE it will be an absolut address.
 * @param DataFieldW  Pointer to the WCHAR* datafield. The adress
 *            of the data will be written to it.
 * @param SrcDataW Data to write/append at pOffset (payload). pOffset
 *            will be increased after writing data.
 * @param SrcDataLen if 0 it will be autodetected by assuming a
 *            0-terminating string.
 *            SrcDataLen is the length in bytes without terminator.
 * @param AbsoluteOffset Current absolute offset. Will be increased by
 *            data length.
 * @return FALSE if something went wrong
 */
BOOL
NtlmStructWriteStrW(
    _In_ PVOID DataStart,
    _In_ ULONG DataSize,
    _Out_ PWCHAR* DstDataWPtr,
    _In_ const WCHAR* SrcDataW,
    _In_ ULONG SrcDataLen,
    _Inout_ PBYTE* AbsoluteOffsetPtr,
    _In_ BOOL TerminateWith0)
{
    ULONG SrcDataMaxLen;

    if (SrcDataLen == 0)
        SrcDataLen = wcslen(SrcDataW) * sizeof(WCHAR);

    SrcDataMaxLen = SrcDataLen;
    if (TerminateWith0)
        SrcDataMaxLen += sizeof(WCHAR);

    if (*AbsoluteOffsetPtr < (PBYTE)DataStart)
    {
        ERR("Invalid offset\n");
        return FALSE;
    }
    if (*AbsoluteOffsetPtr + SrcDataMaxLen > (PBYTE)DataStart + DataSize)
    {
        ERR("Out of bounds!\n");
        return FALSE;
    }

    memcpy(*AbsoluteOffsetPtr, SrcDataW, SrcDataLen);
    *DstDataWPtr = (WCHAR*)*AbsoluteOffsetPtr;
    if (TerminateWith0)
        (*DstDataWPtr)[SrcDataLen / sizeof(WCHAR)] = 0;
    *AbsoluteOffsetPtr += SrcDataMaxLen;

    return TRUE;
}

BOOL
NtlmUStrWriteToStruct(
    _In_ PVOID DataStart,
    _In_ ULONG DataSize,
    _Out_ PUNICODE_STRING DstData,
    _In_ const PUNICODE_STRING SrcData,
    _Inout_ PBYTE* AbsoluteOffsetPtr,
    _In_ BOOL TerminateWith0)
{
    if (!NtlmStructWriteStrW(
        DataStart, DataSize,
        &DstData->Buffer,
        SrcData->Buffer, SrcData->Length,
        AbsoluteOffsetPtr,
        TerminateWith0))
        return FALSE;

    DstData->Length = SrcData->Length;
    DstData->MaximumLength = SrcData->Length;
    if (TerminateWith0)
        SrcData->MaximumLength += sizeof(WCHAR);

    return TRUE;
}

BOOL
NtlmFixupAndValidateUStr(
    _Inout_ PUNICODE_STRING String,
    _In_ ULONG_PTR FixupOffset)
{
    NTSTATUS Status;

    if (String->Length)
    {
        String->Buffer = FIXUP_POINTER(String->Buffer, FixupOffset);
        String->MaximumLength = String->Length;
    }
    else
    {
        String->Buffer = NULL;
        String->MaximumLength = 0;
    }

    Status = RtlValidateUnicodeString(0, String);
    return NT_SUCCESS(Status);
}

BOOL
NtlmFixupAStr(
    _Inout_ PSTRING String,
    _In_ ULONG_PTR FixupOffset)
{
    if (String->Length)
    {
        String->Buffer = (PCHAR)FIXUP_POINTER(String->Buffer, FixupOffset);
        String->MaximumLength = String->Length;
    }
    else
    {
        String->Buffer = NULL;
        String->MaximumLength = 0;
    }

    return TRUE;
}

NTSTATUS
NtlmAllocateClientBuffer(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ ULONG BufferLength,
    _Inout_ PNTLM_CLIENT_BUFFER Buffer)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (!Buffer)
        return STATUS_NO_MEMORY;

    Buffer->LocalBuffer = NtlmAllocate(BufferLength, FALSE);
    if (!Buffer->LocalBuffer)
        return STATUS_NO_MEMORY;

    if ((HANDLE)ClientRequest == INVALID_HANDLE_VALUE)
    {
        Buffer->ClientBaseAddress = Buffer->LocalBuffer;
        //if (!ClientBaseAddress)
        //    return STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        Status = DispatchTable.AllocateClientBuffer(ClientRequest,
                                                    BufferLength,
                                                    &Buffer->ClientBaseAddress);
        if (!NT_SUCCESS(Status))
        {
            NtlmFree(Buffer->LocalBuffer, FALSE);
            Buffer->LocalBuffer == NULL;
        }
        //FIXME: Maybe we have to free ClientBaseAddress if something
        //       goes wrong ...? I'm not sure about that ...
    }
    return Status;
}

NTSTATUS
NtlmCopyToClientBuffer(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ ULONG BufferLength,
    _Inout_ PNTLM_CLIENT_BUFFER Buffer)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if ((HANDLE)ClientRequest == INVALID_HANDLE_VALUE)
    {
        // If ClientRequest ist INVALID_HANDLE_VALUE
        // Buffer->LocalBuffer == Buffer->ClientBaseAddress
        if (Buffer->ClientBaseAddress != Buffer->LocalBuffer)
        {
            ERR("Buffer->ClientBaseAddress != Buffer->LocalBuffer (something must be wrong!)\n");
            return STATUS_INTERNAL_ERROR;
        }
    }
    else
    {
        if (!Buffer->ClientBaseAddress ||
            !Buffer->LocalBuffer)
        {
            ERR("Invalid Buffer - not allocated!\n");
            return STATUS_NO_MEMORY;
        }
        Status = DispatchTable.CopyToClientBuffer(ClientRequest,
                                                  BufferLength,
                                                  Buffer->ClientBaseAddress,
                                                  Buffer->LocalBuffer);
    }
    return Status;
}

VOID
NtlmFreeClientBuffer(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ BOOL FreeClientBuffer,
    _Inout_ PNTLM_CLIENT_BUFFER Buffer)
{
    if (!Buffer->ClientBaseAddress)
        return;

    if ((HANDLE)ClientRequest == INVALID_HANDLE_VALUE)
    {
        if (Buffer->ClientBaseAddress != Buffer->LocalBuffer)
        {
            ERR("Buffer->ClientBaseAddress != Buffer->LocalBuffer (something must be wrong!)\n");
            return;
        }
        // LocalBuffer and ClientBaseAddress is the same
        // so we have only to free it if FreeClientBuffer is TRUE.
        Buffer->LocalBuffer == NULL;
        if (FreeClientBuffer)
        {
            NtlmFree(Buffer->ClientBaseAddress, FALSE);
            Buffer->ClientBaseAddress == NULL;
        }
    }
    else
    {
        NtlmFree(Buffer->LocalBuffer, FALSE);
        Buffer->LocalBuffer == NULL;
        if (FreeClientBuffer)
            DispatchTable.FreeClientBuffer(ClientRequest,
                                           Buffer->ClientBaseAddress);
        Buffer->ClientBaseAddress == NULL;
    }
}
