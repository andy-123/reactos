/*
 * PROJECT:     Authentication Package DLL
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dll/win32/msv1_0/ntlm/protocol.h
 * PURPOSE:     ntlm globals definitions (header)
 * COPYRIGHT:   Copyright 2011 Samuel Serapión
 *              Copyright 2020 Andreas Maier (staubim@quantentunnel.de)
 */

#ifndef _MSV1_0_NTLM_GLOBALS_H_
#define _MSV1_0_NTLM_GLOBALS_H_

/* functions provided by LSA in SpInstanceInit */
extern PSECPKG_DLL_FUNCTIONS UsrFunctions;
/* functions we provide to LSA in SpUserModeInitialize */
extern SECPKG_USER_FUNCTION_TABLE NtlmUsrFn[1];


#endif
