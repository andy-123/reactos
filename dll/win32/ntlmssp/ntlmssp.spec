@ stdcall AcceptSecurityContext(ptr ptr ptr long long ptr ptr ptr ptr)
@ stdcall AcquireCredentialsHandleA(str str long ptr ptr ptr ptr ptr ptr)
@ stdcall AcquireCredentialsHandleW(wstr wstr long ptr ptr ptr ptr ptr ptr)secur32.AcquireCredentialsHandleW
#@ stdcall ApplyControlToken(ptr ptr)
@ stdcall CompleteAuthToken(ptr ptr)
@ stdcall DeleteSecurityContext(ptr)
@ stdcall EnumerateSecurityPackagesA(ptr ptr)
@ stdcall EnumerateSecurityPackagesW(ptr ptr)
@ stdcall FreeContextBuffer(ptr)
@ stdcall FreeCredentialsHandle(ptr)
@ stdcall ImpersonateSecurityContext(ptr)
@ stdcall InitSecurityInterfaceA()
@ stdcall InitSecurityInterfaceW()
@ stdcall InitializeSecurityContextA(ptr ptr str long long long ptr long ptr ptr ptr ptr)
@ stdcall InitializeSecurityContextW(ptr ptr wstr long long long ptr long ptr ptr ptr ptr)
@ stdcall MakeSignature(ptr long ptr long)
@ stdcall QueryContextAttributesA(ptr long ptr)
@ stdcall QueryContextAttributesW(ptr long ptr)
@ stdcall QuerySecurityPackageInfoA(str ptr)
@ stdcall QuerySecurityPackageInfoW(wstr ptr)
@ stdcall RevertSecurityContext(ptr)
@ stdcall SealMessage (ptr long ptr long) EncryptMessage
@ stdcall UnsealMessage(ptr ptr long ptr) DecryptMessage
@ stdcall VerifySignature(ptr ptr long ptr)
