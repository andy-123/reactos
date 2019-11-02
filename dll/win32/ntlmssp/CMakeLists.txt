spec2def(ntlmssp.dll ntlmssp.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    avl.c
	calculations.c
	ciphers.c
	context.c
	credentials.c
	crypt.c
	debug.c
	dllmain.c
    samba/
	messages.c
	ntlmssp.c
	protocol.c
    smbhelper.c
    smbsettings.c
    samba/auth/credentials/credentials_ntlm.c
    samba/auth/gensec/gensec_start.c
    samba/auth/gensec/gensec.c
    samba/auth/ntlmssp/gensec_ntlmssp.c
    samba/auth/ntlmssp/gensec_ntlmssp_server.c
    samba/auth/ntlmssp/ntlmssp_client.c
    samba/auth/ntlmssp/ntlmssp_ndr.c
    samba/auth/ntlmssp/ntlmssp_server.c
    samba/auth/ntlmssp/ntlmssp_sign.c
    samba/auth/ntlmssp/ntlmssp_util.c
    samba/libcli/auth/msrpc_parse.c
    samba/libcli/auth/ntlm_check.c
    samba/libcli/auth/smbdes.c
    samba/libcli/auth/smbencrypt.c
    samba/libcli/security/session.c
    samba/libcli/util/nterr.c
    samba/librpc/ndr/ndr.c
    samba/librpc/ndr/ndr_basic.c
    samba/librpc/ndr/ndr_ntlmssp.c
    samba/librpc/ndr/ndr_string.c
    samba/librpc/gen_ndr/ndr_ntlmssp.c
    samba/librpc/gen_ndr/ndr_ntlmssp_c.c
    samba/librpc/gen_ndr/ndr_ntlmssp_s.c
    samba/librpc/gen_ndr/ndr_security.c
    samba/lib/crypto/arcfour.c
    samba/lib/crypto/hmacmd5.c
    samba/lib/talloc/talloc.c
    samba/lib/tevent/tevent.c
    samba/lib/tevent/tevent_debug.c
    samba/lib/tevent/tevent_poll.c
    samba/lib/tevent/tevent_immediate.c
    samba/lib/tevent/tevent_standard.c
    samba/lib/tevent/tevent_req.c
    samba/lib/param/loadparm.c
    samba/lib/util/charset/codepoints.c
    samba/lib/util/charset/convert_string.c
    samba/lib/util/charset/iconv.c
    samba/lib/util/charset/pull_push.c
    samba/lib/util/charset/util_str.c
    samba/lib/util/charset/util_unistr.c
    samba/lib/util/charset/util_unistr_w.c
    samba/lib/util/data_blob.c
    samba/lib/util/debug.c
    samba/lib/util/genrand.c
    samba/lib/util/talloc_stack.c
    samba/lib/util/tevent_ntstatus.c
    samba/lib/util/time_basic.c
    samba/lib/util/util_strlist.c
    samba/lib/util/util.c
    samba/source4/auth/sam.c
    samba/source4/auth/ntlm/auth.c
    samba/source4/auth/ntlm/auth_sam.c
    samba/source4/auth/ntlm/auth_util.c
    strutil.c
	stubs.c
	sign.c
	util.c
	${CMAKE_CURRENT_BINARY_DIR}/ntlmssp_stubs.c
	${CMAKE_CURRENT_BINARY_DIR}/ntlmssp.def)

add_library(ntlmssp SHARED ${SOURCE})
allow_warnings(ntlmssp)
set_module_type(ntlmssp win32dll UNICODE)

target_link_libraries(ntlmssp zlib wine)

add_importlibs(ntlmssp advapi32 crypt32 netapi32 msvcrt kernel32 ntdll)

add_cd_file(TARGET ntlmssp DESTINATION reactos/system32 FOR all)
#add_importlib_target(ntlmssp.spec)
