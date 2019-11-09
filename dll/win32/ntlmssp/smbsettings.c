// settings for samba ... loaded from windows (registry)

#include "smbincludes.h"
#include "samba/libcli/auth/ntlm_check.h"
#include "samba/lib/param/loadparm.h"

#include "wine/debug.h"
WINE_DEFAULT_DEBUG_CHANNEL(ntlm);



struct gensec_settings* gsettings = NULL;
struct rosconfig
{
    /* LMCompatibilityLevel comes from registry */
    uint8_t LMCompatibilityLevel;
    /* CliLMLevel and SvrLMLevel depends on LMCompatibilityLevel */
    uint8_t CliLMLevel;
    uint8_t SvrLMLevel;
    /* computername */
    EXT_STRING_A computerNameOEM;
    /* netbios name */
    EXT_STRING_A netbiosNameOEM;
    /* domain name - empty if not in domain */
    EXT_STRING_A domainNameOEM;
} roscfg;



const char *lpcfg_workgroup(struct loadparm_context * x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP-1";
}

const char *lpcfg_netbios_name(struct loadparm_context *x)
{
    /* not used - samba takes value from gsettings.server_netbios_name */
    return "unused";
}

const char *lpcfg_dnsdomain(struct loadparm_context *x)
{
    /* not used - samba takes value from gsettings.server_dns_domain */
    return "unused";
}

const int lpcfg_map_to_guest(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return 0;//NEVER_MAP_TO_GUEST;
}

const bool lpcfg_client_lanman_auth(struct loadparm_context *x)
{
    return true;//(smbcfg.CliLMLevel & CLI_LMFLAG_USE_AUTH_LM);
}

const bool lpcfg_lanman_auth(struct loadparm_context *x)
{
    return (roscfg.SvrLMLevel & SVR_LMFLAG_ACCPT_AUTH_LM);
}

const enum ntlm_auth_level lpcfg_ntlm_auth(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return NTLM_AUTH_ON;
}

const bool lpcfg_client_ntlmv2_auth(struct loadparm_context *x)
{
    return (roscfg.CliLMLevel & CLI_LMFLAG_USE_AUTH_NTLMv2);
}

/* gensec_start.c */
bool gensec_setting_bool(struct gensec_settings *settings, const char *mechanism, const char *name, bool default_value)
{
    if (strcasecmp(mechanism, "ntlmssp_server") == 0)
    {
        if (strcasecmp(name, "allow_lm_key") == 0)
            return (roscfg.SvrLMLevel & SVR_LMFLAG_ACCPT_AUTH_LM);
        else if (strcasecmp(name, "force_old_spnego") == 0)
            return false;
        else if (strcasecmp(name, "128bit") == 0)
            return true;
        else if (strcasecmp(name, "56bit") == 0)
            return true;
        else if (strcasecmp(name, "keyexchange") == 0)
            return true;
        else if (strcasecmp(name, "alwayssign") == 0)
            return true;
        else if (strcasecmp(name, "ntlm2") == 0)
            return true;
        else
        {
            D_WARNING("using default value for %s/%s\n", mechanism, name);
        }
    }
    else if (strcasecmp(mechanism, "ntlmssp_client") == 0)
    {
        if (strcasecmp(name, "unicode") == 0)
            return true;
        else if (strcasecmp(name, "send_nt_response") == 0)
            return true;
        else if (strcasecmp(name, "allow_lm_key") == 0)
            return (roscfg.SvrLMLevel & SVR_LMFLAG_ACCPT_AUTH_LM);
        else if (strcasecmp(name, "lm_key") == 0)
            return (roscfg.CliLMLevel & CLI_LMFLAG_USE_AUTH_LM);
        else if (strcasecmp(name, "force_old_spnego") == 0)
            return false;
        else if (strcasecmp(name, "128bit") == 0)
            return true;
        else if (strcasecmp(name, "56bit") == 0)
            return true;
        else if (strcasecmp(name, "keyexchange") == 0)
            return true;
        else if (strcasecmp(name, "alwayssign") == 0)
            return true;
        else if (strcasecmp(name, "ntlm2") == 0)
            return (roscfg.CliLMLevel & CLI_LMFLAG_USE_SSEC_NTLMv2);
        else
        {
            D_WARNING("using default value for %s/%s\n", mechanism, name);
        }
    }
    else
    {
        D_WARNING("using default value for %s/%s\n", mechanism, name);
    }
    /* default */
    return default_value;
}

struct gensec_settings* smbGetGensecSettigs()
{
    if (gsettings == NULL)
    {
        gsettings = talloc_zero(NULL, struct gensec_settings);
        gsettings->lp_ctx = talloc_zero(NULL, struct loadparm_context);

        /* assign values from ROS to samba settings struct
         * smbcfg is freed after gsettings. So there is no
         * problem in simply assign char*-pointers */
        
        gsettings->target_hostname = "targethost";
        gsettings->backends = NULL;
        gsettings->server_dns_domain = (char*)roscfg.domainNameOEM.Buffer;
        gsettings->server_dns_name = (char*)roscfg.domainNameOEM.Buffer;
        gsettings->server_netbios_domain = "nb-dom";//unused
        gsettings->server_netbios_name = (char*)roscfg.netbiosNameOEM.Buffer;
    }

    return gsettings;
}

void NtlmInitializeSamba_LMCompLvl(
    IN ULONG LMCompatibilityLevel)
{
    /* maybe read from registry ... */
    /*  NTLMV1 works */
    /*  NTLMV2 not fully working (AUTH_MESSAGE receives INVALID_PARAMETER :-( ) */
    /* FIXME value is stored in registry ... so get it from there! */
    roscfg.LMCompatibilityLevel = 2;// partly unimplemented
    /* LMCompatibilityLevel - matrix
     * cli/DC  lvl   LM-     NTLMv1-   NTLMv2   v2-Session-
     *               auth.   auth.     auth.     Security
     * cli      0    use     use       -         never
     * DC       0    accept  accept    accept    accept
     * cli      1    use     use                 use if svr supports it
     * DC       1    accept  accept    -         accept
     * cli      2    -       use       -         use if svr supports it
     * DC       2    accept  accept    accept    accept
     * cli      3    -       -         use       use if svr supports it
     * DC       3    accept  accept    accept    accept
     * cli      4    -       -         use       use if svr supports it
     * DC       4    refuse  accept    accept    accept
     * cli      5    -       -         use       use if svr supports it
     * DC       5    refuse  refuse    accept    accept
     *
     * W2k-default = 2 */

    /* FIXME implement the following options ...
       Send LM & NTLM responses - never NTLMv2 */
    //#define NTLMSSP_LMCOMPLVL_LM_NTLM 0;
    /* Send LM & NTLM - use NTLMv2 session security if negotiated */
    //#define NTLMSSP_LMCOMPLVL_LM_NTLM_NTLMv2 1
    /* Send NTLM responses only */
    //#define NTLMSSP_LMCOMPLVL_NTLM 2 // w2k default
    /* Send NTLMv2 responses only */
    //#define NTLMSSP_LMCOMPLVL_NTLMv2 3
    /* Send NTLMv2 responses only. Refuse LM */
    //#define NTLMSSP_LMCOMPLVL_NTLMv2_NoLM 4
    /* Send NTLMv2 responses only. Refuse LM & NTLM */
    //#define NTLMSSP_LMCOMPLVL_NTLMv2_NoLM_NTLM 5;

    switch (roscfg.LMCompatibilityLevel)
    {
        case 0 :
        {
            roscfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_LM |
                                CLI_LMFLAG_USE_AUTH_NTLMv1;
            roscfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 1 :
        {
            roscfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_LM |
                                CLI_LMFLAG_USE_AUTH_NTLMv1 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            roscfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 2:
        default:
        {
            roscfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv1 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            roscfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 3 :
        {
            roscfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv2 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            roscfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 4 :
        {
            roscfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv2 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            roscfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 5 :
        {
            roscfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv2 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            roscfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
    }
}

void NtlmInitializeSamba_Names()
{
    WCHAR compNameW[CNLEN + 1];
    char dnsNameA[256];
    WCHAR *domNameW;
    ULONG compNameChLen = ARRAY_SIZE(compNameW);
    ULONG dnsNameChLen = ARRAY_SIZE(dnsNameA);
    EXT_STRING_W tmpW;

    if (!GetComputerNameW(compNameW, &compNameChLen))
    {
        compNameW[0] = L'\0';
        ERR("could not get computer name!\n");
    }
    TRACE("%s\n", debugstr_w(compNameW));

    if (!GetComputerNameExA(ComputerNameDnsHostname, dnsNameA, &dnsNameChLen))
    {
        dnsNameA[0] = '\0';
        ERR("could not get dns name!\n");
    }
    TRACE("%s\n",debugstr_a(dnsNameA));

    /* is this computer a domain member? */
    /* FIXME: NetGetJoinInformation is not implmented on ROS */
    /*        if implemented remove #if 1 block ... */
#if 1
    domNameW = NULL;
    /* assume no domain is joined */
    if (NetApiBufferAllocate((compNameChLen + 1) * sizeof(WCHAR), (PVOID*)&domNameW) == NERR_Success)
        wcscpy(domNameW, compNameW);
    else
        domNameW = NULL;
#else
    if (NetGetJoinInformation(NULL, &domNameW, &gsvr->lmJoinState) != NERR_Success)
    {
        ERR("failed to get domain join state!\n");
        gsvr->lmJoinState = NetSetupUnknownStatus;
        if (NetApiBufferAllocate(50, (PVOID*)&domNameW) == NERR_Success)
            wcscpy(domNameW, L"WORKGROUP");
        else
            domNameW = NULL;
    }
#endif
    if (!domNameW)
        ERR("could not get domain name!\n");

    ERR("%s\n", debugstr_w(domNameW));

    /* fill internal setting info */
    if (!ExtWStrInit(&tmpW, compNameW) ||
        !ExtWStrToAStr(&roscfg.computerNameOEM, &tmpW, TRUE, TRUE))
    {
        ERR("failed to allocate memory!\n");
        ExtAStrInit(&roscfg.computerNameOEM, NULL);
    }
    if (!ExtWStrSet(&tmpW, domNameW) ||
        !ExtWStrToAStr(&roscfg.domainNameOEM, &tmpW, TRUE, TRUE))
    {
        ERR("failed to allocate memory!\n");
        ExtAStrInit(&roscfg.domainNameOEM, 0);
    }
    if (!ExtAStrInit(&roscfg.netbiosNameOEM, dnsNameA))
    {
        ERR("failed to allocate memory!\n");
        ExtAStrInit(&roscfg.netbiosNameOEM, 0);
    }
    ExtStrFree(&tmpW);
}

void NtlmInitializeSamba()
{
    gsettings = NULL;
    NtlmInitializeSamba_LMCompLvl(2);
    NtlmInitializeSamba_Names();
}

void NtlmFinalizeSamba()
{
    if (gsettings)
    {
        talloc_free(gsettings->lp_ctx);
        talloc_free(gsettings);
        gsettings = NULL;
    }
    ExtStrFree(&roscfg.computerNameOEM);
    ExtStrFree(&roscfg.netbiosNameOEM);
    ExtStrFree(&roscfg.domainNameOEM);
}

