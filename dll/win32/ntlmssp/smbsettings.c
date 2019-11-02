// settings for samba ... loaded from windows (registry)

#include "smbincludes.h"
#include "samba/libcli/auth/ntlm_check.h"
#include "samba/lib/param/loadparm.h"

//#include "wine/debug.h"
//WINE_DEFAULT_DEBUG_CHANNEL(ntlm);



struct gensec_settings* gs = NULL;
struct smbconfig
{
    /* LMCompatibilityLevel comes from registry */
    uint8_t LMCompatibilityLevel;
    /* CliLMLevel and SvrLMLevel depends on LMCompatibilityLevel */
    uint8_t CliLMLevel;
    uint8_t SvrLMLevel;
} smbcfg;



const char *lpcfg_workgroup(struct loadparm_context * x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
}

const char *lpcfg_netbios_name(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
}

const char *lpcfg_dnsdomain(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
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
    return (smbcfg.SvrLMLevel & SVR_LMFLAG_ACCPT_AUTH_LM);
}

const enum ntlm_auth_level lpcfg_ntlm_auth(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return NTLM_AUTH_ON;
}

const bool lpcfg_client_ntlmv2_auth(struct loadparm_context *x)
{
    return (smbcfg.CliLMLevel & CLI_LMFLAG_USE_AUTH_NTLMv2);
}

/* gensec_start.c */
bool gensec_setting_bool(struct gensec_settings *settings, const char *mechanism, const char *name, bool default_value)
{
    if (strcasecmp(mechanism, "ntlmssp_server") == 0)
    {
        if (strcasecmp(name, "allow_lm_key") == 0)
            return (smbcfg.SvrLMLevel & SVR_LMFLAG_ACCPT_AUTH_LM);
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
            return (smbcfg.SvrLMLevel & SVR_LMFLAG_ACCPT_AUTH_LM);
        else if (strcasecmp(name, "lm_key") == 0)
            return (smbcfg.CliLMLevel & CLI_LMFLAG_USE_AUTH_LM);
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
            return (smbcfg.CliLMLevel & CLI_LMFLAG_USE_SSEC_NTLMv2);
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
    if (gs == NULL)
    {
        gs = talloc_zero(NULL, struct gensec_settings);
        gs->lp_ctx = talloc_zero(NULL, struct loadparm_context);

        gs->target_hostname = "targethost";
        gs->backends = NULL;
        gs->server_dns_domain = NULL;
        gs->server_dns_name = NULL;
        gs->server_netbios_domain = NULL;
        gs->server_netbios_name = NULL;
    }

    return gs;
}

void NtlmInitializeSamba()
{
    gs = NULL;

    /* maybe read from registry ... */
    /*  NTLMV1 works */
    /*  NTLMV2 not fully working (AUTH_MESSAGE receives INVALID_PARAMETER :-( ) */
    /* FIXME value is stored in registry ... so get it from there! */
    smbcfg.LMCompatibilityLevel = 2;// partly unimplemented
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

    switch (smbcfg.LMCompatibilityLevel)
    {
        case 0 :
        {
            smbcfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_LM |
                                CLI_LMFLAG_USE_AUTH_NTLMv1;
            smbcfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 1 :
        {
            smbcfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_LM |
                                CLI_LMFLAG_USE_AUTH_NTLMv1 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            smbcfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 2:
        default:
        {
            smbcfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv1 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            smbcfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 3 :
        {
            smbcfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv2 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            smbcfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 4 :
        {
            smbcfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv2 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            smbcfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
        case 5 :
        {
            smbcfg.CliLMLevel = CLI_LMFLAG_USE_AUTH_NTLMv2 |
                                CLI_LMFLAG_USE_SSEC_NTLMv2;
            smbcfg.SvrLMLevel = SVR_LMFLAG_ACCPT_AUTH_LM |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv1 |
                                SVR_LMFLAG_ACCPT_AUTH_NTLMv2;
            break;
        }
    }
}

void NtlmFinalizeSamba()
{
    if (gs)
    {
        talloc_free(gs->lp_ctx);
        talloc_free(gs);
        gs = NULL;
    }
}

