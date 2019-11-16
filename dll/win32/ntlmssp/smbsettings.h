#ifndef _SMBSETTINGS_H_
#define _SMBSETTINGS_H_

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
};

struct rosconfig* smbGetROSConfig();

#endif
