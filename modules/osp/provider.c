/*
 * opensips osp module.
 *
 * This module enables opensips to communicate with an Open Settlement
 * Protocol (OSP) server.  The Open Settlement Protocol is an ETSI
 * defined standard for Inter-Domain VoIP pricing, authorization
 * and usage exchange.  The technical specifications for OSP
 * (ETSI TS 101 321 V4.1.1) are available at www.etsi.org.
 *
 * Uli Abend was the original contributor to this module.
 *
 * Copyright (C) 2001-2005 Fhg Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <osp/osp.h>
#include <osp/osputils.h>
#include <osp/ospb64.h>
#include "../../dprint.h"
#include "osp_mod.h"
#include "provider.h"

extern unsigned int _osp_sp_number;
extern char* _osp_sp_uris[];
extern unsigned long _osp_sp_weights[];
extern int _osp_use_security;
extern char* _osp_private_key;
extern char* _osp_local_certificate;
extern char* _osp_ca_certificate;
extern int _osp_ssl_lifetime;
extern int _osp_persistence;
extern int _osp_retry_delay;
extern int _osp_retry_limit;
extern int _osp_timeout;
extern int _osp_crypto_hw;
extern OSPTPROVHANDLE _osp_provider;

const char* B64PKey = "MIIBOgIBAAJBAK8t5l+PUbTC4lvwlNxV5lpl+2dwSZGW46dowTe6y133XyVEwNiiRma2YNk3xKs/TJ3Wl9Wpns2SYEAJsFfSTukCAwEAAQJAPz13vCm2GmZ8Zyp74usTxLCqSJZNyMRLHQWBM0g44Iuy4wE3vpi7Wq+xYuSOH2mu4OddnxswCP4QhaXVQavTAQIhAOBVCKXtppEw9UaOBL4vW0Ed/6EA/1D8hDW6St0h7EXJAiEAx+iRmZKhJD6VT84dtX5ZYNVk3j3dAcIOovpzUj9a0CECIEduTCapmZQ5xqAEsLXuVlxRtQgLTUD4ZxDElPn8x0MhAiBE2HlcND0+qDbvtwJQQOUzDgqg5xk3w8capboVdzAlQQIhAMC+lDL7+gDYkNAft5Mu+NObJmQs4Cr+DkDFsKqoxqrm";
const char* B64LCert = "MIIBeTCCASMCEHqkOHVRRWr+1COq3CR/xsowDQYJKoZIhvcNAQEEBQAwOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMB4XDTA1MDYyMzAwMjkxOFoXDTA2MDYyNDAwMjkxOFowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvLeZfj1G0wuJb8JTcVeZaZftncEmRluOnaME3ustd918lRMDYokZmtmDZN8SrP0yd1pfVqZ7NkmBACbBX0k7pAgMBAAEwDQYJKoZIhvcNAQEEBQADQQDnV8QNFVVJx/+7IselU0wsepqMurivXZzuxOmTEmTVDzCJx1xhA8jd3vGAj7XDIYiPub1PV23eY5a2ARJuw5w9";
const char* B64CACert = "MIIBYDCCAQoCAQEwDQYJKoZIhvcNAQEEBQAwOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMB4XDTAyMDIwNDE4MjU1MloXDTEyMDIwMzE4MjU1MlowOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPGeGwV41EIhX0jEDFLRXQhDEr50OUQPq+f55VwQd0TQNts06BP29+UiNdRW3c3IRHdZcJdC1Cg68ME9cgeq0h8CAwEAATANBgkqhkiG9w0BAQQFAANBAGkzBSj1EnnmUxbaiG1N4xjIuLAWydun7o3bFk2tV8dBIhnuh445obYyk1EnQ27kI7eACCILBZqi2MHDOIMnoN0=";

/*
 * Create a new OSP provider object per process
 * return 0 success, others failure
 */
int ospSetupProvider(void)
{
    OSPTPRIVATEKEY privatekey = { NULL, 0 };
    OSPT_CERT localcert = { NULL, 0 };
    OSPT_CERT cacert = { NULL, 0 };
    OSPT_CERT* cacerts[1];
    unsigned char privatekeydata[OSP_KEYBUF_SIZE];
    unsigned char localcertdata[OSP_KEYBUF_SIZE];
    unsigned char cacertdata[OSP_KEYBUF_SIZE];
    int errorcode, result = -1;

    cacerts[0] = &cacert;

    if ((errorcode = OSPPInit(_osp_crypto_hw)) != OSPC_ERR_NO_ERROR) {
        LM_ERR("failed to initalize OSP (%d)\n", errorcode);
    } else {
        if (_osp_use_security == 0) {
            privatekey.PrivateKeyData = privatekeydata;
            privatekey.PrivateKeyLength = sizeof(privatekeydata);

            localcert.CertData = localcertdata;
            localcert.CertDataLength = sizeof(localcertdata);

            cacert.CertData = cacertdata;
            cacert.CertDataLength = sizeof(cacertdata);

            if ((errorcode = OSPPBase64Decode(B64PKey, strlen(B64PKey), privatekey.PrivateKeyData, &privatekey.PrivateKeyLength)) != OSPC_ERR_NO_ERROR) {
                LM_ERR("failed to decode private key (%d)\n", errorcode);
            } else if ((errorcode = OSPPBase64Decode(B64LCert, strlen(B64LCert), localcert.CertData, &localcert.CertDataLength)) != OSPC_ERR_NO_ERROR) {
                LM_ERR("failed to decode local cert (%d)\n", errorcode);
            } else if ((errorcode = OSPPBase64Decode(B64CACert, strlen(B64CACert), cacert.CertData, &cacert.CertDataLength)) != OSPC_ERR_NO_ERROR) {
                LM_ERR("failed to decode cacert (%d)\n", errorcode);
            }
        } else {
            if ((errorcode = OSPPUtilLoadPEMPrivateKey((unsigned char*)_osp_private_key, &privatekey)) != OSPC_ERR_NO_ERROR) {
                LM_ERR("failed to load private key (%d) from '%s'\n", errorcode, _osp_private_key);
            } else if ((errorcode = OSPPUtilLoadPEMCert((unsigned char*)_osp_local_certificate, &localcert)) != OSPC_ERR_NO_ERROR) {
                LM_ERR("failed to load local certificate (%d) from '%s'\n", errorcode, _osp_local_certificate);
            } else if ((errorcode = OSPPUtilLoadPEMCert((unsigned char*)_osp_ca_certificate, &cacert)) != OSPC_ERR_NO_ERROR) {
                LM_ERR("failed to load CA certificate (%d) from '%s'\n", errorcode, _osp_ca_certificate);
            }
        }

        if (errorcode == OSPC_ERR_NO_ERROR) {
            errorcode = OSPPProviderNew(
                _osp_sp_number,
                (const char**)_osp_sp_uris,
                _osp_sp_weights,
                "http://localhost:1234",
                &privatekey,
                &localcert,
                1,
                (const OSPT_CERT**)cacerts,
                1,
                _osp_ssl_lifetime,
                _osp_sp_number,
                _osp_persistence,
                _osp_retry_delay,
                _osp_retry_limit,
                _osp_timeout,
                "",
                "",
                &_osp_provider);
            if (errorcode != OSPC_ERR_NO_ERROR) {
                LM_ERR("failed to create provider (%d)\n", errorcode);
            } else {
                LM_DBG("created new (per process) provider '%d'\n", _osp_provider);
                result = 0;
            }
        }

        /*
         * Free space allocated while loading crypto information from PEM-encoded files.
         * There are some problems to free the memory, do not free them
         */
#if 0
        if (_osp_use_security != 0) {
            if (privatekey.PrivateKeyData != NULL) {
                free(privatekey.PrivateKeyData);
            }

            if (localcert.CertData != NULL) {
                free(localcert.CertData);
            }

            if (cacert.CertData != NULL) {
                free(localcert.CertData);
            }
        }
#endif
    }

    return result;
}

/*
 * Erase OSP provider object
 * return 0 success, others failure
 */
int ospDeleteProvider(void)
{
    int errorcode;

    if ((errorcode = OSPPProviderDelete(_osp_provider, 0)) != OSPC_ERR_NO_ERROR) {
        LM_ERR("failed to erase provider '%d' (%d)\n", _osp_provider, errorcode);
    }

    return errorcode;
}

