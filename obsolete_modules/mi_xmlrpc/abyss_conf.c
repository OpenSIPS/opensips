/******************************************************************************
** conf.c
**
** This file is part of the ABYSS Web server project.
**
** Copyright (C) 2000 by Moez Mahfoudh <mmoez@bigfoot.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
**
******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(WIN32) && !defined(__BORLANDC__)
#include <direct.h>
#endif

#ifdef _UNIX
#include <pwd.h>
#endif

#include <xmlrpc-c/config.h>
#include "abyss_xmlrpc_int.h"
#include <xmlrpc-c/abyss.h>
#include "abyss_trace.h"
#include "abyss_server.h"
#include "abyss_http.h"

/*********************************************************************
** Configuration Files Parsing Functions
*********************************************************************/



static abyss_bool
ConfReadLine(TFile *f,char *buffer,uint32_t len) {
    abyss_bool r=TRUE;
    char c,*p,*z=buffer;

    while ((--len)>0)
    {
        if (FileRead(f,buffer,1)<1)
        {
            if (z==buffer)
                r=FALSE;
            break;
        };

        if ((*buffer==CR) || (*buffer==LF) )
            break;

        buffer++;
    };

    if (len==0)
        while (FileRead(f,&c,1)==1)
            if ((c==CR) || (c==LF))
                break;

    *buffer='\0';

    /* Discard comments */
    p=strchr(z,'#');
    if (p)
        *p='\0';

    return r;
}

static abyss_bool
ConfNextToken(char **p) {
    while (1)
        switch (**p)
        {
        case '\t':
        case ' ':
            (*p)++;
            break;
        case '\0':
            return FALSE;
        default:
            return TRUE;
        };
}

static char *
ConfGetToken(char **p) {
    char *p0=*p;

    while (1)
        switch (**p)
        {
        case '\t':
        case ' ':
        case CR:
        case LF:
        case '\0':
            if (p0==*p)
                return NULL;

            if (**p)
            {
                **p='\0';
                (*p)++;
            };
            return p0;

        default:
            (*p)++;
        };
}

static abyss_bool
ConfReadInt(const char * const p,
            int32_t *    const n,
            int32_t      const min,
            int32_t      const max) {
/*----------------------------------------------------------------------------
   Convert string 'p' to integer *n.

   If it isn't a valid integer or is not with the bounds [min, max],
   return FALSE.  Otherwise, return TRUE.
-----------------------------------------------------------------------------*/
    char * e;

    *n = strtol(p, &e, 10);

    if (min != max)
        return ((e != p) && (*n >= min) && (*n <= max));
    else
        return (e != p);
}



static abyss_bool
ConfReadBool(char *p, abyss_bool *b) {
    if (strcasecmp(p,"yes")==0)
    {
        *b=TRUE;
        return TRUE;
    };

    if (strcasecmp(p,"no")==0)
    {
        *b=FALSE;
        return TRUE;
    };

    return FALSE;
}

/*********************************************************************
** MIME Types File
*********************************************************************/

static void
readMIMETypesFile(const char * const filename,
                  MIMEType **  const MIMETypePP) {

    abyss_bool success;
    MIMEType * MIMETypeP;

    MIMETypeP = MIMETypeCreate();
    if (MIMETypeP) {
        TFile file;
        abyss_bool fileOpened;

        fileOpened = FileOpen(&file, filename, O_RDONLY);
        if (fileOpened) {
            char z[512];
            while (ConfReadLine(&file, z, 512)) {
                char * p;
                p = &z[0];

                if (ConfNextToken(&p)) {
                    const char * mimetype = ConfGetToken(&p);
                    if (mimetype) {
                        while (ConfNextToken(&p)) {
                            const char * const ext = ConfGetToken(&p);
                            if (ext)
                                MIMETypeAdd2(MIMETypeP, mimetype, ext);
                            else
                                break;
                        }
                    }
                }
            }
            FileClose(&file);
            success = TRUE;
        } else
            success = FALSE;
        if (!success)
            MIMETypeDestroy(MIMETypeP);
    } else
        success = FALSE;

    if (success)
        *MIMETypePP = MIMETypeP;
    else
        *MIMETypePP = NULL;
}

/*********************************************************************
** Server Configuration File
*********************************************************************/

static void
chdirx(const char * const newdir,
       abyss_bool * const successP) {

#if defined(WIN32) && !defined(__BORLANDC__)
    *successP = _chdir(newdir) == 0;
#else
    *successP = chdir(newdir) == 0;
#endif
}



static void
parseUser(const char *      const p,
          struct _TServer * const srvP) {
#ifdef _UNIX
    if (p[0] == '#') {
        int32_t n;

        if (!ConfReadInt(&p[1], &n, 0, 0))
            TraceExit("Bad user number '%s'", p);
        else
            srvP->uid = n;
    } else {
        struct passwd * pwd;

        if (!(pwd = getpwnam(p)))
            TraceExit("Unknown user '%s'", p);

        srvP->uid = pwd->pw_uid;
        if ((int)srvP->gid==(-1))
            srvP->gid = pwd->pw_gid;
    };
#else
    TraceMsg("User option ignored");
#endif  /* _UNIX */
}



static void
parsePidfile(const char *      const p,
             struct _TServer * const srvP) {
#ifdef _UNIX
    if (!FileOpenCreate(&srvP->pidfile, p, O_TRUNC | O_WRONLY)) {
        srvP->pidfile = -1;
        TraceMsg("Bad PidFile value '%s'", p);
    };
#else
    TraceMsg("PidFile option ignored");
#endif  /* _UNIX */
}



abyss_bool
ConfReadServerFile(const char * const filename,
                   TServer *    const serverP) {

    struct _TServer * const srvP = serverP->srvP;

    TFile f;
    char z[512];
    char * p;
    unsigned int lineNum;
    TFileStat fs;

    if (!FileOpen(&f, filename, O_RDONLY))
        return FALSE;

    lineNum = 0;

    while (ConfReadLine(&f, z, 512)) {
        ++lineNum;
        p = z;

        if (ConfNextToken(&p)) {
            const char * const option = ConfGetToken(&p);
            if (option) {
                ConfNextToken(&p);

                if (strcasecmp(option, "port") == 0) {
                    int32_t n;
                    if (ConfReadInt(p, &n, 1, 65535))
                        srvP->port = n;
                    else
                        TraceExit("Invalid port '%s'", p);
                } else if (strcasecmp(option, "serverroot") == 0) {
                    abyss_bool success;
                    chdirx(p, &success);
                    if (!success)
                        TraceExit("Invalid server root '%s'",p);
                } else if (strcasecmp(option, "path") == 0) {
                    if (FileStat(p, &fs))
                        if (fs.st_mode & S_IFDIR) {
                            xmlrpc_strfree(srvP->filespath);
                            srvP->filespath = strdup(p);
                            continue;
                        }
                    TraceExit("Invalid path '%s'", p);
                } else if (strcasecmp(option, "default") == 0) {
                    const char * filename;

                    while ((filename = ConfGetToken(&p))) {
                        ListAdd(&srvP->defaultfilenames, strdup(filename));
                        if (!ConfNextToken(&p))
                            break;
                    }
                } else if (strcasecmp(option, "keepalive") == 0) {
                    int32_t n;
                    if (ConfReadInt(p, &n, 1, 65535))
                        srvP->keepalivemaxconn = n;
                    else
                        TraceExit("Invalid KeepAlive value '%s'", p);
                } else if (strcasecmp(option, "timeout") == 0) {
                    int32_t n;
                    if (ConfReadInt(p, &n, 1, 3600)) {
                        srvP->keepalivetimeout = n;
                        /* Must see what to do with that */
                        srvP->timeout = n;
                    } else
                        TraceExit("Invalid TimeOut value '%s'", p);
                } else if (strcasecmp(option, "mimetypes") == 0) {
                    readMIMETypesFile(p, &srvP->mimeTypeP);
                    if (!srvP->mimeTypeP)
                        TraceExit("Can't read MIME Types file '%s'", p);
                } else if (strcasecmp(option,"logfile") == 0) {
                    srvP->logfilename = strdup(p);
                } else if (strcasecmp(option,"user") == 0) {
                    parseUser(p, srvP);
                } else if (strcasecmp(option, "pidfile")==0) {
                    parsePidfile(p, srvP);
                } else if (strcasecmp(option, "advertiseserver") == 0) {
                    if (!ConfReadBool(p, &srvP->advertise))
                        TraceExit("Invalid boolean value "
                                  "for AdvertiseServer option");
                } else
                    TraceExit("Invalid option '%s' at line %u",
                              option, lineNum);
            }
        }
    }

    FileClose(&f);
    return TRUE;
}
