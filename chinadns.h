#ifndef CHINADNS_NG_CHINADNS_H
#define CHINADNS_NG_CHINADNS_H

#define _GNU_SOURCE
#include <stdbool.h>
#undef _GNU_SOURCE

/* nftables setname max len */
#define SET_MAXNAMELEN 32 /* including '\0' */

/* global variable declaration */
extern bool g_noip_as_chnip; /* used by dnsutils.h */
extern char g_set_setname4[SET_MAXNAMELEN]; /* used by netutils.h */
extern char g_set_setname6[SET_MAXNAMELEN]; /* used by netutils.h */

#endif
