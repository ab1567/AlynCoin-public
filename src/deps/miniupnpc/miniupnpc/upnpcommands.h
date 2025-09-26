#ifndef MINIUPNPC_UPNPCOMMANDS_H
#define MINIUPNPC_UPNPCOMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "miniupnpc.h"

#define UPNPCOMMAND_SUCCESS 0

#ifndef MINIUPNPC_API_VERSION
#define MINIUPNPC_API_VERSION 0
#endif

int UPNP_GetValidIGD(struct UPNPDev *devlist, struct UPNPUrls *urls,
                     struct IGDdatas *data, char *lanaddr, int lanaddrlen);
int UPNP_AddPortMapping(const char *controlURL, const char *servicetype,
                        const char *extPort, const char *inPort,
                        const char *inClient, const char *desc,
                        const char *proto, const char *remoteHost,
                        const char *leaseDuration);
#if MINIUPNPC_API_VERSION >= 18
int UPNP_GetExternalIPAddress(const char *controlURL,
                              const char *servicetype, char *extIpAdd,
                              int *status);
#else
int UPNP_GetExternalIPAddress(const char *controlURL,
                              const char *servicetype, char *extIpAdd);
#endif
const char *strupnperror(int err);

#ifdef __cplusplus
}
#endif

#endif /* MINIUPNPC_UPNPCOMMANDS_H */
