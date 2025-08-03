#ifndef MINIUPNPC_UPNPCOMMANDS_H
#define MINIUPNPC_UPNPCOMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "miniupnpc.h"

#define UPNPCOMMAND_SUCCESS 0

int UPNP_GetValidIGD(struct UPNPDev *devlist, struct UPNPUrls *urls,
                     struct IGDdatas *data, char *lanaddr, int lanaddrlen);
int UPNP_AddPortMapping(const char *controlURL, const char *servicetype,
                        const char *extPort, const char *inPort,
                        const char *inClient, const char *desc,
                        const char *proto, const char *remoteHost,
                        const char *leaseDuration);

#ifdef __cplusplus
}
#endif

#endif /* MINIUPNPC_UPNPCOMMANDS_H */
