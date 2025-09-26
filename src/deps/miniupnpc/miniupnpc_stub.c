#include "miniupnpc/miniupnpc.h"
#include "miniupnpc/upnpcommands.h"
#include "miniupnpc/upnperrors.h"
#include <stdlib.h>

struct UPNPDev {
  int dummy;
};

struct UPNPDev *upnpDiscover(int delay, const char *multicastif,
                             const char *minissdpdpath, int sameport, int ipv6,
                             int *error, int ttl) {
  (void)delay;
  (void)multicastif;
  (void)minissdpdpath;
  (void)sameport;
  (void)ipv6;
  (void)ttl;
  if (error)
    *error = -1;
  return NULL;
}

void freeUPNPDevlist(struct UPNPDev *devlist) { (void)devlist; }

void FreeUPNPUrls(struct UPNPUrls *urls) { (void)urls; }

int UPNP_GetValidIGD(struct UPNPDev *devlist, struct UPNPUrls *urls,
                     struct IGDdatas *data, char *lanaddr, int lanaddrlen) {
  (void)devlist;
  (void)urls;
  (void)data;
  (void)lanaddr;
  (void)lanaddrlen;
  return 0;
}

int UPNP_AddPortMapping(const char *controlURL, const char *servicetype,
                        const char *extPort, const char *inPort,
                        const char *inClient, const char *desc,
                        const char *proto, const char *remoteHost,
                        const char *leaseDuration) {
  (void)controlURL;
  (void)servicetype;
  (void)extPort;
  (void)inPort;
  (void)inClient;
  (void)desc;
  (void)proto;
  (void)remoteHost;
  (void)leaseDuration;
  return -1;
}

int UPNP_GetExternalIPAddress(const char *controlURL,
                              const char *servicetype, char *extIpAdd
#if defined(MINIUPNPC_API_VERSION) && (MINIUPNPC_API_VERSION >= 18)
                              , int *status
#endif
) {
  (void)controlURL;
  (void)servicetype;
  if (extIpAdd)
    extIpAdd[0] = '\0';
#if defined(MINIUPNPC_API_VERSION) && (MINIUPNPC_API_VERSION >= 18)
  if (status)
    *status = 0;
#endif
  return -1;
}

const char *strupnperror(int err) {
  (void)err;
  return "miniupnpc stub";
}
