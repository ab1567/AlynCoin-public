#ifndef MINIUPNPC_MINIUPNPC_H
#define MINIUPNPC_MINIUPNPC_H

#ifdef __cplusplus
extern "C" {
#endif

struct UPNPDev;

struct UPNPUrls {
  char *controlURL;
};

struct IGDdatas {
  struct {
    char *servicetype;
  } first;
};

struct UPNPDev *upnpDiscover(int delay, const char *multicastif,
                             const char *minissdpdpath, int sameport, int ipv6,
                             int *error, int ttl);
void freeUPNPDevlist(struct UPNPDev *devlist);
void FreeUPNPUrls(struct UPNPUrls *urls);

#ifdef __cplusplus
}
#endif

#endif /* MINIUPNPC_MINIUPNPC_H */
