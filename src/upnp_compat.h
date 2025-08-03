#ifndef ALYNCOIN_UPNP_COMPAT_H
#define ALYNCOIN_UPNP_COMPAT_H

// Request legacy function names from miniupnpc so our existing
// code continues to link against Ubuntu's 2.x library.
#define MINIUPNPC_SET_OLDNAMES
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#endif // ALYNCOIN_UPNP_COMPAT_H
