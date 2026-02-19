#ifndef UPNP_H
#define UPNP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Discover UPnP IGD, request an external port mapping for the given TCP port,
   and write the router's external IP into out_ip (NUL-terminated).
   Returns 0 on success, -1 if UPnP is unavailable or the mapping failed.
   Blocks for up to ~2 s during SSDP discovery. */
int  upnp_setup(int port, char *out_ip, int out_ip_len);

/* Remove the port mapping created by upnp_setup. No-op if never succeeded. */
void upnp_cleanup(int port);

#ifdef __cplusplus
}
#endif

#endif /* UPNP_H */
