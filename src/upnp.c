/*
 * Minimal UPnP IGD port-mapping client.
 *
 * Flow:
 *   1. SSDP M-SEARCH (UDP multicast) → find router LOCATION URL
 *   2. HTTP GET LOCATION → parse XML for WANIPConnection controlURL
 *   3. SOAP GetExternalIPAddress → learn our public IP
 *   4. SOAP AddPortMapping  → open external TCP port
 *   5. SOAP DeletePortMapping (on cleanup)
 *
 * No external dependencies; standard POSIX sockets only.
 */

#include "compat.h"
#include "upnp.h"

/* ---- Persistent state written by upnp_setup, read by upnp_cleanup ---- */
static char g_ctrl_url[512];
static char g_service_type[128];

/* ---- URL parser ---- */

static int parse_url(const char *url,
                     char *host, int hlen,
                     int  *port,
                     char *path, int plen)
{
    *port = 80;
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;

    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');
    if (!slash) return -1;

    if (colon && colon < slash) {
        int n = (int)(colon - p);
        if (n >= hlen) return -1;
        memcpy(host, p, (size_t)n);
        host[n] = '\0';
        *port = atoi(colon + 1);
    } else {
        int n = (int)(slash - p);
        if (n >= hlen) return -1;
        memcpy(host, p, (size_t)n);
        host[n] = '\0';
    }
    strncpy(path, slash, (size_t)(plen - 1));
    path[plen - 1] = '\0';
    return 0;
}

/* ---- Minimal TCP client ---- */

static int tcp_connect(const char *host, int port)
{
    char svc[16];
    snprintf(svc, sizeof(svc), "%d", port);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, svc, &hints, &res) != 0) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    dcomms_set_socktimeo(fd, SO_RCVTIMEO, 3);
    dcomms_set_socktimeo(fd, SO_SNDTIMEO, 3);

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        sock_close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* HTTP GET; strips headers, returns body in buf. */
static int http_get(const char *host, int port, const char *path,
                    char *buf, int buflen)
{
    int fd = tcp_connect(host, port);
    if (fd < 0) return -1;

    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
             path, host, port);
    if (sock_send(fd, req, strlen(req)) <= 0) { sock_close(fd); return -1; }

    int total = 0;
    ssize_t n;
    char tmp[1024];
    while ((n = sock_recv(fd, tmp, sizeof(tmp))) > 0) {
        if (total + (int)n < buflen - 1) {
            memcpy(buf + total, tmp, (size_t)n);
            total += (int)n;
        }
    }
    buf[total] = '\0';
    sock_close(fd);

    char *body = strstr(buf, "\r\n\r\n");
    if (body) { body += 4; memmove(buf, body, strlen(body) + 1); }
    return 0;
}

/* HTTP POST SOAP; strips headers, returns body in resp. */
static int soap_post(const char *host, int port, const char *path,
                     const char *service_type, const char *action,
                     const char *soap_body,
                     char *resp, int resplen)
{
    char envelope[4096];
    int env_len = snprintf(envelope, sizeof(envelope),
        "<?xml version=\"1.0\"?>"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
        " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>%s</s:Body></s:Envelope>",
        soap_body);

    char action_hdr[256];
    snprintf(action_hdr, sizeof(action_hdr), "\"%s#%s\"", service_type, action);

    int fd = tcp_connect(host, port);
    if (fd < 0) return -1;

    char req[8192];
    int req_len = snprintf(req, sizeof(req),
        "POST %s HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        "SOAPAction: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        path, host, port, action_hdr, env_len, envelope);
    if (sock_send(fd, req, (size_t)req_len) <= 0) { sock_close(fd); return -1; }

    int total = 0;
    ssize_t n;
    char tmp[1024];
    while ((n = sock_recv(fd, tmp, sizeof(tmp))) > 0) {
        if (total + (int)n < resplen - 1) {
            memcpy(resp + total, tmp, (size_t)n);
            total += (int)n;
        }
    }
    resp[total] = '\0';
    sock_close(fd);

    char *body = strstr(resp, "\r\n\r\n");
    if (body) { body += 4; memmove(resp, body, strlen(body) + 1); }
    return 0;
}

/* ---- Minimal XML helper ---- */

/* Find <tag>text</tag> and copy text into out. */
static int xml_get(const char *xml, const char *tag, char *out, int olen)
{
    char open[128], close[128];
    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *s = strstr(xml, open);
    if (!s) return -1;
    s += strlen(open);
    const char *e = strstr(s, close);
    if (!e) return -1;
    int len = (int)(e - s);
    if (len >= olen) len = olen - 1;
    memcpy(out, s, (size_t)len);
    out[len] = '\0';
    return 0;
}

/* ---- Determine local IP toward a given host ---- */

static void get_local_ip(const char *gateway, char *out, int olen)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { strncpy(out, "127.0.0.1", (size_t)olen); return; }

    struct sockaddr_in gw;
    memset(&gw, 0, sizeof(gw));
    gw.sin_family = AF_INET;
    inet_pton(AF_INET, gateway, &gw.sin_addr);
    gw.sin_port = htons(1900);
    connect(fd, (struct sockaddr *)&gw, sizeof(gw));

    struct sockaddr_in local;
    socklen_t llen = sizeof(local);
    getsockname(fd, (struct sockaddr *)&local, &llen);
    sock_close(fd);
    inet_ntop(AF_INET, &local.sin_addr, out, (socklen_t)olen);
}

/* ---- SSDP discovery ---- */

/* Walk <service>...</service> blocks in xml; return controlURL and
   serviceType for the first WANIPConnection or WANPPPConnection found. */
static int find_wan_service(const char *xml,
                            const char *base_host, int base_port,
                            char *ctrl_url, int curl_len,
                            char *svc_type, int st_len)
{
    const char *p = xml;
    while ((p = strstr(p, "<service>")) != NULL) {
        const char *end = strstr(p, "</service>");
        if (!end) break;

        int blen = (int)(end - p) + (int)strlen("</service>");
        char block[2048];
        if (blen >= (int)sizeof(block)) { p++; continue; }
        memcpy(block, p, (size_t)blen);
        block[blen] = '\0';

        char st[128], cpath[256];
        if (xml_get(block, "serviceType", st, sizeof(st)) != 0) { p++; continue; }
        if (!strstr(st, "WANIPConnection") && !strstr(st, "WANPPPConnection")) { p++; continue; }
        if (xml_get(block, "controlURL", cpath, sizeof(cpath)) != 0) { p++; continue; }

        /* Build absolute control URL */
        if (cpath[0] == '/') {
            snprintf(ctrl_url, (size_t)curl_len, "http://%s:%d%s",
                     base_host, base_port, cpath);
        } else {
            snprintf(ctrl_url, (size_t)curl_len, "http://%s:%d/%s",
                     base_host, base_port, cpath);
        }
        strncpy(svc_type, st, (size_t)(st_len - 1));
        svc_type[st_len - 1] = '\0';
        return 0;
    }
    return -1;
}

static int ssdp_discover(char *ctrl_url, int curl_len,
                         char *svc_type,  int st_len)
{
    /* Search targets in priority order */
    static const char *targets[] = {
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        NULL
    };

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) return -1;

    dcomms_set_socktimeo(sfd, SO_RCVTIMEO, 2);

    /* On macOS, multicast routing is independent of the default route and
       defaults to lo0 without an explicit interface.  Set IP_MULTICAST_IF
       to the interface that actually faces the LAN so the M-SEARCH reaches
       the router rather than looping back.
       Important: use a unicast address for the interface lookup — using the
       multicast address itself would follow the multicast routing table,
       which on macOS also points to lo0, defeating the purpose. */
    char local_ip[64];
    get_local_ip("8.8.8.8", local_ip, sizeof(local_ip));
    struct in_addr iface;
    if (inet_pton(AF_INET, local_ip, &iface) == 1 &&
            iface.s_addr != htonl(INADDR_LOOPBACK))
        setsockopt(sfd, IPPROTO_IP, IP_MULTICAST_IF,
                   SOCKOPT_VAL(&iface), sizeof(iface));

    struct sockaddr_in mcast;
    memset(&mcast, 0, sizeof(mcast));
    mcast.sin_family = AF_INET;
    inet_pton(AF_INET, "239.255.255.250", &mcast.sin_addr);
    mcast.sin_port = htons(1900);

    char location[512] = "";

    for (int t = 0; targets[t] && location[0] == '\0'; t++) {
        char msg[512];
        int mlen = snprintf(msg, sizeof(msg),
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: %s\r\n"
            "\r\n",
            targets[t]);
        sendto(sfd, (const char *)msg, (size_t)mlen, 0,
               (struct sockaddr *)&mcast, sizeof(mcast));

        for (int r = 0; r < 4; r++) {
            char buf[2048];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(sfd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&from, &flen);
            if (n <= 0) break;
            buf[n] = '\0';

            char *loc = strcasestr(buf, "LOCATION:");
            if (!loc) continue;
            loc += 9;
            while (*loc == ' ') loc++;
            char *eol = loc;
            while (*eol && *eol != '\r' && *eol != '\n') eol++;
            int llen = (int)(eol - loc);
            if (llen <= 0 || llen >= (int)sizeof(location) - 1) continue;
            memcpy(location, loc, (size_t)llen);
            location[llen] = '\0';
            break;
        }
    }
    sock_close(sfd);

    if (location[0] == '\0') return -1;

    /* Fetch and parse the IGD XML description */
    char host[128]; int port; char path[256];
    if (parse_url(location, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return -1;

    char desc[8192];
    if (http_get(host, port, path, desc, sizeof(desc)) != 0) return -1;

    return find_wan_service(desc, host, port, ctrl_url, curl_len, svc_type, st_len);
}

/* ---- Public API ---- */

int upnp_setup(int port, char *out_ip, int out_ip_len)
{
    g_ctrl_url[0]    = '\0';
    g_service_type[0] = '\0';

    char svc_type[128];
    if (ssdp_discover(g_ctrl_url, sizeof(g_ctrl_url),
                      svc_type,   sizeof(svc_type)) != 0)
        return -1;
    strncpy(g_service_type, svc_type, sizeof(g_service_type) - 1);

    char ctrl_host[128]; int ctrl_port; char ctrl_path[256];
    if (parse_url(g_ctrl_url, ctrl_host, sizeof(ctrl_host),
                  &ctrl_port, ctrl_path, sizeof(ctrl_path)) != 0)
        return -1;

    /* Get external IP */
    char ip_body[256];
    snprintf(ip_body, sizeof(ip_body),
             "<u:GetExternalIPAddress xmlns:u=\"%s\"/>", g_service_type);

    char resp[4096];
    if (soap_post(ctrl_host, ctrl_port, ctrl_path,
                  g_service_type, "GetExternalIPAddress",
                  ip_body, resp, sizeof(resp)) != 0)
        return -1;

    char ext_ip[64] = "";
    if (xml_get(resp, "NewExternalIPAddress", ext_ip, sizeof(ext_ip)) != 0
            || ext_ip[0] == '\0')
        return -1;

    /* Get local IP toward the router */
    char local_ip[64];
    get_local_ip(ctrl_host, local_ip, sizeof(local_ip));

    /* Add port mapping */
    char map_body[1024];
    snprintf(map_body, sizeof(map_body),
        "<u:AddPortMapping xmlns:u=\"%s\">"
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "<NewInternalPort>%d</NewInternalPort>"
        "<NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>dcomms</NewPortMappingDescription>"
        "<NewLeaseDuration>3600</NewLeaseDuration>"
        "</u:AddPortMapping>",
        g_service_type, port, port, local_ip);

    if (soap_post(ctrl_host, ctrl_port, ctrl_path,
                  g_service_type, "AddPortMapping",
                  map_body, resp, sizeof(resp)) != 0)
        return -1;

    /* A SOAP fault means the mapping was refused */
    if (strstr(resp, "errorCode") || strstr(resp, ":Fault")) {
        g_ctrl_url[0] = '\0';
        return -1;
    }

    strncpy(out_ip, ext_ip, (size_t)(out_ip_len - 1));
    out_ip[out_ip_len - 1] = '\0';
    return 0;
}

void upnp_cleanup(int port)
{
    if (g_ctrl_url[0] == '\0' || port <= 0) return;

    char ctrl_host[128]; int ctrl_port; char ctrl_path[256];
    if (parse_url(g_ctrl_url, ctrl_host, sizeof(ctrl_host),
                  &ctrl_port, ctrl_path, sizeof(ctrl_path)) != 0)
        return;

    char del_body[512];
    snprintf(del_body, sizeof(del_body),
        "<u:DeletePortMapping xmlns:u=\"%s\">"
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "</u:DeletePortMapping>",
        g_service_type, port);

    char resp[1024];
    soap_post(ctrl_host, ctrl_port, ctrl_path,
              g_service_type, "DeletePortMapping",
              del_body, resp, sizeof(resp));

    g_ctrl_url[0] = '\0';
}
