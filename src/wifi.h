#ifndef _WIFI_H_
#define _WIFI_H_

#include <stdint.h>

int wifi_init(void);
int lan_start(void);
int lan_stop(void);
int wan_start(void);
int wan_stop(void);

struct net_if *lan_get_iface(void);
struct net_if *wan_get_iface(void);

const char *mac_str(const uint8_t *mac);

#endif
