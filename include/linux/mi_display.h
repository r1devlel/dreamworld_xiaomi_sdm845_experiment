#ifndef _LINUX_MI_DISPLAY_H
#define _LINUX_MI_DISPLAY_H

#include <linux/types.h>

bool mi_display_is_aod_enabled(void);
void dsi_display_enter_aod(void);
void dsi_display_exit_aod(void);

#endif /* _LINUX_MI_DISPLAY_H */
