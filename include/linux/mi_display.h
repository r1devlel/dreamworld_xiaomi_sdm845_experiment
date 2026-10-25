#ifndef _LINUX_MI_DISPLAY_H
#define _LINUX_MI_DISPLAY_H

#include <linux/types.h>

bool mi_display_is_aod_enabled(void);
void dsi_display_enter_aod(void);
void dsi_display_exit_aod(void);
bool dsi_display_aod_grace_active(void);

/*
 * Set by the FTS driver when its firmware reports a double-tap wake.  The
 * display driver uses this to distinguish a real DTW wake from the AOD
 * composition power-on that can happen during the screen-off grace window.
 */
bool fts_recent_double_tap_wake(void);

#endif /* _LINUX_MI_DISPLAY_H */
