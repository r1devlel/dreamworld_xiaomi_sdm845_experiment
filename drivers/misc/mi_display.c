/*
 * Minimal Xiaomi mi_display feature transport.
 *
 * HyperOS SurfaceFlinger opens /dev/mi_display/disp_feature and sends
 * display-feature notifications through ioctl 0xc0304401.  The Android
 * ueventd configuration already creates the /dev/mi_display directory for
 * devices in the "mi_display" subsystem.
 *
 * Only the AOD layer notification is consumed here.  It is used by the DSI
 * bridge to keep the primary panel in its doze state instead of powering it
 * off when the screen is blanked.  Other messages are accepted and ignored;
 * they carry optional frame-rate and power hints that are not required for
 * display operation.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mi_display.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define MI_DISPLAY_IOCTL_MAGIC	'D'
#define MI_DISPLAY_IOCTL_NR	1
#define MI_DISPLAY_MSG_AOD	0x27
#define MI_DISPLAY_MSG_EARLY	0x28

struct mi_display_request {
	__u64 reserved0;
	__u32 type;
	__u32 value;
	__u64 reserved[4];
};

#define MI_DISPLAY_IOCTL \
	_IOWR(MI_DISPLAY_IOCTL_MAGIC, MI_DISPLAY_IOCTL_NR, \
	      struct mi_display_request)

static bool mi_display_aod_enabled;
static dev_t mi_display_dev;
static struct cdev mi_display_cdev;
static struct class *mi_display_class;
static struct device *mi_display_device;

bool mi_display_is_aod_enabled(void)
{
	return READ_ONCE(mi_display_aod_enabled);
}
EXPORT_SYMBOL_GPL(mi_display_is_aod_enabled);

static long mi_display_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct mi_display_request req;

	if (cmd != MI_DISPLAY_IOCTL)
		return -ENOTTY;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	switch (req.type) {
	case MI_DISPLAY_MSG_AOD:
		WRITE_ONCE(mi_display_aod_enabled, !!req.value);
		pr_info("mi_display: AOD notification %u\n", req.value);
		break;
	case MI_DISPLAY_MSG_EARLY:
		/* Optional screen-on/off latency hint. */
		break;
	default:
		pr_debug("mi_display: ignoring message type 0x%x\n", req.type);
		break;
	}

	return 0;
}

static const struct file_operations mi_display_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = mi_display_ioctl,
};

static int __init mi_display_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&mi_display_dev, 0, 1, "mi_display");
	if (ret)
		return ret;

	cdev_init(&mi_display_cdev, &mi_display_fops);
	mi_display_cdev.owner = THIS_MODULE;

	ret = cdev_add(&mi_display_cdev, mi_display_dev, 1);
	if (ret)
		goto err_unregister;

	mi_display_class = class_create(THIS_MODULE, "mi_display");
	if (IS_ERR(mi_display_class)) {
		ret = PTR_ERR(mi_display_class);
		mi_display_class = NULL;
		goto err_cdev;
	}

	mi_display_device = device_create(mi_display_class, NULL,
					  mi_display_dev, NULL, "disp_feature");
	if (IS_ERR(mi_display_device)) {
		ret = PTR_ERR(mi_display_device);
		mi_display_device = NULL;
		goto err_class;
	}

	pr_info("mi_display: created /dev/mi_display/disp_feature\n");
	return 0;

err_class:
	class_destroy(mi_display_class);
	mi_display_class = NULL;
err_cdev:
	cdev_del(&mi_display_cdev);
err_unregister:
	unregister_chrdev_region(mi_display_dev, 1);
	return ret;
}
module_init(mi_display_init);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Minimal Xiaomi mi_display feature transport");
