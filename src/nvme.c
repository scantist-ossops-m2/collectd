/**
 * collectd - src/nvme.c
 * Copyright (C) 2016       Pavel Rochnyak
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Pavel Rochnyak <pavel2000 ngs.ru>
 * 
 * Uses some of `nvme-cli` code (licensed under GNU GPL 2.0).
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"
#include <libgen.h>

#include "nvme/linux/nvme.h"
#include "nvme/nvme-ioctl.h"

typedef struct {
  char *device;
  uint8_t critical_warning;
  uint8_t last_available_spare;
} device_t;

static device_t *devices;
static size_t devices_num;

static long double int128_to_double(__u8 *data) {
  long double result = 0;

  for (int i = 0; i < 16; i++) {
    result *= 256;
    result += data[15 - i];
  }
  return result;
}

static int nvme_open_dev(char *dev) {
  static struct stat nvme_stat;
  char *devicename = basename(dev);
  int fd = open(dev, O_RDONLY);
  if (fd < 0) {
    ERROR("nvme plugin: open (%s): %s", devicename, STRERRNO);
    return -1;
  }

  int err = fstat(fd, &nvme_stat);
  if (err < 0) {
    close(fd);
    ERROR("nvme plugin: fstat (%s): %s", devicename, STRERRNO);
    return -1;
  }

  if (!S_ISCHR(nvme_stat.st_mode) && !S_ISBLK(nvme_stat.st_mode)) {
    ERROR("nvme plugin: %s is not a block or character device", dev);
    close(fd);
    return -ENODEV;
  }
  return fd;
}

static void cnvme_notify_critical_warning(struct nvme_smart_log *smart, device_t *device) {
  char *devname = basename(device->device);

  notification_t n;
  notification_init(&n, NOTIF_FAILURE, NULL, hostname_g, "nvme", devname, "critical_warning", NULL);
  n.time = cdtime();

  if (smart->critical_warning == 0)
   n.severity = NOTIF_OKAY;

  char *buf = n.message;
  size_t bufsize = sizeof(n.message);

  int status = ssnprintf(buf, bufsize, "critical_warning: %#x\n\n", smart->critical_warning);
  buf += status;
  bufsize -= status;

  status = ssnprintf(buf, bufsize, "Available Spare[0]             : %d\n", smart->critical_warning & 0x01);
  buf += status;
  bufsize -= status;

  status = ssnprintf(buf, bufsize, "Temp. Threshold[1]             : %d\n", (smart->critical_warning & 0x02) >> 1);
  buf += status;
  bufsize -= status;

  status = ssnprintf(buf, bufsize, "NVM subsystem Reliability[2]   : %d\n", (smart->critical_warning & 0x04) >> 2);
  buf += status;
  bufsize -= status;

  status = ssnprintf(buf, bufsize, "Read-only[3]                   : %d\n", (smart->critical_warning & 0x08) >> 3);
  buf += status;
  bufsize -= status;

  status = ssnprintf(buf, bufsize, "Volatile mem. backup failed[4] : %d\n", (smart->critical_warning & 0x10) >> 4);
  buf += status;
  bufsize -= status;

  status = ssnprintf(buf, bufsize, "Persistent Mem. RO[5]          : %d\n", (smart->critical_warning & 0x20) >> 5);
  buf += status;
  bufsize -= status;

  plugin_dispatch_notification(&n);
}

static void cnvme_notify_available_spare(struct nvme_smart_log *smart, device_t *device) {

  //Skip first cycle
  if (device->last_available_spare == 255)
    return;

  char *devname = basename(device->device);

  notification_t n;
  notification_init(&n, NOTIF_WARNING, NULL, hostname_g, "nvme", devname, "available_spare", NULL);
  n.time = cdtime();

  if (smart->avail_spare > smart->spare_thresh)
   n.severity = NOTIF_OKAY;

  char *buf = n.message;
  size_t bufsize = sizeof(n.message);

  ssnprintf(buf, bufsize, "avail_spare changed from %u%% to %u%%. Threshold: %u%%\n", device->last_available_spare, smart->avail_spare, smart->spare_thresh);

  plugin_dispatch_notification(&n);
}

static void cnvme_submit(device_t *device, const char *type, const char *type_instance, value_t *values, size_t values_len) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = values;
  vl.values_len = values_len;

  sstrncpy(vl.plugin, "nvme", sizeof(vl.plugin));

  char *devname = basename(device->device);
  sstrncpy(vl.plugin_instance, devname, sizeof(vl.plugin_instance));

  sstrncpy(vl.type, type, sizeof(vl.type));

  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
}

/*
# nvme smart-log /dev/nvme0n1 --- Dead device
Smart Log for NVME device:nvme0n1 namespace-id:ffffffff
+critical_warning                    : 0x9
+temperature                         : 38 C
+available_spare                     : 3%
+available_spare_threshold           : 10%
+ercentage_used                     : 27%
+data_units_read                     : 27,415,274
+data_units_written                  : 2,436,083,299
+host_read_commands                  : 3,880,968,389
+host_write_commands                 : 26,429,546,049
-controller_busy_time                : 16,758
-power_cycles                        : 29
-power_on_hours                      : 14,453
-unsafe_shutdowns                    : 14
-media_errors                        : 0
-num_err_log_entries                 : 10
-Warning Temperature Time            : 0
-Critical Composite Temperature Time : 0
+Temperature Sensor 1                : 38 C
+Temperature Sensor 2                : 0 C
+Temperature Sensor 3                : 0 C
+Temperature Sensor 4                : 0 C
+Temperature Sensor 5                : 0 C
+Temperature Sensor 6                : 0 C
+Temperature Sensor 7                : 0 C
+Temperature Sensor 8                : 0 C
*/

static void cnvme_report_smart_log(struct nvme_smart_log *smart, device_t *device) {
        /* Check device status */
        if (device->critical_warning != smart->critical_warning) {
           cnvme_notify_critical_warning(smart, device);
           device->critical_warning = smart->critical_warning;
        }
        cnvme_submit(device, "gauge", "critical_warning", &(value_t){.gauge = smart->critical_warning}, 1);

        /* Report available_spare */
        if (device->last_available_spare != smart->avail_spare) {
           cnvme_notify_available_spare(smart, device);
           device->last_available_spare = smart->avail_spare;
        }

        cnvme_submit(device, "percent", "available_spare", &(value_t){.gauge = smart->avail_spare}, 1);
        cnvme_submit(device, "percent", "spare_threshold", &(value_t){.gauge = smart->spare_thresh}, 1);
        if (smart->percent_used > 100) //Could be > 100
           smart->percent_used = 100;
        cnvme_submit(device, "percent", "percentage_used", &(value_t){.gauge = smart->percent_used}, 1);

        {
        //Convert units to bytes
        value_t values[] = {
           {.derive = int128_to_double(smart->data_units_read) * 512 * 1024},
           {.derive = int128_to_double(smart->data_units_written) * 512 * 1024},
        };

        cnvme_submit(device, "disk_octets", NULL, values, STATIC_ARRAY_SIZE(values));
        }

        {
        value_t values[] = {
           {.derive = int128_to_double(smart->host_reads)},
           {.derive = int128_to_double(smart->host_writes)},
        };
        cnvme_submit(device, "disk_ops", NULL, values, STATIC_ARRAY_SIZE(values));
        }

        /* Report temperatures */
        /* Possible TODO: Get thresholds from WCTEMP and CCTEMP fields in the Identify Controller data structure. */

        /* convert temperature from Kelvin to Celsius */
        int temperature = ((smart->temperature[1] << 8) | smart->temperature[0]) - 273;

        /* Warning and critical overheating composite temperature threshold 
        values are reported by the WCTEMP and CCTEMP fields in the 
        Identify Controller data structure. */
        cnvme_submit(device, "temperature", "composite", &(value_t){.gauge = temperature}, 1);
        for (int i = 0; i < 8; i++) {
                __s32 temp = le16_to_cpu(smart->temp_sensor[i]);

                if (temp == 0)
                        continue;

                char sensor[DATA_MAX_NAME_LEN];
                snprintf(sensor, sizeof(sensor), "sensor-%d", i + 1);

                cnvme_submit(device, "temperature", sensor, &(value_t){.gauge = temp - 273}, 1);
        }
}

static int cnvme_read_device(device_t *device) {
  int fd = nvme_open_dev(device->device);
  if (fd < 0)
    return -1;

  struct nvme_smart_log smart_log;
  int err = nvme_smart_log(fd, NVME_NSID_ALL, &smart_log);
  if (!err)
    cnvme_report_smart_log(&smart_log, device);
  else if (err > 0)
    //ERROR("nvme plugin: NVMe status: %s(%#x)", nvme_status_to_string(err), err);
    ERROR("nvme plugin: NVMe status: %#x", err);
  else
    ERROR("nvme plugin: smart_log failed: %s", STRERRNO);

  close(fd);

  if (!err)
    return 0;

  return -1;
} /* static int cnvme_read_device */

static int cnvme_read(void) {
  for (int i = 0 ; i < devices_num ; i++) {
    cnvme_read_device(&devices[i]);
  }
  return 0;
} /* static int cnvme_read */

static int cnvme_config_device(oconfig_item_t *ci) {
  if (ci->values_num != 1 || ci->values[0].type != OCONFIG_TYPE_STRING) {
    P_ERROR("`Device` expects only single string argument.");
    return 1;
  }

  char *device = strdup(ci->values[0].value.string);
  if (device == NULL) {
    P_ERROR("strdup failed: %s.", STRERRNO);
    return -1;
  }

  device_t *tmp = realloc(devices, (devices_num + 1) * sizeof(*devices));
  if (tmp == NULL) {
    P_ERROR("realloc failed: %s.", STRERRNO);
    return -1;
  }

  devices = tmp;
  devices[devices_num].device = device;
  devices[devices_num].critical_warning = 0;
  devices[devices_num].last_available_spare = 255;
  devices_num++;

  return 0;
} /* static int cnvme_config_device */


static int cnvme_config(oconfig_item_t *ci) {
  for (int i = 0; i < ci->children_num; ++i) {
    oconfig_item_t *c = ci->children + i;

    if (strcasecmp(c->key, "Device") == 0)
      cnvme_config_device(c);
    else
      P_WARNING("Ignoring unknown config key \"%s\".", c->key);
  }

  return 0;
} /* static int cnvme_config */

static int cnvme_init(void) {
  if (devices_num == 0) {
    P_WARNING("No devices configured");
  }
  else {
    plugin_register_read("nvme", cnvme_read);
  }
  return 0;
} /* static int cnvme_init */

static int cnvme_shutdown(void) {
  for (int i = 0 ; i < devices_num ; i++) {
    sfree(devices[i].device);
  }
  sfree(devices);
  return 0;
} /* static int nvme_shutdown */


void module_register(void) {
  plugin_register_complex_config("nvme", cnvme_config);
  plugin_register_init("nvme", cnvme_init);
  plugin_register_shutdown("nvme", cnvme_shutdown);
} /* void module_register */
