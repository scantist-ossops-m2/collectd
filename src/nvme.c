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
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#include <libgen.h>
//#include "nvme/linux/nvme_ioctl.h"
#include "nvme/linux/nvme.h"
#include "nvme/nvme-ioctl.h"
#include "nvme/nvme-print.h"

//#include <errno.h>
//#include <getopt.h>
//#include <fcntl.h>
//#include <inttypes.h>
//#include <locale.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <math.h>
//#include <dirent.h>
//#include <libgen.h>


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
    fprintf(stderr, "%s is not a block or character device\n", dev);
    close(fd);
    return -ENODEV;
  }
  return fd;
}

static int cnvme_init(void) {
  return 0;
} /* static int nvme_init */

static int cnvme_shutdown(void) {

  return 0;
} /* static int nvme_shutdown */
    
static void cnvme_report_smart_log(struct nvme_smart_log *smart, const char *devname) {
  return;
}

static int cnvme_read(void) {
  struct nvme_smart_log smart_log;
  int err, fd;
  
  char *dev = "/dev/nvme0n1";
  
  char *devicename = basename(dev);
  
  err = fd = nvme_open_dev(dev);
  if (fd < 0)
    goto ret;
  
  err = nvme_smart_log(fd, NVME_NSID_ALL, &smart_log);
  if (!err)
    cnvme_report_smart_log(&smart_log, devicename);
  else if (err > 0)
    ERROR("nvme plugin: NVMe status: %s(%#x)", nvme_status_to_string(err), err);
  else
    ERROR("nvme plugin: smart_log failed: %s", STRERRNO);

  close(fd);
ret:
  if (!err)
    return 0;

  return -1;
} /* static int nvme_read */

void module_register(void) {
  plugin_register_init("nvme", cnvme_init);
  plugin_register_read("nvme", cnvme_read);
  plugin_register_shutdown("nvme", cnvme_shutdown);
} /* void module_register */
