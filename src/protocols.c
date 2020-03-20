/**
 * collectd - src/protocols.c
 * Copyright (C) 2009,2010  Florian octo Forster
 * Copyright (C) 2020 Pavel Rochnyak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 *   Pavel Rochnyak <pavel2000 ngs.ru>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"
#include "utils/ignorelist/ignorelist.h"

#if !KERNEL_LINUX
#error "No applicable input method."
#endif

#define SNMP_FILE "/proc/net/snmp"
#define NETSTAT_FILE "/proc/net/netstat"

/*
 * Global variables
 */
static const char *config_keys[] = {"Value", "IgnoreSelected",
                                    "ReportEmptyMetrics"};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static ignorelist_t *ignore_list;
static bool report_empty = false;

/*
 * Functions
 */

static void submit(const char *plugin_instance, const char *type,
                   const char *type_instance, value_t *values,
                   size_t values_len) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = values;
  vl.values_len = values_len;
  sstrncpy(vl.plugin, "protocols", sizeof(vl.plugin));

  if (plugin_instance != NULL)
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));
  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
} /* void submit */

static int match_ignorelist(const char *protocol, const char *key) {
  if (ignore_list == NULL)
    return 0;

  char match_name[2 * DATA_MAX_NAME_LEN];
  ssnprintf(match_name, sizeof(match_name), "%s:%s", protocol, key);

  if (ignorelist_match(ignore_list, match_name))
    return 1;
  return 0;
}

static void protocols_handle_default(const char *protocol, char **key_fields,
                                     char **value_fields, int fields_num) {
  for (int i = 0; i < fields_num; i++) {
    if (match_ignorelist(protocol, key_fields[i]))
      continue;

    value_t value;
    int status = parse_value(value_fields[i], &value, DS_TYPE_DERIVE);
    if (status != 0) {
      continue;
    }

    if (!report_empty && (value.derive == 0)) // Skip empty metrics
      continue;

    submit(protocol /* plugin_instance */, "protocol_counter" /* type */,
           key_fields[i] /* type_instance */, &value, 1);
  }
}

static void protocols_handle_ip(const char *protocol, char **key_fields,
                                char **value_fields, int fields_num) {
  value_t total_packets[] = {{.derive = 0}, {.derive = 0}};

  for (int i = 0; i < fields_num; i++) {
    const char *key = key_fields[i];
    if (match_ignorelist(protocol, key))
      continue;

    if ((strcmp(key, "Forwarding") == 0) || (strcmp(key, "DefaultTTL") == 0))
      continue; // Not a metric

    value_t value;
    int status = parse_value(value_fields[i], &value, DS_TYPE_DERIVE);
    if (status != 0) {
      continue;
    }

    if (!report_empty && (value.derive == 0)) // Skip empty metrics
      continue;

    if (strcmp(key, "InReceives") == 0) {
      total_packets[0] = value;
    } else if (strcmp(key, "OutRequests") == 0) {
      total_packets[1] = value;
    } else {
      submit(protocol /* plugin_instance */, "protocol_counter" /* type */,
             key /* type_instance */, &value, 1);
    }
  };

  submit(protocol, "io_packets", "total", total_packets,
         STATIC_ARRAY_SIZE(total_packets));
}

static void protocols_handle_ipext(const char *protocol, char **key_fields,
                                   char **value_fields, int fields_num) {
  value_t mcast_packets[] = {{.derive = 0}, {.derive = 0}};
  value_t bcast_packets[] = {{.derive = 0}, {.derive = 0}};
  value_t total_octets[] = {{.derive = 0}, {.derive = 0}};
  value_t mcast_octets[] = {{.derive = 0}, {.derive = 0}};
  value_t bcast_octets[] = {{.derive = 0}, {.derive = 0}};

  for (int i = 0; i < fields_num; i++) {
    const char *key = key_fields[i];
    if (match_ignorelist(protocol, key))
      continue;

    if ((strcmp(key, "Forwarding") == 0) || (strcmp(key, "DefaultTTL") == 0))
      continue; // Not a metric

    value_t value;
    int status = parse_value(value_fields[i], &value, DS_TYPE_DERIVE);
    if (status != 0) {
      continue;
    }

    if (!report_empty && (value.derive == 0)) // Skip empty metrics
      continue;

    if (strcmp(key, "InMcastPkts") == 0) {
      mcast_packets[0] = value;
    } else if (strcmp(key, "OutMcastPkts") == 0) {
      mcast_packets[1] = value;
    } else if (strcmp(key, "InBcastPkts") == 0) {
      bcast_packets[0] = value;
    } else if (strcmp(key, "OutBcastPkts") == 0) {
      bcast_packets[1] = value;
    } else if (strcmp(key, "InOctets") == 0) {
      total_octets[0] = value;
    } else if (strcmp(key, "OutOctets") == 0) {
      total_octets[1] = value;
    } else if (strcmp(key, "InMcastOctets") == 0) {
      mcast_octets[0] = value;
    } else if (strcmp(key, "OutMcastOctets") == 0) {
      mcast_octets[1] = value;
    } else if (strcmp(key, "InBcastOctets") == 0) {
      bcast_octets[0] = value;
    } else if (strcmp(key, "OutBcastOctets") == 0) {
      bcast_octets[1] = value;
    } else {
      submit(protocol /* plugin_instance */, "protocol_counter" /* type */,
             key /* type_instance */, &value, 1);
    }
  };

  if ((mcast_packets[0].derive > 0) || (mcast_packets[1].derive > 0))
    submit("Ip", "io_packets", "mcast", mcast_packets,
           STATIC_ARRAY_SIZE(mcast_packets));
  if ((bcast_packets[0].derive > 0) || (bcast_packets[1].derive > 0))
    submit("Ip", "io_packets", "bcast", bcast_packets,
           STATIC_ARRAY_SIZE(bcast_packets));

  submit("Ip", "io_octets", "total", total_octets,
         STATIC_ARRAY_SIZE(total_octets));

  if ((mcast_octets[0].derive > 0) || (mcast_octets[1].derive > 0))
    submit("Ip", "io_octets", "mcast", mcast_octets,
           STATIC_ARRAY_SIZE(mcast_octets));
  if ((bcast_octets[0].derive > 0) || (bcast_octets[1].derive > 0))
    submit("Ip", "io_octets", "bcast", bcast_octets,
           STATIC_ARRAY_SIZE(bcast_octets));
}

static void protocols_handle_udp(const char *protocol, char **key_fields,
                                 char **value_fields, int fields_num) {
  value_t total_packets[] = {{.derive = 0}, {.derive = 0}};

  for (int i = 0; i < fields_num; i++) {
    const char *key = key_fields[i];
    if (match_ignorelist(protocol, key))
      continue;

    if ((strcmp(key, "Forwarding") == 0) || (strcmp(key, "DefaultTTL") == 0))
      continue; // Not a metric

    value_t value;
    int status = parse_value(value_fields[i], &value, DS_TYPE_DERIVE);
    if (status != 0) {
      continue;
    }

    if (!report_empty && (value.derive == 0)) // Skip empty metrics
      continue;

    if (strcmp(key, "InDatagrams") == 0) {
      total_packets[0] = value;
    } else if (strcmp(key, "OutDatagrams") == 0) {
      total_packets[1] = value;
    } else {
      submit(protocol /* plugin_instance */, "protocol_counter" /* type */,
             key /* type_instance */, &value, 1);
    }
  };

  submit(protocol, "io_packets", "total", total_packets,
         STATIC_ARRAY_SIZE(total_packets));
}

static void protocols_handle_icmp(const char *protocol, char **key_fields,
                                  char **value_fields, int fields_num) {
  value_t total_packets[] = {{.derive = 0}, {.derive = 0}};
  value_t sent_echo[] = {{.derive = 0}, {.derive = 0}};

  for (int i = 0; i < fields_num; i++) {
    const char *key = key_fields[i];
    if (match_ignorelist(protocol, key))
      continue;

    value_t value;
    int status = parse_value(value_fields[i], &value, DS_TYPE_DERIVE);
    if (status != 0) {
      continue;
    }

    if (!report_empty && (value.derive == 0)) // Skip empty metrics
      continue;

    // Save values for pingloss calculations
    if (strcmp(key, "OutEchos") == 0) {
      sent_echo[0] = value;
    } else if (strcmp(key, "InEchoReps") == 0) {
      sent_echo[1] = value;
    }

    if (strcmp(key, "InMsgs") == 0) {
      total_packets[0] = value;
    } else if (strcmp(key, "OutMsgs") == 0) {
      total_packets[1] = value;
    } else {
      submit(protocol /* plugin_instance */, "protocol_counter" /* type */,
             key /* type_instance */, &value, 1);
    }
  };

  submit(protocol, "io_packets", "total", total_packets,
         STATIC_ARRAY_SIZE(total_packets));

  // Calculate percent of lost ping probes sent by host
  // This metric is highly affected by race conditions
  // When packet sent accounted in one read cycle, and reply is in next,
  // that produces highly inaccurate results due to low packets rate.
  static value_t prev_sent_echo[] = {{.derive = 0}, {.derive = 0}};
  if (prev_sent_echo[0].derive > 0) {
    derive_t sent = sent_echo[0].derive - prev_sent_echo[0].derive;
    derive_t rcvd = sent_echo[1].derive - prev_sent_echo[1].derive;

    gauge_t loss = 0.0;

    if ((sent > rcvd) && (rcvd > 0)) {
      loss = 100.0 - ((gauge_t)rcvd / (gauge_t)sent);
    } else if (rcvd > sent) {
      WARNING("protocols plugin: Detected ICMP ping rcvd > sent (%" PRIu64
              " > %" PRIu64 ")",
              (int64_t)rcvd, (int64_t)sent);
    }

    submit(protocol, "percent", "pingloss", &(value_t){.gauge = loss}, 1);
  }
  prev_sent_echo[0] = sent_echo[0];
  prev_sent_echo[1] = sent_echo[1];
}

static void protocols_handle_icmpmsg(const char *protocol, char **key_fields,
                                     char **value_fields, int fields_num) {
  for (int i = 0; i < fields_num; i++) {
    const char *key = key_fields[i];
    if (match_ignorelist(protocol, key))
      continue;

    const char *subkey = key;
    if ((((strncmp(key, "InType", strlen("InType")) == 0) &&
          (subkey += strlen("InType"))) ||
         ((strncmp(key, "OutType", strlen("OutType")) == 0) &&
          (subkey += strlen("OutType")))) &&
        ((strcmp(subkey, "0") == 0) || (strcmp(subkey, "3") == 0) ||
         (strcmp(subkey, "4") == 0) || (strcmp(subkey, "5") == 0) ||
         (strcmp(subkey, "8") == 0) || (strcmp(subkey, "11") == 0) ||
         (strcmp(subkey, "12") == 0) || (strcmp(subkey, "13") == 0) ||
         (strcmp(subkey, "14") == 0) || (strcmp(subkey, "17") == 0) ||
         (strcmp(subkey, "18") == 0)))
      continue; // These metrics already sent in protocols_handle_icmp

    value_t value;
    int status = parse_value(value_fields[i], &value, DS_TYPE_DERIVE);
    if (status != 0) {
      continue;
    }

    if (!report_empty && (value.derive == 0)) // Skip empty metrics
      continue;

    submit("Icmp" /* plugin_instance */, "protocol_counter" /* type */,
           key /* type_instance */, &value, 1);
  }
}

static void protocols_handle_tcp(const char *protocol, char **key_fields,
                                 char **value_fields, int fields_num) {
  value_t total_packets[] = {{.derive = 0}, {.derive = 0}};
  value_t retransmit[] = {{.derive = 0}, {.derive = 0}};

  for (int i = 0; i < fields_num; i++) {
    const char *key = key_fields[i];
    if (match_ignorelist(protocol, key))
      continue;

    if ((strcmp(key, "RtoAlgorithm") == 0) || (strcmp(key, "RtoMin") == 0) ||
        (strcmp(key, "RtoMax") == 0))
      continue; // Not a metric

    if (strcmp(key, "MaxConn") == 0)
      continue; // Unsure, got '-1' value

    value_t value;
    int status = parse_value(value_fields[i], &value, DS_TYPE_DERIVE);
    if (status != 0) {
      continue;
    }

    if (strcmp(key, "CurrEstab") == 0) {
      submit(protocol /* plugin_instance */, "current_connections" /* type */,
             NULL /* type_instance */, &(value_t){.gauge = value.derive}, 1);
      continue;
    }

    if (!report_empty && (value.derive == 0)) // Skip empty metrics
      continue;

    // Save value for packetloss/retransmit calculations
    if (strcmp(key, "RetransSegs") == 0) {
      retransmit[0] = value;
    }

    if (strcmp(key, "InSegs") == 0) {
      total_packets[0] = value;
    } else if (strcmp(key, "OutSegs") == 0) {
      total_packets[1] = value;
      retransmit[1] = value;
    } else {
      submit(protocol /* plugin_instance */, "protocol_counter" /* type */,
             key /* type_instance */, &value, 1);
    }
  };

  submit(protocol, "io_packets", "total", total_packets,
         STATIC_ARRAY_SIZE(total_packets));

  /* Similar to RetransSegs/OutSegs ratio it might be possible to report
   * AttemptFails/ActiveOpens ratio. But such metric might show 'weather
   * conditions' just because of long connect timeout. Connection attempt
   * accounted in one read cycle, and connection failure in another
   * (In my tests: after ~21sec, so typically 2 read cycles between)
  */

  // Calculate retransmit rate as RetransSegs/OutSegs
  static value_t prev_retransmit[] = {{.derive = 0}, {.derive = 0}};
  if (prev_retransmit[0].derive > 0) { // Retransmit segments exists
    derive_t num = retransmit[0].derive - prev_retransmit[0].derive;
    derive_t denom = retransmit[1].derive - prev_retransmit[1].derive;

    gauge_t rate = 100.0;
    if (denom > 0)
      rate = 100.0 * (gauge_t)num / (gauge_t)denom;

    submit(protocol, "percent", "retransmit", &(value_t){.gauge = rate}, 1);
  }
  prev_retransmit[0] = retransmit[0];
  prev_retransmit[1] = retransmit[1];
}

static int read_file(const char *path) {
  char key_buffer[4096];
  char value_buffer[4096];
  char *key_fields[256];
  char *value_fields[256];

  FILE *fh = fopen(path, "r");
  if (fh == NULL) {
    ERROR("protocols plugin: fopen (%s) failed: %s.", path, STRERRNO);
    return -1;
  }

  int status = -1;
  while (42) {
    clearerr(fh);
    char *key_ptr = fgets(key_buffer, sizeof(key_buffer), fh);
    if (key_ptr == NULL) {
      if (feof(fh) != 0) {
        status = 0;
        break;
      } else if (ferror(fh) != 0) {
        ERROR("protocols plugin: Reading from %s failed.", path);
        break;
      } else {
        ERROR("protocols plugin: fgets failed for an unknown reason.");
        break;
      }
    } /* if (key_ptr == NULL) */

    char *value_ptr = fgets(value_buffer, sizeof(value_buffer), fh);
    if (value_ptr == NULL) {
      ERROR("protocols plugin: read_file (%s): Could not read values line.",
            path);
      break;
    }

    key_ptr = strchr(key_buffer, ':');
    if (key_ptr == NULL) {
      ERROR("protocols plugin: Could not find protocol name in keys line.");
      break;
    }
    *key_ptr = 0;
    key_ptr++; // Now points to headers

    value_ptr = strchr(value_buffer, ':');
    if (value_ptr == NULL) {
      ERROR("protocols plugin: Could not find protocol name "
            "in values line.");
      break;
    }
    *value_ptr = 0;
    value_ptr++;

    if (strcmp(key_buffer, value_buffer) != 0) {
      ERROR("protocols plugin: Protocol names in keys and values lines "
            "don't match: `%s' vs. `%s'.",
            key_buffer, value_buffer);
      break;
    }

    int key_fields_num =
        strsplit(key_ptr, key_fields, STATIC_ARRAY_SIZE(key_fields));
    int value_fields_num =
        strsplit(value_ptr, value_fields, STATIC_ARRAY_SIZE(value_fields));

    if (key_fields_num != value_fields_num) {
      ERROR("protocols plugin: Number of fields in keys and values lines "
            "don't match: %i vs %i.",
            key_fields_num, value_fields_num);
      break;
    }

    if (strcmp(key_buffer, "Ip") == 0) {
      protocols_handle_ip(key_buffer, key_fields, value_fields, key_fields_num);
    } else if (strcmp(key_buffer, "IpExt") == 0) {
      protocols_handle_ipext(key_buffer, key_fields, value_fields,
                             key_fields_num);
    } else if (strcmp(key_buffer, "Icmp") == 0) {
      protocols_handle_icmp(key_buffer, key_fields, value_fields,
                            key_fields_num);
    } else if (strcmp(key_buffer, "IcmpMsg") == 0) {
      protocols_handle_icmpmsg(key_buffer, key_fields, value_fields,
                               key_fields_num);
    } else if (strcmp(key_buffer, "Tcp") == 0) {
      protocols_handle_tcp(key_buffer, key_fields, value_fields,
                           key_fields_num);
    }
    // else if (strcmp(key_buffer,"TcpExt") == 0) {
    //    //Use default handler
    //}
    else if (strcmp(key_buffer, "Udp") == 0) {
      protocols_handle_udp(key_buffer, key_fields, value_fields,
                           key_fields_num);
    }
    // else if (strcmp(key_buffer,"UdpLite") == 0) {
    //    //Use default handler
    //}
    else {
      protocols_handle_default(key_buffer, key_fields, value_fields,
                               key_fields_num);
    }
  } /* while (42) */

  fclose(fh);

  return status;
} /* int read_file */

static int protocols_read(void) {
  int success = 0;

  int status = read_file(SNMP_FILE);
  if (status == 0)
    success++;

  status = read_file(NETSTAT_FILE);
  if (status == 0)
    success++;

  if (success == 0)
    return -1;

  return 0;
} /* int protocols_read */

static int protocols_config(const char *key, const char *value) {
  if (ignore_list == NULL)
    ignore_list = ignorelist_create(/* invert = */ 1);

  if (strcasecmp(key, "Value") == 0) {
    ignorelist_add(ignore_list, value);
  } else if (strcasecmp(key, "IgnoreSelected") == 0) {
    int invert = 1;
    if (IS_TRUE(value))
      invert = 0;
    ignorelist_set_invert(ignore_list, invert);
  } else if (strcasecmp(key, "ReportEmptyMetrics")) {
    report_empty = IS_TRUE(value);
  } else {
    return -1;
  }

  return 0;
} /* int protocols_config */

void module_register(void) {
  plugin_register_config("protocols", protocols_config, config_keys,
                         config_keys_num);
  plugin_register_read("protocols", protocols_read);
} /* void module_register */
