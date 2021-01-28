/**
 * collectd - src/opcache.c
 * Copyright (C) 2009       Doug MacEachern
 * Copyright (C) 2006-2013  Florian octo Forster
 * Copyright (C) 2021       Pavel Rochnyak
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
 *   Doug MacEachern <dougm at hyperic.com>
 *   Florian octo Forster <octo at collectd.org>
 *   Pavel Rochnyak  <pavel2000 ngs.ru>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"
#include "utils/curl_stats/curl_stats.h"

#include <sys/types.h>

#include <curl/curl.h>

#include <yajl/yajl_tree.h>

#define CJ_DEFAULT_HOST "localhost"

struct prev_s {
  derive_t hits;
  derive_t gets;
};

typedef struct prev_s prev_t;

struct cj_s {
  char *instance;
  char *plugin_name;
  char *host;

  char *url;
  int address_family;
  char *user;
  char *pass;
  char *credentials;
  bool digest;
  bool verify_peer;
  bool verify_host;
  char *cacert;
  struct curl_slist *headers;
  // char *post_body;
  int timeout;
  curl_stats_t *stats;

  CURL *curl;
  char curl_errbuf[CURL_ERROR_SIZE];
  char *buffer;
  size_t buffer_size;
  size_t buffer_fill;

  prev_t prev;
};
typedef struct cj_s cj_t;

static int cj_read(user_data_t *ud);

static size_t cj_curl_callback(void *buf, size_t size, size_t nmemb,
                               void *user_data) {
  size_t len = size * nmemb;
  if (len == 0)
    return len;

  cj_t *db = user_data;
  if (db == NULL)
    return 0;

  if ((db->buffer_fill + len) >= db->buffer_size) {
    size_t temp_size = db->buffer_fill + len + 1;
    char *temp = realloc(db->buffer, temp_size);
    if (temp == NULL) {
      ERROR("opcache plugin: realloc failed.");
      return 0;
    }
    db->buffer = temp;
    db->buffer_size = temp_size;
  }

  memcpy(db->buffer + db->buffer_fill, (char *)buf, len);
  db->buffer_fill += len;
  db->buffer[db->buffer_fill] = 0;

  return len;
}

static void cj_free(void *arg) {
  DEBUG("opcache plugin: cj_free (arg = %p);", arg);

  cj_t *db = (cj_t *)arg;

  if (db == NULL)
    return;

  if (db->curl != NULL)
    curl_easy_cleanup(db->curl);
  db->curl = NULL;

  sfree(db->instance);
  sfree(db->plugin_name);
  sfree(db->host);

  sfree(db->url);
  sfree(db->user);
  sfree(db->pass);
  sfree(db->credentials);
  sfree(db->cacert);
  // sfree(db->post_body);
  curl_slist_free_all(db->headers);
  curl_stats_destroy(db->stats);

  sfree(db->buffer);
  sfree(db);
}

/* Configuration handling functions {{{ */

static int cj_config_append_string(const char *name,
                                   struct curl_slist **dest, /* {{{ */
                                   oconfig_item_t *ci) {
  struct curl_slist *temp = NULL;
  if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_STRING)) {
    WARNING("opcache plugin: `%s' needs exactly one string argument.", name);
    return -1;
  }

  temp = curl_slist_append(*dest, ci->values[0].value.string);
  if (temp == NULL)
    return -1;

  *dest = temp;

  return 0;
}

static int cj_init_curl(cj_t *db) {
  db->curl = curl_easy_init();
  if (db->curl == NULL) {
    ERROR("opcache plugin: curl_easy_init failed.");
    return -1;
  }

  curl_easy_setopt(db->curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(db->curl, CURLOPT_WRITEFUNCTION, cj_curl_callback);
  curl_easy_setopt(db->curl, CURLOPT_WRITEDATA, db);
  curl_easy_setopt(db->curl, CURLOPT_USERAGENT, COLLECTD_USERAGENT);
  curl_easy_setopt(db->curl, CURLOPT_ERRORBUFFER, db->curl_errbuf);
  curl_easy_setopt(db->curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(db->curl, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(db->curl, CURLOPT_IPRESOLVE, db->address_family);

  if (db->user != NULL) {
#ifdef HAVE_CURLOPT_USERNAME
    curl_easy_setopt(db->curl, CURLOPT_USERNAME, db->user);
    curl_easy_setopt(db->curl, CURLOPT_PASSWORD,
                     (db->pass == NULL) ? "" : db->pass);
#else
    size_t credentials_size;

    credentials_size = strlen(db->user) + 2;
    if (db->pass != NULL)
      credentials_size += strlen(db->pass);

    db->credentials = malloc(credentials_size);
    if (db->credentials == NULL) {
      ERROR("opcache plugin: malloc failed.");
      return -1;
    }

    snprintf(db->credentials, credentials_size, "%s:%s", db->user,
             (db->pass == NULL) ? "" : db->pass);
    curl_easy_setopt(db->curl, CURLOPT_USERPWD, db->credentials);
#endif

    if (db->digest)
      curl_easy_setopt(db->curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
  }

  curl_easy_setopt(db->curl, CURLOPT_SSL_VERIFYPEER, (long)db->verify_peer);
  curl_easy_setopt(db->curl, CURLOPT_SSL_VERIFYHOST, db->verify_host ? 2L : 0L);
  if (db->cacert != NULL)
    curl_easy_setopt(db->curl, CURLOPT_CAINFO, db->cacert);
  if (db->headers != NULL)
    curl_easy_setopt(db->curl, CURLOPT_HTTPHEADER, db->headers);
    //  if (db->post_body != NULL)
    //    curl_easy_setopt(db->curl, CURLOPT_POSTFIELDS, db->post_body);

#ifdef HAVE_CURLOPT_TIMEOUT_MS
  if (db->timeout >= 0)
    curl_easy_setopt(db->curl, CURLOPT_TIMEOUT_MS, (long)db->timeout);
  else
    curl_easy_setopt(db->curl, CURLOPT_TIMEOUT_MS,
                     (long)CDTIME_T_TO_MS(plugin_get_interval()));
#endif

  return 0;
}

static int cj_config_add_url(oconfig_item_t *ci) {
  cj_t *db;
  int status = 0;
  cdtime_t interval = 0;

  if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_STRING)) {
    WARNING("opcache plugin: The `URL' block "
            "needs exactly one string argument.");
    return -1;
  }

  db = calloc(1, sizeof(*db));
  if (db == NULL) {
    ERROR("opcache plugin: calloc failed.");
    return -1;
  }

  db->timeout = -1;
  db->address_family = CURL_IPRESOLVE_WHATEVER;

  if (strcasecmp("URL", ci->key) == 0)
    status = cf_util_get_string(ci, &db->url);
  else {
    ERROR("opcache plugin: cj_config: "
          "Invalid key: %s",
          ci->key);
    cj_free(db);
    return -1;
  }
  if (status != 0) {
    sfree(db);
    return status;
  }

  assert(db->url != NULL);

  /* Fill the `cj_t' structure.. */
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp("Instance", child->key) == 0)
      status = cf_util_get_string(child, &db->instance);
    else if (strcasecmp("Plugin", child->key) == 0)
      status = cf_util_get_string(child, &db->plugin_name);
    else if (strcasecmp("Host", child->key) == 0)
      status = cf_util_get_string(child, &db->host);
    else if (db->url && strcasecmp("User", child->key) == 0)
      status = cf_util_get_string(child, &db->user);
    else if (db->url && strcasecmp("Password", child->key) == 0)
      status = cf_util_get_string(child, &db->pass);
    else if (strcasecmp("Digest", child->key) == 0)
      status = cf_util_get_boolean(child, &db->digest);
    else if (db->url && strcasecmp("VerifyPeer", child->key) == 0)
      status = cf_util_get_boolean(child, &db->verify_peer);
    else if (db->url && strcasecmp("VerifyHost", child->key) == 0)
      status = cf_util_get_boolean(child, &db->verify_host);
    else if (db->url && strcasecmp("CACert", child->key) == 0)
      status = cf_util_get_string(child, &db->cacert);
    else if (db->url && strcasecmp("Header", child->key) == 0)
      status = cj_config_append_string("Header", &db->headers, child);
    //    else if (db->url && strcasecmp("Post", child->key) == 0)
    //      status = cf_util_get_string(child, &db->post_body);
    else if (strcasecmp("Interval", child->key) == 0)
      status = cf_util_get_cdtime(child, &interval);
    else if (strcasecmp("Timeout", child->key) == 0)
      status = cf_util_get_int(child, &db->timeout);
    else if (strcasecmp("Statistics", child->key) == 0) {
      db->stats = curl_stats_from_config(child);
      if (db->stats == NULL)
        status = -1;
    } else if (db->url && strcasecmp("AddressFamily", child->key) == 0) {
      char *af = NULL;
      status = cf_util_get_string(child, &af);
      if (status != 0 || af == NULL) {
        WARNING("opcache plugin: Cannot parse value of `%s' for URL `%s'.",
                child->key, db->url);
      } else if (strcasecmp("any", af) == 0) {
        db->address_family = CURL_IPRESOLVE_WHATEVER;
      } else if (strcasecmp("ipv4", af) == 0) {
        db->address_family = CURL_IPRESOLVE_V4;
      } else if (strcasecmp("ipv6", af) == 0) {
        /* If curl supports ipv6, use it. If not, log a warning and
         * fall back to default - don't set status to non-zero.
         */
        curl_version_info_data *curl_info = curl_version_info(CURLVERSION_NOW);
        if (curl_info->features & CURL_VERSION_IPV6)
          db->address_family = CURL_IPRESOLVE_V6;
        else
          WARNING("opcache plugin: IPv6 not supported by this libCURL. "
                  "Using fallback `any'.");
      } else {
        WARNING("opcache plugin: Unsupported value of `%s' for URL `%s'.",
                child->key, db->url);
        status = -1;
      }
    } else {
      WARNING("opcache plugin: Option `%s' not allowed here.", child->key);
      status = -1;
    }

    if (status != 0)
      break;
  }

  if (status == 0) {
    status = cj_init_curl(db);
  }

  if (status != 0) {
    cj_free(db);
    return -1;
  }

  /* If all went well, register this database for reading */
  if (db->instance == NULL)
    db->instance = strdup("default");

  if (db->plugin_name == NULL)
    db->plugin_name = strdup("opcache");

  if (db->instance == NULL || db->plugin_name == NULL) {
    ERROR("opcache plugin: no memory");
    cj_free(db);
    return -1;
  }

  DEBUG("opcache plugin: Registering new read callback: %s", db->instance);

  char *cb_name = ssnprintf_alloc("opcache-%s-%s", db->instance, db->url);

  plugin_register_complex_read(/* group = */ NULL, cb_name, cj_read, interval,
                               &(user_data_t){
                                   .data = db,
                                   .free_func = cj_free,
                               });
  sfree(cb_name);
  return 0;
}

static int cj_config(oconfig_item_t *ci) {
  int success = 0;
  int errors = 0;

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp("URL", child->key) == 0) {
      int status = cj_config_add_url(child);
      if (status == 0)
        success++;
      else
        errors++;
    } else {
      WARNING("opcache plugin: Option `%s' not allowed here.", child->key);
      errors++;
    }
  }

  if ((success == 0) && (errors > 0)) {
    ERROR("opcache plugin: All statements failed.");
    return -1;
  }

  return 0;
}

/* }}} End of configuration handling functions */

static const char *cj_host(cj_t *db) /* {{{ */
{
  if ((db->host == NULL) || (strcmp("", db->host) == 0) ||
      (strcmp(CJ_DEFAULT_HOST, db->host) == 0))
    return hostname_g;
  return db->host;
} /* }}} cj_host */

static void submit(const char *type, const char *type_instance, value_t *values,
                   size_t values_len, cj_t *db) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = values;
  vl.values_len = values_len;

  sstrncpy(vl.host, cj_host(db), sizeof(vl.host));
  sstrncpy(vl.plugin, db->plugin_name, sizeof(vl.plugin));

  sstrncpy(vl.plugin_instance, db->instance, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));
  if (type_instance)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
}

static gauge_t calculate_ratio_percent(derive_t part1, derive_t part2,
                                       derive_t *prev1, derive_t *prev2) {
  if ((*prev1 == 0) || (*prev2 == 0) || (part1 < *prev1) || (part2 < *prev2)) {
    *prev1 = part1;
    *prev2 = part2;
    return NAN;
  }

  derive_t num = part1 - *prev1;
  derive_t denom = part2 - *prev2 + num;

  *prev1 = part1;
  *prev2 = part2;

  if (denom == 0)
    return NAN;

  if (num == 0)
    return 0;

  return 100.0 * (gauge_t)num / (gauge_t)denom;
}

static int cj_read(user_data_t *ud) {
  long rc;
  char *url;

  if ((ud == NULL) || (ud->data == NULL)) {
    ERROR("opcache plugin: cj_read: Invalid user data.");
    return -1;
  }

  cj_t *db = (cj_t *)ud->data;

  db->buffer_fill = 0;
  curl_easy_setopt(db->curl, CURLOPT_URL, db->url);

  int status = curl_easy_perform(db->curl);
  if (status != CURLE_OK) {
    ERROR("opcache plugin: curl_easy_perform failed with status %i: %s (%s)",
          status, db->curl_errbuf, db->url);
    return -1;
  }
  if (db->stats != NULL)
    curl_stats_dispatch(db->stats, db->curl, cj_host(db), "opcache",
                        db->instance);

  curl_easy_getinfo(db->curl, CURLINFO_EFFECTIVE_URL, &url);
  curl_easy_getinfo(db->curl, CURLINFO_RESPONSE_CODE, &rc);

  /* The response code is zero if a non-HTTP transport was used. */
  if ((rc != 0) && (rc != 200)) {
    ERROR("opcache plugin: curl_easy_perform failed with "
          "response code %ld (%s)",
          rc, url);
    return -1;
  }

#if COLLECT_DEBUG
  if (db->buffer_size > 0) {
    DEBUG("opcache plugin: curl_response=%s", db->buffer);
  }
#endif

  char errbuf[1024];
  const char *memory_usage_path[] = {"memory_usage", NULL};
  const char *statistics_path[] = {"opcache_statistics", NULL};
  const char *istrings_path[] = {"interned_strings_usage", NULL};

  yajl_val root = yajl_tree_parse(db->buffer, errbuf, sizeof(errbuf));
  if (root == NULL) {
    ERROR("opcache plugin: JSON parse error %s", errbuf);
    return -1;
  }

  // MEMORY part
  yajl_val memory_val = yajl_tree_get(root, memory_usage_path, yajl_t_object);
  if (memory_val == NULL) {
    ERROR("opcache plugin: memory_usage structure not found");
    yajl_tree_free(root);
    return -1;
  }

#define MEMORY_VARIABLE(variable, path)                                        \
  uint64_t variable;                                                           \
  do {                                                                         \
    const char *value_path[] = {path, NULL};                                   \
    yajl_val value = yajl_tree_get(memory_val, value_path, yajl_t_number);     \
    if (value == NULL) {                                                       \
      ERROR("opcache plugin: " path " field not found");                       \
      yajl_tree_free(root);                                                    \
      return -1;                                                               \
    }                                                                          \
    variable = YAJL_GET_INTEGER(value);                                        \
    DEBUG("opcache plugin: " path " = %llu", variable);                        \
  } while (0);

  MEMORY_VARIABLE(used_memory, "used_memory");
  MEMORY_VARIABLE(free_memory, "free_memory");
  MEMORY_VARIABLE(wasted_memory, "wasted_memory");

  submit("memory", "used", &(value_t){.gauge = used_memory}, 1, db);
  submit("memory", "free", &(value_t){.gauge = free_memory}, 1, db);
  submit("memory", "wasted", &(value_t){.gauge = wasted_memory}, 1, db);

  // INTERNED STRINGS part
  yajl_val istrings_val = yajl_tree_get(root, istrings_path, yajl_t_object);
  if (memory_val == NULL) {
    ERROR("opcache plugin: memory_usage structure not found");
    yajl_tree_free(root);
    return -1;
  }

#define ISTRINGS_VARIABLE(variable, path)                                      \
  uint64_t variable;                                                           \
  do {                                                                         \
    const char *value_path[] = {path, NULL};                                   \
    yajl_val value = yajl_tree_get(istrings_val, value_path, yajl_t_number);   \
    if (value == NULL) {                                                       \
      ERROR("opcache plugin: " path " field not found");                       \
      yajl_tree_free(root);                                                    \
      return -1;                                                               \
    }                                                                          \
    variable = YAJL_GET_INTEGER(value);                                        \
    DEBUG("opcache plugin: " path " = %llu", variable);                        \
  } while (0);

  ISTRINGS_VARIABLE(is_used_memory, "used_memory");
  ISTRINGS_VARIABLE(is_free_memory, "free_memory");
  ISTRINGS_VARIABLE(is_number, "number_of_strings");

  submit("memory_strings", "used", &(value_t){.gauge = is_used_memory}, 1, db);
  submit("memory_strings", "free", &(value_t){.gauge = is_free_memory}, 1, db);
  submit("objects", "strings", &(value_t){.gauge = is_number}, 1, db);

  // STATISTICS part
  yajl_val statistics_val = yajl_tree_get(root, statistics_path, yajl_t_object);
  if (statistics_val == NULL) {
    ERROR("opcache plugin: opcache_statistics structure not found");
    yajl_tree_free(root);
    return -1;
  }

#define STATISTICS_VARIABLE(variable, path)                                    \
  uint64_t variable;                                                           \
  do {                                                                         \
    const char *value_path[] = {path, NULL};                                   \
    yajl_val value = yajl_tree_get(statistics_val, value_path, yajl_t_number); \
    if (value == NULL) {                                                       \
      ERROR("opcache plugin: " path " field not found");                       \
      yajl_tree_free(root);                                                    \
      return -1;                                                               \
    }                                                                          \
    variable = YAJL_GET_INTEGER(value);                                        \
    DEBUG("opcache plugin: " path " = %llu", variable);                        \
  } while (0);

  STATISTICS_VARIABLE(num_cached_scripts, "num_cached_scripts");
  STATISTICS_VARIABLE(num_cached_keys, "num_cached_keys");
  STATISTICS_VARIABLE(max_cached_keys, "max_cached_keys");
  STATISTICS_VARIABLE(hits, "hits");
  STATISTICS_VARIABLE(misses, "misses");
  STATISTICS_VARIABLE(blacklist_misses, "blacklist_misses");

  submit("objects", "scripts", &(value_t){.gauge = num_cached_scripts}, 1, db);
  submit("cache_size", "used", &(value_t){.gauge = num_cached_keys}, 1, db);
  submit("cache_size", "free",
         &(value_t){.gauge = max_cached_keys - num_cached_keys}, 1, db);

  prev_t *prev = &db->prev;
  gauge_t ratio =
      calculate_ratio_percent(hits, misses, &prev->hits, &prev->gets);
  submit("percent", "hitratio", &(value_t){.gauge = ratio}, 1, db);

  yajl_tree_free(root);

  return 0;
}

static int cj_init(void) {
  /* Call this while collectd is still single-threaded to avoid
   * initialization issues in libgcrypt. */
  curl_global_init(CURL_GLOBAL_SSL);
  return 0;
}

void module_register(void) {
  plugin_register_complex_config("opcache", cj_config);
  plugin_register_init("opcache", cj_init);
} /* void module_register */
