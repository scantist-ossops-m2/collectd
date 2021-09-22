/**
 * collectd - src/utils/cmds/gethistory.c
 * Copyright (C) 2008       Florian octo Forster
 * Copyright (C) 2021       Pavel Rochnyak
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
 *   Pavel Rochnyak  <pavel2000 ngs.ru>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#include "utils/cmds/cmds.h"
#include "utils/cmds/gethistory.h"
#include "utils/cmds/parse_option.h"
#include "utils_cache.h"

#define print_to_socket(fh, ...)                                               \
  do {                                                                         \
    if (fprintf(fh, __VA_ARGS__) < 0) {                                        \
      WARNING("handle_gethistory: failed to write to socket #%i: %s",          \
              fileno(fh), STRERRNO);                                           \
      return -1;                                                               \
    }                                                                          \
    fflush(fh);                                                                \
  } while (0)

static int set_period(double *period, const char *value) {
  char *endptr = NULL;

  errno = 0;
  *period = strtod(value, &endptr);
  if ((errno != 0)         /* Overflow */
      || (endptr == value) /* Invalid string */
      || (endptr == NULL)  /* This should not happen */
      || (*endptr != 0))   /* Trailing chars */
    return -1;

  if (*period < 0)
    return -1;

  return 0;
} /* int set_period */

int handle_gethistory(FILE *fh, char *buffer) {
  cmd_error_handler_t err = {cmd_error_fh, fh};

  if ((fh == NULL) || (buffer == NULL))
    return -1;

  DEBUG("utils_cmd_gethistory: handle_gethistory (fh = %p, buffer = %s);",
        (void *)fh, buffer);

  char *command = NULL;
  int status = parse_string(&buffer, &command);
  if (status != 0) {
    cmd_error(CMD_PARSE_ERROR, &err, "Cannot parse command.");
    return -1;
  }
  assert(command != NULL);

  if (strcasecmp("GETHISTORY", command) != 0) {
    cmd_error(CMD_UNKNOWN_COMMAND, &err, "Unexpected command: `%s'.", command);
    return -1;
  }

  double period = 0;
  char *identifier = NULL;
  status = parse_string(&buffer, &identifier);
  if (status != 0) {
    cmd_error(CMD_PARSE_ERROR, &err, "Cannot parse identifier.");
    return -1;
  }
  assert(identifier != NULL);

  while (*buffer != 0) {
    char *key;
    char *value;

    status = parse_option(&buffer, &key, &value);
    if (status != 0) {
      cmd_error(CMD_PARSE_ERROR, &err, "Malformed option.");
      return -1;
    }

    if (strcasecmp("period", key) == 0) {
      status = set_period(&period, value);
      if (status != 0) {
        cmd_error(CMD_PARSE_ERROR, &err, "Malformed option.");
        return -1;
      }
    } else {
      cmd_error(CMD_ERROR, &err, "Unsupported option `%s'.", key);
      return -1;
    }
  }

  if (*buffer != 0) {
    cmd_error(CMD_PARSE_ERROR, &err, "Garbage after end of command: `%s'.",
              buffer);
    return -1;
  }

  if (period <= 0) {
    cmd_error(CMD_ERROR, &err, "Option `period' missing or incorrect.");
    return -1;
  }

  char *host;
  char *plugin;
  char *plugin_instance;
  char *type;
  char *type_instance;
  /* parse_identifier() modifies its first argument, returning pointers into it
   */
  char *identifier_copy = sstrdup(identifier);

  status = parse_identifier(identifier_copy, &host, &plugin, &plugin_instance,
                            &type, &type_instance, /* default_host = */ NULL);
  if (status != 0) {
    DEBUG("handle_gethistory: Cannot parse identifier `%s'.", identifier);
    cmd_error(CMD_PARSE_ERROR, &err, "Cannot parse identifier `%s'.",
              identifier);
    sfree(identifier_copy);
    return -1;
  }

  const data_set_t *ds = plugin_get_ds(type);
  if (ds == NULL) {
    DEBUG("handle_gethistory: plugin_get_ds (%s) == NULL;", type);
    cmd_error(CMD_ERROR, &err, "Type `%s' is unknown.\n", type);
    sfree(identifier_copy);
    return -1;
  }

  gauge_t *history = NULL;
  size_t num_steps = 0;
  while (1) {
    cdtime_t interval;
    status = uc_get_interval_by_name(identifier, &interval);
    if (status != 0)
      break;

    num_steps = period / CDTIME_T_TO_DOUBLE(interval);
    if (num_steps < 1)
      num_steps = 1;

    history = malloc(sizeof(*history) * num_steps * ds->ds_num);
    if (history == NULL) {
      status = -ENOMEM;
      break;
    }

    status = uc_get_history_by_name(identifier, history, num_steps, ds->ds_num);

    break;
  }

  if (status == -ENOENT) {
    print_to_socket(fh, "-1 No data found for identifier %s\n", identifier);
    sfree(identifier_copy);
    return 0;
  } else if (status != 0) {
    print_to_socket(fh, "-1 Error while looking up data: %i\n", status);
    sfree(identifier_copy);
    return -1;
  }

  print_to_socket(fh, "%i Success\n", (int)(num_steps * ds->ds_num));

  for (size_t i = 0; i < num_steps; i++)
    for (size_t j = 0; j < ds->ds_num; j++) {
      print_to_socket(fh, "%s=", ds->ds[j].name);
      if (isnan(history[i * ds->ds_num + j])) {
        print_to_socket(fh, "NaN\n");
      } else {
        print_to_socket(fh, "%12e\n", history[i * ds->ds_num + j]);
      }
    }

  sfree(identifier_copy);
  return 0;
} /* int handle_gethistory */
