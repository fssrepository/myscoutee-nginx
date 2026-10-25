/* Shared, bounded edge state. No request-time IPC, geolocation or disk reads.
 */
#include <curl/curl.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/stat.h>
#include <unistd.h>

#define IP_CAP 8192
#define PROBE_CAP 64
#define VISIT_CAP 16384
#define SERVICE_CAP 32
#define INSTANCE_CAP 128
#define MSG_LEN 1000
#define PATH_LEN 200
#define SOURCE_CAP 8
#define STATE_FILE "/var/lib/nginx/myscoutee/scanner-blocked-ips.json"
#define SUMMARY_FILE "/var/lib/nginx/myscoutee/traffic-summary.json"
#define AUTO_MESSAGE "We see your scanning activity. Access denied."

typedef struct {
  u_char address[16];
  uint32_t family;
  unsigned used, manual, automatic;
  time_t window, seen, detected;
  uint64_t ban_generation;
  unsigned count;
  char message[MSG_LEN + 1], paths[3][PATH_LEN + 1];
} edge_ip;
typedef struct {
  uint64_t key;
  time_t seen;
  unsigned source, flags;
  uint64_t requests, html;
} edge_visit;
typedef struct {
  uint64_t sessions, html, requests, active, demo, login, articles;
} edge_stats;
typedef struct {
  char id[65];
  time_t seen;
  unsigned ready;
} edge_instance;
typedef struct {
  edge_ip ips[IP_CAP];
  edge_visit visits[VISIT_CAP];
  edge_stats stats[SOURCE_CAP];
  edge_instance leases[SERVICE_CAP][INSTANCE_CAP];
  time_t day, kube_checked;
  unsigned kube_known, kube_ready;
  uint64_t generation, saved, lease_configuration;
  ngx_uint_t streams;
} edge_shared;
typedef struct {
  ngx_shm_zone_t *zone;
  ngx_slab_pool_t *pool;
  edge_shared *shared;
  ngx_str_t manual_file;
  ngx_uint_t threshold, window;
  char services[SERVICE_CAP][65], tokens[SERVICE_CAP][513];
  unsigned service_count;
  unsigned kubernetes;
  char namespace[65];
} edge_conf;
typedef struct {
  ngx_flag_t public_policy;
} edge_server_conf;
typedef struct {
  ngx_uint_t action;
} edge_loc;
typedef struct {
  ngx_event_t timer;
  ngx_http_request_t *request;
  time_t started, ping;
  unsigned previous, have_previous, closed;
} edge_stream;
static edge_conf *worker_conf;
static ngx_event_t maintenance;
static time_t manual_mtime;
static long manual_nsec;
static struct stat auto_stamp;
static int auto_stamp_valid;
static off_t manual_size = -1;
static ino_t manual_inode;
extern ngx_module_t ngx_http_edge_module;
static ngx_int_t edge_postconfig(ngx_conf_t *cf);
static ngx_int_t edge_variables(ngx_conf_t *cf);
static void *edge_create_main(ngx_conf_t *cf);
static void *edge_create_server(ngx_conf_t *cf);
static char *edge_merge_server(ngx_conf_t *cf, void *parent, void *child);
static void *edge_create_loc(ngx_conf_t *cf);
static char *edge_state(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *edge_handler_directive(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);
static ngx_int_t edge_init_process(ngx_cycle_t *cycle);
static void edge_exit_process(ngx_cycle_t *cycle);
static ngx_int_t edge_handler(ngx_http_request_t *r);
static ngx_int_t edge_log(ngx_http_request_t *r);
static void edge_tick(ngx_event_t *ev);
static int refresh_manual(edge_conf *c);
static void load_stats(edge_conf *c);
static const char *source_names[SOURCE_CAP] = {
    "direct_or_unknown", "meta_paid",     "meta_campaign", "other_paid",
    "other_campaign",    "meta_referral", "meta_browser",  "other_referral"};
static ngx_command_t edge_commands[] = {
    {ngx_string("myscoutee_public_edge"), NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(edge_server_conf, public_policy), NULL},
    {ngx_string("myscoutee_edge_state"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     edge_state, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},
    {ngx_string("myscoutee_blocklist_file"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET, offsetof(edge_conf, manual_file), NULL},
    {ngx_string("myscoutee_scanner_threshold"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_conf_set_num_slot,
     NGX_HTTP_MAIN_CONF_OFFSET, offsetof(edge_conf, threshold), NULL},
    {ngx_string("myscoutee_scanner_window"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_conf_set_num_slot,
     NGX_HTTP_MAIN_CONF_OFFSET, offsetof(edge_conf, window), NULL},
    {ngx_string("myscoutee_runtime_status"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, edge_handler_directive,
     NGX_HTTP_LOC_CONF_OFFSET, 1, NULL},
    {ngx_string("myscoutee_runtime_events"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, edge_handler_directive,
     NGX_HTTP_LOC_CONF_OFFSET, 2, NULL},
    {ngx_string("myscoutee_runtime_receive"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, edge_handler_directive,
     NGX_HTTP_LOC_CONF_OFFSET, 3, NULL},
    {ngx_string("myscoutee_traffic_summary"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, edge_handler_directive,
     NGX_HTTP_LOC_CONF_OFFSET, 4, NULL},
    ngx_null_command};
static ngx_http_module_t edge_context = {edge_variables,
                                         edge_postconfig,
                                         edge_create_main,
                                         NULL,
                                         edge_create_server,
                                         edge_merge_server,
                                         edge_create_loc,
                                         NULL};
ngx_module_t ngx_http_edge_module = {NGX_MODULE_V1,
                                     &edge_context,
                                     edge_commands,
                                     NGX_HTTP_MODULE,
                                     NULL,
                                     NULL,
                                     edge_init_process,
                                     NULL,
                                     NULL,
                                     edge_exit_process,
                                     NULL,
                                     NGX_MODULE_V1_PADDING};
static void *edge_create_main(ngx_conf_t *cf) {
  edge_conf *c = ngx_pcalloc(cf->pool, sizeof(*c));
  if (!c)
    return NULL;
  c->threshold = NGX_CONF_UNSET_UINT;
  c->window = NGX_CONF_UNSET_UINT;
  return c;
}
static void *edge_create_loc(ngx_conf_t *cf) {
  return ngx_pcalloc(cf->pool, sizeof(edge_loc));
}
static void *edge_create_server(ngx_conf_t *cf) {
  edge_server_conf *c = ngx_pcalloc(cf->pool, sizeof(*c));
  if (c)
    c->public_policy = NGX_CONF_UNSET;
  return c;
}
static char *edge_merge_server(ngx_conf_t *cf, void *parent, void *child) {
  edge_server_conf *prev = parent, *conf = child;
  (void)cf;
  ngx_conf_merge_value(conf->public_policy, prev->public_policy, 0);
  return NGX_CONF_OK;
}
static char *edge_handler_directive(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf) {
  edge_loc *l = conf;
  ngx_http_core_loc_conf_t *cl =
      ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  l->action = cmd->offset;
  cl->handler = edge_handler;
  return NGX_CONF_OK;
}
static int identifier(const char *s) {
  size_t n = strlen(s);
  if (!n || n > 64)
    return 0;
  while (*s) {
    if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
          (*s >= '0' && *s <= '9') || *s == '_' || *s == '-'))
      return 0;
    s++;
  }
  return 1;
}
static int copy_json(char *dst, size_t cap, json_object *o) {
  size_t n;
  const char *s;
  if (!o || json_object_get_type(o) != json_type_string)
    return 0;
  n = json_object_get_string_len(o);
  s = json_object_get_string(o);
  if (n >= cap || strlen(s) != n) {
    return 0;
  }
  memcpy(dst, s, n + 1);
  return 1;
}
static json_object *read_json(const char *path, size_t limit) {
  struct stat st;
  int fd = open(path, O_RDONLY | O_NOFOLLOW);
  char *s;
  ssize_t n;
  json_object *o = NULL;
  json_tokener *t;
  if (fd < 0)
    return NULL;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
      (uint64_t)st.st_size > limit) {
    close(fd);
    return NULL;
  }
  s = malloc(st.st_size + 1);
  if (!s) {
    close(fd);
    return NULL;
  }
  n = read(fd, s, st.st_size);
  close(fd);
  if (n == st.st_size) {
    s[n] = 0;
    t = json_tokener_new();
    o = json_tokener_parse_ex(t, s, n);
    if (json_tokener_get_error(t) != json_tokener_success) {
      if (o)
        json_object_put(o);
      o = NULL;
    }
    if (o) {
      size_t end = json_tokener_get_parse_end(t);
      while (end < (size_t)n && (s[end] == ' ' || s[end] == '\n' ||
                                 s[end] == '\r' || s[end] == '\t'))
        end++;
      if (end != (size_t)n) {
        json_object_put(o);
        o = NULL;
      }
    }
    json_tokener_free(t);
  }
  free(s);
  return o;
}
static uint64_t hash_bytes(const void *data, size_t n, uint64_t h) {
  const u_char *p = data;
  while (n--) {
    h ^= *p++;
    h *= 1099511628211ULL;
  }
  return h ? h : 1;
}
static int address_key(struct sockaddr *sa, u_char key[16], uint32_t *family) {
  memset(key, 0, 16);
  *family = sa->sa_family;
  if (sa->sa_family == AF_INET) {
    memcpy(key, &((struct sockaddr_in *)sa)->sin_addr, 4);
    return 1;
  }
#if (NGX_HAVE_INET6)
  if (sa->sa_family == AF_INET6) {
    memcpy(key, &((struct sockaddr_in6 *)sa)->sin6_addr, 16);
    return 1;
  }
#endif
  return 0;
}
static edge_ip *find_ip(edge_conf *c, const u_char *key, uint32_t family,
                        int create) {
  unsigned i, start = (unsigned)hash_bytes(key, 16, family) % IP_CAP;
  edge_ip *oldest = NULL;
  for (i = 0; i < PROBE_CAP; i++) {
    edge_ip *p = &c->shared->ips[(start + i) % IP_CAP];
    if (p->used && p->family == family && !memcmp(p->address, key, 16))
      return p;
    if (!p->used) {
      if (!create)
        return NULL;
      oldest = p;
      break;
    }
    if (!p->manual && !p->automatic && (!oldest || p->seen < oldest->seen))
      oldest = p;
  }
  if (!create || !oldest)
    return NULL;
  memset(oldest, 0, sizeof(*oldest));
  oldest->used = 1;
  oldest->family = family;
  memcpy(oldest->address, key, 16);
  return oldest;
}
static int parse_ip(const char *s, u_char key[16], uint32_t *family) {
  memset(key, 0, 16);
  if (inet_pton(AF_INET, s, key) == 1) {
    *family = AF_INET;
    return 1;
  }
  if (inet_pton(AF_INET6, s, key) == 1) {
    *family = AF_INET6;
    return 1;
  }
  return 0;
}
static int load_bans(edge_conf *c) {
  json_object *a = read_json(STATE_FILE, 16 * 1024 * 1024);
  size_t i;
  if (!a) { struct stat st; return stat(STATE_FILE, &st) != 0 && errno == ENOENT; }
  if (json_object_get_type(a) != json_type_array || json_object_array_length(a) > IP_CAP) { json_object_put(a); return 0; }
  if (json_object_get_type(a) == json_type_array)
    for (i = 0; i < json_object_array_length(a); i++) {
      json_object *v = json_object_array_get_idx(a, i), *x, *paths;
      u_char key[16];
      uint32_t family;
      edge_ip *p;
      unsigned j;
      if (!json_object_object_get_ex(v, "ip", &x) ||
          json_object_get_type(x) != json_type_string ||
          !parse_ip(json_object_get_string(x), key, &family))
        { json_object_put(a); return 0; }
      p = find_ip(c, key, family, 1);
      if (!p) { json_object_put(a); return 0; }
      p->automatic = 1;
      if (json_object_object_get_ex(v, "detectedAt", &x))
        p->detected = json_object_get_int64(x);
      if (json_object_object_get_ex(v, "count", &x))
        p->count = json_object_get_int(x);
      if (json_object_object_get_ex(v, "paths", &paths) &&
          json_object_get_type(paths) == json_type_array)
        for (j = 0; j < 3 && j < json_object_array_length(paths); j++)
          copy_json(p->paths[j], sizeof(p->paths[j]),
                    json_object_array_get_idx(paths, j));
    }
  json_object_put(a);
  return 1;
}
static void sync_services(edge_conf *c) {
    unsigned i; uint64_t hash = 1469598103934665603ULL;
    for (i = 0; i < c->service_count; i++) hash = hash_bytes(c->services[i], strlen(c->services[i]) + 1, hash);
    ngx_shmtx_lock(&c->pool->mutex);
    if (hash != c->shared->lease_configuration) {
        memset(c->shared->leases, 0, sizeof(c->shared->leases));
        c->shared->kube_known = 0;
        c->shared->lease_configuration = hash;
    }
    ngx_shmtx_unlock(&c->pool->mutex);
}
static ngx_int_t edge_init_zone(ngx_shm_zone_t *z, void *old) {
  edge_conf *c = z->data, *previous = old;
  if (previous) {
    c->pool = previous->pool;
    c->shared = previous->shared;
    sync_services(c);
    if (!refresh_manual(c)) { ngx_log_error(NGX_LOG_EMERG, z->shm.log, 0, "invalid operator nginx blocklist"); return NGX_ERROR; }
    return NGX_OK;
  }
  c->pool = (ngx_slab_pool_t *)z->shm.addr;
  if (z->shm.exists) {
    c->shared = c->pool->data;
    sync_services(c);
    if (!refresh_manual(c)) { ngx_log_error(NGX_LOG_EMERG, z->shm.log, 0, "invalid operator nginx blocklist"); return NGX_ERROR; }
    return NGX_OK;
  }
  c->shared = ngx_slab_calloc(c->pool, sizeof(edge_shared));
  if (!c->shared)
    return NGX_ERROR;
  c->pool->data = c->shared;
  if (!load_bans(c)) { ngx_log_error(NGX_LOG_EMERG, z->shm.log, 0, "invalid saved nginx scanner bans"); return NGX_ERROR; }
  load_stats(c);
  sync_services(c);
  if (!refresh_manual(c)) { ngx_log_error(NGX_LOG_EMERG, z->shm.log, 0, "invalid operator nginx blocklist"); return NGX_ERROR; }
  return NGX_OK;
}
static char *edge_state(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  edge_conf *c = conf;
  ngx_str_t *v = cf->args->elts;
  ssize_t size = ngx_parse_size(&v[1]);
  ngx_str_t name = ngx_string("myscoutee_edge");
  (void)cmd;
  if (c->zone || size < (ssize_t)(sizeof(edge_shared) + 128 * 1024))
    return "requires one shared zone of at least 16m";
  c->zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_edge_module);
  if (!c->zone)
    return NGX_CONF_ERROR;
  c->zone->init = edge_init_zone;
  c->zone->data = c;
  return NGX_CONF_OK;
}
static ngx_int_t blocked_variable(ngx_http_request_t *r,
                                  ngx_http_variable_value_t *v,
                                  uintptr_t data) {
  edge_conf *c = ngx_http_get_module_main_conf(r, ngx_http_edge_module);
  edge_server_conf *server = ngx_http_get_module_srv_conf(r, ngx_http_edge_module);
  u_char key[16];
  uint32_t family;
  edge_ip *p;
  const char *msg = NULL;
  size_t n;
  (void)data;
  v->valid = 1;
  v->not_found = 0;
  v->no_cacheable = 0;
  v->len = 0;
  v->data = (u_char *)"";
  if (!server->public_policy || !c->shared ||
      !address_key(r->connection->sockaddr, key, &family))
    return NGX_OK;
  ngx_shmtx_lock(&c->pool->mutex);
  p = find_ip(c, key, family, 0);
  if (p) {
    if (p->manual)
      msg = p->message;
    else if (p->automatic)
      msg = AUTO_MESSAGE;
  }
  if (msg) {
    n = strlen(msg);
    v->data = ngx_pnalloc(r->pool, n);
    if (v->data) {
      memcpy(v->data, msg, n);
      v->len = n;
    } else {
      ngx_shmtx_unlock(&c->pool->mutex);
      return NGX_ERROR;
    }
  }
  ngx_shmtx_unlock(&c->pool->mutex);
  return NGX_OK;
}
static ngx_int_t edge_variables(ngx_conf_t *cf) {
  ngx_str_t name = ngx_string("myscoutee_block_message");
  ngx_http_variable_t *v = ngx_http_add_variable(cf, &name, 0);
  if (!v) {
    return NGX_ERROR;
  }
  v->get_handler = blocked_variable;
  return NGX_OK;
}
static int service_add(edge_conf *c, const char *service, const char *token) {
  unsigned i = c->service_count;
  if (i >= SERVICE_CAP || !identifier(service) || strlen(token) > 512 ||
      strlen(token) < 32)
    return 0;
  strcpy(c->services[i], service);
  strcpy(c->tokens[i], token);
  c->service_count++;
  return 1;
}
static int credentials(edge_conf *c, ngx_conf_t *cf) {
  char *raw = getenv("MYSCOUTEE_RUNTIME_STATUS_TOKENS_JSON"), *token, *path,
       *ns;
  json_object *o;
  ns = getenv("POD_NAMESPACE");
  if (ns && *ns) {
    char *services = getenv("MYSCOUTEE_RUNTIME_SERVICES"), *p, *save, *copy;
    if (!identifier(ns) || !services) {
      return 0;
    }
    strcpy(c->namespace, ns);
    c->kubernetes = 1;
    copy = strdup(services);
    if (!copy)
      return 0;
    for (p = strtok_r(copy, ",", &save); p; p = strtok_r(NULL, ",", &save))
      if (!service_add(c, p, "00000000000000000000000000000000")) {
        free(copy);
        return 0;
      }
    free(copy);
    return c->service_count > 0;
  }
  if (raw && *raw) {
    o = json_tokener_parse(raw);
    if (!o || json_object_get_type(o) != json_type_object) {
      if (o)
        json_object_put(o);
      return 0;
    }
    json_object_object_foreach(o, k, v) {
      if (json_object_get_type(v) != json_type_string ||
          !service_add(c, k, json_object_get_string(v))) {
        json_object_put(o);
        return 0;
      }
    }
    json_object_put(o);
    return c->service_count > 0;
  }
  token = getenv("MYSCOUTEE_RUNTIME_STATUS_TOKEN");
  if (token && *token)
    return service_add(c, "profilemanagement", token);
  path = getenv("MYSCOUTEE_RUNTIME_STATUS_TOKEN_FILE");
  if (path && *path) {
    char bytes[514];
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    ssize_t n;
    if (fd < 0 && errno == ENOENT && !ngx_test_config) {
      u_char random[32];
      char hex[65];
      int rnd = open("/dev/urandom", O_RDONLY);
      unsigned i;
      if (rnd < 0) {
        return 0;
      }
      n = read(rnd, random, 32);
      close(rnd);
      if (n != 32)
        return 0;
      for (i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", random[i]);
      fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0444);
      if (fd >= 0) {
        int ok = write(fd, hex, 64) == 64;
        close(fd);
        if (!ok)
          return 0;
      } else if (errno != EEXIST)
        return 0;
      fd = open(path, O_RDONLY | O_NOFOLLOW);
    }
    if (fd >= 0) {
      n = read(fd, bytes, sizeof(bytes) - 1);
      close(fd);
      if (n < 32 || n > 512)
        return 0;
      bytes[n] = 0;
      while (n > 0 && (bytes[n - 1] == '\n' || bytes[n - 1] == '\r'))
        bytes[--n] = 0;
      return service_add(c, "profilemanagement", bytes);
    }
    if (ngx_test_config)
      return 1;
    ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                       "cannot read runtime status credential");
    return 0;
  }
  /* A standalone extension image may omit readiness configuration entirely. */
  return 1;
}
static ngx_int_t edge_postconfig(ngx_conf_t *cf) {
  edge_conf *c = ngx_http_conf_get_module_main_conf(cf, ngx_http_edge_module);
  ngx_http_core_main_conf_t *m;
  ngx_http_handler_pt *h;
  ngx_conf_init_uint_value(c->threshold, 100);
  ngx_conf_init_uint_value(c->window, 600);
  if (!c->threshold || !c->window)
    return NGX_ERROR;
  if (!credentials(c, cf)) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid native runtime status configuration");
    return NGX_ERROR;
  }
  m = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  h = ngx_array_push(&m->phases[NGX_HTTP_LOG_PHASE].handlers);
  if (!h)
    return NGX_ERROR;
  *h = edge_log;
  return NGX_OK;
}
static int has(ngx_str_t s, const char *needle) {
  if (!s.data || s.len < strlen(needle)) return 0;
  return ngx_strlcasestrn(s.data, s.data + s.len, (u_char *)needle,
                          strlen(needle) - 1) != NULL;
}
static int prefix(ngx_str_t s, const char *p) {
  size_t n = strlen(p);
  return s.len >= n && !memcmp(s.data, p, n);
}
static unsigned traffic_source(ngx_http_request_t *r) {
  ngx_str_t src = ngx_null_string, medium = ngx_null_string;
  int meta, paid;
  ngx_http_arg(r, (u_char *)"utm_source", 10, &src);
  ngx_http_arg(r, (u_char *)"utm_medium", 10, &medium);
  meta = (src.len == 2 && !ngx_strncasecmp(src.data, (u_char *)"ig", 2)) ||
         has(src, "facebook") || has(src, "instagram") ||
         (src.len == 2 && !ngx_strncasecmp(src.data, (u_char *)"fb", 2)) ||
         has(src, "meta");
  paid = has(medium, "paid") || has(medium, "cpc") || has(medium, "ppc");
  if (src.len || medium.len)
    return meta ? (paid ? 1 : 2) : (paid ? 3 : 4);
  if (r->headers_in.referer &&
      (has(r->headers_in.referer->value, "instagram.com") ||
       has(r->headers_in.referer->value, "facebook.com")))
    return 5;
  if (r->headers_in.user_agent &&
      (has(r->headers_in.user_agent->value, "instagram") ||
       has(r->headers_in.user_agent->value, "fban/") ||
       has(r->headers_in.user_agent->value, "fbav/")))
    return 6;
  return r->headers_in.referer ? 7 : 0;
}
static ngx_int_t edge_log(ngx_http_request_t *r) {
  edge_conf *c = ngx_http_get_module_main_conf(r, ngx_http_edge_module);
  edge_server_conf *server = ngx_http_get_module_srv_conf(r, ngx_http_edge_module);
  u_char key[16];
  uint32_t family;
  edge_ip *p;
  ngx_http_variable_value_t *known;
  ngx_str_t name = ngx_string("myscoutee_route_known");
  ngx_str_t uri = r->unparsed_uri;
  time_t now = ngx_time();
  unsigned i, src, flags, html, active;
  uint64_t hash;
  edge_visit *v = NULL;
  edge_stats *s;
  if (!server->public_policy || r != r->main || prefix(uri, "/internal/") || !c->shared ||
      !address_key(r->connection->sockaddr, key, &family))
    return NGX_OK;
  known = ngx_http_get_variable(r, &name, ngx_hash_key(name.data, name.len));
  /* Missing static resources are nonexistent URLs too; business API 404s
   * on valid routes must not become scanner evidence. */
  unsigned missing_static = r->headers_out.status == 404 && prefix(uri, "/assets/");
  if (((known && !known->not_found && known->len == 1 && known->data[0] == '0') || missing_static) &&
      r->headers_out.status != 403) {
    ngx_shmtx_lock(&c->pool->mutex);
    p = find_ip(c, key, family, 1);
    if (p && !p->automatic) {
      if (!p->window || now - p->window >= (time_t)c->window) {
        p->window = now;
        p->count = 0;
        memset(p->paths, 0, sizeof(p->paths));
      }
      p->seen = now;
      p->count++;
      for (i = 0; i < 3; i++)
        if (!p->paths[i][0]) {
          size_t n = ngx_min(r->uri.len, PATH_LEN);
          memcpy(p->paths[i], r->uri.data, n);
          p->paths[i][n] = 0;
          break;
        }
      if (p->count >= c->threshold) {
        p->automatic = 1;
        p->detected = now;
        c->shared->generation++;
        p->ban_generation = c->shared->generation;
      }
    }
    ngx_shmtx_unlock(&c->pool->mutex);
    return NGX_OK;
  }
  if (r->headers_out.status >= 400 || prefix(uri, "/internal/") ||
      prefix(uri, "/api/runtime-status") ||
      prefix(uri, "/nginx-health") || prefix(uri, "/__landing-debug") ||
      prefix(uri, "/api/health"))
    return NGX_OK;
  html = prefix(r->headers_out.content_type, "text/html");
  if (!html && !prefix(uri, "/api/"))
    return NGX_OK;
  flags = 0;
  if (prefix(uri, "/demo") || prefix(uri, "/api/auth/demo-users")) flags |= 3;
  if (prefix(uri, "/api/auth/session/login") && r->method == NGX_HTTP_POST) flags |= 5;
  if (prefix(uri, "/article") || prefix(uri, "/api/landing/articles")) flags |= 9;
  if (prefix(uri, "/api/auth/me/profile-ext") || prefix(uri, "/api/auth/me/logout") ||
      prefix(uri, "/api/privacy/consents") || prefix(uri, "/api/game-cards/query")) flags |= 1;
  src = traffic_source(r);
  hash = hash_bytes(key, 16, family);
  if (r->headers_in.user_agent)
    hash = hash_bytes(r->headers_in.user_agent->value.data,
                      r->headers_in.user_agent->value.len, hash);
  ngx_shmtx_lock(&c->pool->mutex);
  if (c->shared->day != now / 86400) {
    memset(c->shared->stats, 0, sizeof(c->shared->stats));
    memset(c->shared->visits, 0, sizeof(c->shared->visits));
    c->shared->day = now / 86400;
  }
  for (i = 0; i < PROBE_CAP; i++) {
    edge_visit *q = &c->shared->visits[(hash + i) % VISIT_CAP];
    if (!q->key || q->key == hash || now - q->seen > 1800) {
      v = q;
      break;
    }
  }
  if (v) {
    if (v->key != hash || now - v->seen > 1800) {
      memset(v, 0, sizeof(*v));
      v->key = hash;
      v->source = src;
      c->shared->stats[src].sessions++;
    } else if (src > 0 && src <= 4 && v->source != src) {
      edge_stats *old = &c->shared->stats[v->source],
                 *next = &c->shared->stats[src];
      old->sessions--;
      next->sessions++;
      old->requests -= v->requests; next->requests += v->requests;
      old->html -= v->html; next->html += v->html;
      /* Per-visit totals move with campaign attribution. */
      if (v->flags & 1) {
        old->active--;
        next->active++;
      }
      if (v->flags & 2) {
        old->demo--;
        next->demo++;
      }
      if (v->flags & 4) {
        old->login--;
        next->login++;
      }
      if (v->flags & 8) {
        old->articles--;
        next->articles++;
      }
      v->source = src;
    }
    s = &c->shared->stats[v->source];
    s->requests++;
    s->html += html;
    v->requests++; v->html += html;
    active = (html && (v->flags & 16)) ? 1 : 0;
    flags |= active;
    if ((flags & 1) && !(v->flags & 1))
      s->active++;
    if ((flags & 2) && !(v->flags & 2))
      s->demo++;
    if ((flags & 4) && !(v->flags & 4))
      s->login++;
    if ((flags & 8) && !(v->flags & 8))
      s->articles++;
    v->flags |= flags | (html ? 16 : 0);
    v->seen = now;
  }
  ngx_shmtx_unlock(&c->pool->mutex);
  return NGX_OK;
}
static int refresh_manual(edge_conf *c) {
  struct stat st;
  json_object *o;
  edge_ip *snapshot;
  unsigned i;
  int valid = 1;
  if (!c->manual_file.len) return 1;
  if (stat((char *)c->manual_file.data, &st)) return 0;
  if (st.st_mtime == manual_mtime && st.st_size == manual_size &&
      st.st_ino == manual_inode && st.st_mtim.tv_nsec == manual_nsec)
    return 1;
  o = read_json((char *)c->manual_file.data, 8 * 1024 * 1024);
  if (!o)
    return 0;
  if (json_object_get_type(o) != json_type_object ||
      json_object_object_length(o) > IP_CAP) {
    json_object_put(o);
    return 0;
  }
  snapshot = calloc(IP_CAP, sizeof(edge_ip));
  if (!snapshot) {
    json_object_put(o);
    return 0;
  }
  /* Validate the complete update before replacing live state. */
  json_object_object_foreach(o, k, v) {
    u_char key[16];
    uint32_t family;
    char msg[MSG_LEN + 1];
    if (!parse_ip(k, key, &family) || !copy_json(msg, sizeof(msg), v) ||
        !msg[0]) {
      valid = 0;
      break;
    }
    for (i = 0; msg[i]; i++)
      if ((unsigned char)msg[i] < 32 || (unsigned char)msg[i] == 127) {
        valid = 0;
        break;
      }
    if (!valid)
      break;
  }
  if (valid) {
    ngx_shmtx_lock(&c->pool->mutex);
    memcpy(snapshot, c->shared->ips, IP_CAP * sizeof(edge_ip));
    for (i = 0; i < IP_CAP; i++)
      c->shared->ips[i].manual = 0;
    json_object_object_foreach(o, k, v) {
      u_char key[16];
      uint32_t family;
      edge_ip *p;
      parse_ip(k, key, &family);
      p = find_ip(c, key, family, 1);
      if (!p) {
        valid = 0;
        break;
      }
      p->manual = 1;
      copy_json(p->message, sizeof(p->message), v);
    }
    if (!valid)
      memcpy(c->shared->ips, snapshot, IP_CAP * sizeof(edge_ip));
    ngx_shmtx_unlock(&c->pool->mutex);
    if (valid) {
      manual_mtime = st.st_mtime;
      manual_nsec = st.st_mtim.tv_nsec;
      manual_size = st.st_size;
      manual_inode = st.st_ino;
    }
  }
  free(snapshot);
  json_object_put(o);
  return valid;
}
static int write_json(const char *path, json_object *o) {
  char tmp[256];
  const char *s = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY);
  size_t len = strlen(s), done = 0;
  int fd;
  ssize_t n;
  snprintf(tmp, sizeof(tmp), "%s.%ld.tmp", path, (long)getpid());
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (fd < 0)
    return 0;
  while (done < len) {
    n = write(fd, s + done, len - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    done += n;
  }
  if (done == len && fsync(fd) == 0) {
    close(fd);
    if (rename(tmp, path) == 0)
      return 1;
  } else
    close(fd);
  unlink(tmp);
  return 0;
}
static void load_stats(edge_conf *c) {
    json_object *o = read_json(SUMMARY_FILE, 128 * 1024), *day, *sources;
    edge_stats snapshot[SOURCE_CAP]; unsigned i;
    c->shared->day = ngx_time() / 86400;
    if (!o) return;
    memset(snapshot, 0, sizeof(snapshot));
    if (!json_object_object_get_ex(o, "dayUtc", &day) || json_object_get_int64(day) != c->shared->day ||
        !json_object_object_get_ex(o, "sources", &sources)) goto done;
    for (i = 0; i < SOURCE_CAP; i++) {
        json_object *v, *value;
        if (!json_object_object_get_ex(sources, source_names[i], &v)) goto done;
#define READ_COUNTER(key,field) \
        do { if (!json_object_object_get_ex(v,key,&value) || json_object_get_type(value) != json_type_int || json_object_get_int64(value) < 0) goto done; \
        snapshot[i].field = json_object_get_int64(value); } while(0)
        READ_COUNTER("sessions", sessions); READ_COUNTER("htmlResponses", html);
        READ_COUNTER("applicationRequests", requests); READ_COUNTER("furtherActivity", active);
        READ_COUNTER("demo", demo); READ_COUNTER("login", login); READ_COUNTER("articles", articles);
#undef READ_COUNTER
        if (snapshot[i].active > snapshot[i].sessions || snapshot[i].demo > snapshot[i].active ||
            snapshot[i].login > snapshot[i].active || snapshot[i].articles > snapshot[i].active) goto done;
    }
    memcpy(c->shared->stats, snapshot, sizeof(snapshot));
done:
    json_object_put(o);
}
static json_object *summary(edge_conf *c) {
  edge_stats snapshot[SOURCE_CAP];
  time_t day;
  unsigned i;
  json_object *o = json_object_new_object(),
              *sources = json_object_new_object();
  ngx_shmtx_lock(&c->pool->mutex);
  memcpy(snapshot, c->shared->stats, sizeof(snapshot));
  day = c->shared->day;
  ngx_shmtx_unlock(&c->pool->mutex);
  json_object_object_add(o, "dayUtc", json_object_new_int64(day));
  json_object_object_add(o, "updatedAt", json_object_new_int64(ngx_time()));
  json_object_object_add(
      o, "basis",
      json_object_new_string("HTTP activity; absence of follow-up does not "
                             "prove absence of clicks"));
  for (i = 0; i < SOURCE_CAP; i++) {
    edge_stats *s = &snapshot[i];
    json_object *v = json_object_new_object();
#define COUNT(name, value)                                                     \
  json_object_object_add(v, name, json_object_new_int64(value))
    COUNT("sessions", s->sessions);
    COUNT("htmlResponses", s->html);
    COUNT("applicationRequests", s->requests);
    COUNT("furtherActivity", s->active);
    COUNT("noFurtherActivity", s->sessions - s->active);
    COUNT("demo", s->demo);
    COUNT("login", s->login);
    COUNT("articles", s->articles);
#undef COUNT
    json_object_object_add(sources, source_names[i], v);
  }
  json_object_object_add(o, "sources", sources);
  return o;
}
/* Editing the saved findings removes bans without an nginx reload. Fresh,
 * not-yet-saved detections survive a simultaneous operator edit. */
static void refresh_saved_bans(edge_conf *c) {
    struct stat st;
    json_object *a;
    unsigned i;
    u_char (*keys)[16];
    uint32_t *families;
    size_t count;
    if (stat(STATE_FILE, &st)) return;
    if (auto_stamp_valid && st.st_ino == auto_stamp.st_ino &&
        st.st_size == auto_stamp.st_size && st.st_mtim.tv_sec == auto_stamp.st_mtim.tv_sec &&
        st.st_mtim.tv_nsec == auto_stamp.st_mtim.tv_nsec) return;
    a = read_json(STATE_FILE, 16 * 1024 * 1024);
    if (!a) return;
    if (json_object_get_type(a) != json_type_array || json_object_array_length(a) > IP_CAP) {
        json_object_put(a); return;
    }
    count = json_object_array_length(a);
    keys = calloc(count + 1, sizeof(*keys)); families = calloc(count + 1, sizeof(*families));
    if (!keys || !families) goto done;
    for (i = 0; i < count; i++) {
        json_object *v = json_object_array_get_idx(a, i), *ip;
        if (!json_object_object_get_ex(v, "ip", &ip) || json_object_get_type(ip) != json_type_string ||
            !parse_ip(json_object_get_string(ip), keys[i], &families[i])) goto done;
    }
    ngx_shmtx_lock(&c->pool->mutex);
    for (i = 0; i < IP_CAP; i++) {
        edge_ip *p = &c->shared->ips[i]; unsigned j;
        if (!p->automatic || p->ban_generation > c->shared->saved) continue;
        for (j = 0; j < count; j++) if (p->family == families[j] && !memcmp(p->address, keys[j], 16)) break;
        if (j == count) { p->automatic = 0; p->count = 0; p->window = 0; memset(p->paths, 0, sizeof(p->paths)); }
    }
    ngx_shmtx_unlock(&c->pool->mutex);
    auto_stamp = st; auto_stamp_valid = 1;
done:
    free(keys); free(families); json_object_put(a);
}
static void persist_bans(edge_conf *c) {
  edge_ip *snapshot;
  uint64_t generation;
  unsigned i, j;
  json_object *a;
  int ok;
  ngx_shmtx_lock(&c->pool->mutex);
  generation = c->shared->generation;
  if (generation == c->shared->saved) {
    ngx_shmtx_unlock(&c->pool->mutex);
    return;
  }
  ngx_shmtx_unlock(&c->pool->mutex);
  snapshot = malloc(IP_CAP * sizeof(edge_ip));
  if (!snapshot)
    return;
  ngx_shmtx_lock(&c->pool->mutex);
  memcpy(snapshot, c->shared->ips, IP_CAP * sizeof(edge_ip));
  generation = c->shared->generation;
  ngx_shmtx_unlock(&c->pool->mutex);
  a = json_object_new_array();
  for (i = 0; i < IP_CAP; i++) {
    edge_ip *p = &snapshot[i];
    char ip[INET6_ADDRSTRLEN];
    json_object *v, *paths;
    if (!p->automatic) {
      continue;
    }
    if (!inet_ntop(p->family, p->address, ip, sizeof(ip)))
      continue;
    v = json_object_new_object();
    paths = json_object_new_array();
    json_object_object_add(v, "ip", json_object_new_string(ip));
    json_object_object_add(v, "message", json_object_new_string(AUTO_MESSAGE));
    json_object_object_add(v, "count", json_object_new_int(p->count));
    json_object_object_add(v, "detectedAt", json_object_new_int64(p->detected));
    for (j = 0; j < 3; j++) {
      if (p->paths[j][0])
        json_object_array_add(paths, json_object_new_string(p->paths[j]));
    }
    json_object_object_add(v, "paths", paths);
    json_object_array_add(a, v);
  }
  ok = write_json(STATE_FILE, a);
  json_object_put(a);
  free(snapshot);
  if (ok) {
    if (stat(STATE_FILE, &auto_stamp) == 0) auto_stamp_valid = 1;
    ngx_shmtx_lock(&c->pool->mutex);
    c->shared->saved = generation;
    ngx_shmtx_unlock(&c->pool->mutex);
  } else
    ngx_log_error(NGX_LOG_ERR, maintenance.log, errno,
                  "cannot persist nginx scanner bans");
}
static unsigned runtime_value(edge_conf *c) {
  unsigned i, j, ready = c->service_count > 0;
  time_t now = ngx_time();
  if (c->kubernetes)
    return (c->shared->kube_known && now - c->shared->kube_checked < 15)
               ? (2 | c->shared->kube_ready)
               : 0;
  for (i = 0; i < c->service_count; i++) {
    unsigned up = 0;
    for (j = 0; j < INSTANCE_CAP; j++)
      if (c->shared->leases[i][j].ready &&
          now - c->shared->leases[i][j].seen < 20)
        up = 1;
    if (!up)
      ready = 0;
  }
  return 2 | ready;
}
static ngx_int_t send_json(ngx_http_request_t *r, const char *text,
                           ngx_uint_t status) {
  ngx_buf_t *b;
  ngx_chain_t chain;
  ngx_int_t rc;
  size_t n = strlen(text);
  r->headers_out.status = status;
  r->headers_out.content_length_n = n;
  ngx_str_set(&r->headers_out.content_type, "application/json");
  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    return rc;
  b = ngx_create_temp_buf(r->pool, n);
  if (!b)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  memcpy(b->pos, text, n);
  b->last += n;
  /* SSI subrequests must leave the containing page's output stream open. */
  b->last_buf = (r == r->main);
  b->last_in_chain = 1;
  chain.buf = b;
  chain.next = NULL;
  return ngx_http_output_filter(r, &chain);
}
static ngx_table_elt_t *header(ngx_http_request_t *r, const char *name) {
  ngx_list_part_t *p = &r->headers_in.headers.part;
  ngx_table_elt_t *h = p->elts;
  unsigned i;
  size_t n = strlen(name);
  for (i = 0;; i++) {
    if (i >= p->nelts) {
      if (!p->next)
        break;
      p = p->next;
      h = p->elts;
      i = 0;
    }
    if (h[i].key.len == n && !ngx_strncasecmp(h[i].key.data, (u_char *)name, n))
      return &h[i];
  }
  return NULL;
}
static int constant_equal(ngx_str_t value, const char *token) {
  size_t n = strlen(token), i;
  unsigned diff = 0;
  if (value.len != n + 7)
    return 0;
  for (i = 0; i < 7; i++) {
    diff |= value.data[i] ^ (u_char) "Bearer "[i];
  }
  for (i = 0; i < n; i++)
    diff |= value.data[i + 7] ^ (u_char)token[i];
  return diff == 0;
}
static void receive_body(ngx_http_request_t *r) {
  edge_conf *c = ngx_http_get_module_main_conf(r, ngx_http_edge_module);
  ngx_chain_t *cl;
  u_char body[1025], *dst = body;
  json_object *o, *instance, *ready;
  json_tokener *tok;
  ngx_table_elt_t *service = header(r, "X-MyScoutee-Service");
  unsigned si = 0, j, slot = INSTANCE_CAP;
  time_t now = ngx_time();
  int valid;
  for (cl = r->request_body ? r->request_body->bufs : NULL; cl; cl = cl->next) {
    size_t n = ngx_buf_size(cl->buf);
    if (cl->buf->in_file || n > (size_t)(body + 1024 - dst)) {
      ngx_http_finalize_request(r, 400);
      return;
    }
    memcpy(dst, cl->buf->pos, n);
    dst += n;
  }
  *dst = 0;
  tok = json_tokener_new();
  o = json_tokener_parse_ex(tok, (char *)body, dst - body);
  valid = o && json_tokener_get_error(tok) == json_tokener_success;
  size_t end = json_tokener_get_parse_end(tok);
  while (end < (size_t)(dst - body) && strchr(" \n\r\t", body[end]))
    end++;
  valid = valid && end == (size_t)(dst - body) &&
          json_object_get_type(o) == json_type_object &&
          json_object_object_length(o) == 2 &&
          json_object_object_get_ex(o, "instance", &instance) &&
          json_object_get_type(instance) == json_type_string &&
          json_object_object_get_ex(o, "ready", &ready) &&
          json_object_get_type(ready) == json_type_boolean &&
          identifier(json_object_get_string(instance)) &&
          strlen(json_object_get_string(instance)) ==
              (size_t)json_object_get_string_len(instance);
  json_tokener_free(tok);
  if (!valid) {
    if (o)
      json_object_put(o);
    ngx_http_finalize_request(r, 400);
    return;
  }
  for (si = 0; si < c->service_count; si++)
    if (service->value.len == strlen(c->services[si]) &&
        !memcmp(service->value.data, c->services[si], service->value.len))
      break;
  ngx_shmtx_lock(&c->pool->mutex);
  for (j = 0; j < INSTANCE_CAP; j++) {
    edge_instance *p = &c->shared->leases[si][j];
    if (!strcmp(p->id, json_object_get_string(instance))) {
      slot = j;
      break;
    }
    if (!p->id[0] || now - p->seen >= 20)
      slot = j;
  }
  if (slot < INSTANCE_CAP) {
    edge_instance *p = &c->shared->leases[si][slot];
    strcpy(p->id, json_object_get_string(instance));
    p->seen = now;
    p->ready = json_object_get_boolean(ready);
  }
  ngx_shmtx_unlock(&c->pool->mutex);
  json_object_put(o);
  ngx_http_finalize_request(r, slot < INSTANCE_CAP ? 204 : 429);
}
static void stream_cleanup(void *data) {
  edge_stream *s = data;
  edge_conf *c =
      ngx_http_get_module_main_conf(s->request, ngx_http_edge_module);
  if (s->timer.timer_set) {
    ngx_del_timer(&s->timer);
  }
  if (!s->closed) {
    s->closed = 1;
    ngx_shmtx_lock(&c->pool->mutex);
    c->shared->streams--;
    ngx_shmtx_unlock(&c->pool->mutex);
  }
}
static ngx_int_t stream_write(edge_stream *s, const char *event,
                              unsigned value) {
  char text[180];
  ngx_buf_t *b;
  ngx_chain_t chain;
  size_t n = snprintf(
      text, sizeof(text),
      "event: %s\ndata: {\"ready\":%s,\"known\":%s,\"checkedAt\":%lld}\n\n",
      event, (value & 1) ? "true" : "false", (value & 2) ? "true" : "false",
      (long long)ngx_time());
  b = ngx_create_temp_buf(s->request->pool, n);
  if (!b)
    return NGX_ERROR;
  memcpy(b->pos, text, n);
  b->last += n;
  b->flush = 1;
  chain.buf = b;
  chain.next = NULL;
  return ngx_http_output_filter(s->request, &chain);
}
static void stream_tick(ngx_event_t *ev) {
  edge_stream *s = ev->data;
  ngx_http_request_t *r = s->request;
  edge_conf *c = ngx_http_get_module_main_conf(r, ngx_http_edge_module);
  unsigned value;
  ngx_int_t rc = NGX_OK;
  time_t now = ngx_time();
  if (r->connection->error || r->connection->destroyed ||
      r->connection->buffered || r->buffered || now - s->started >= 60) {
    stream_cleanup(s);
    ngx_http_finalize_request(r, NGX_OK);
    return;
  }
  ngx_shmtx_lock(&c->pool->mutex);
  value = runtime_value(c);
  ngx_shmtx_unlock(&c->pool->mutex);
  if (!s->have_previous || value != s->previous) {
    rc = stream_write(s, "status", value);
    s->previous = value;
    s->have_previous = 1;
    s->ping = now;
  } else if (now - s->ping >= 15) {
    rc = stream_write(s, "ping", value);
    s->ping = now;
  }
  if (rc == NGX_ERROR) {
    stream_cleanup(s);
    ngx_http_finalize_request(r, NGX_ERROR);
    return;
  }
  ngx_add_timer(ev, 1000);
}
static ngx_int_t edge_handler(ngx_http_request_t *r) {
  edge_conf *c = ngx_http_get_module_main_conf(r, ngx_http_edge_module);
  edge_loc *l = ngx_http_get_module_loc_conf(r, ngx_http_edge_module);
  char text[128];
  unsigned value;
  if (!c->shared)
    return NGX_HTTP_SERVICE_UNAVAILABLE;
  if (l->action == 3) {
    ngx_table_elt_t *s = header(r, "X-MyScoutee-Service"),
                    *auth = header(r, "Authorization");
    unsigned i;
    ngx_int_t rc;
    if (r->method != NGX_HTTP_POST)
      return NGX_HTTP_NOT_ALLOWED;
    if (!s || !auth || c->kubernetes)
      return NGX_HTTP_UNAUTHORIZED;
    for (i = 0; i < c->service_count; i++)
      if (s->value.len == strlen(c->services[i]) &&
          !memcmp(s->value.data, c->services[i], s->value.len) &&
          constant_equal(auth->value, c->tokens[i]))
        break;
    if (i == c->service_count)
      return NGX_HTTP_UNAUTHORIZED;
    if (r->headers_in.content_length_n > 1024)
      return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    rc = ngx_http_read_client_request_body(r, receive_body);
    return rc >= NGX_HTTP_SPECIAL_RESPONSE ? rc : NGX_DONE;
  }
  if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
    return NGX_HTTP_NOT_ALLOWED;
  if (l->action == 4) {
    json_object *o = summary(c);
    ngx_int_t rc = send_json(
        r, json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN), 200);
    json_object_put(o);
    return rc;
  }
  ngx_shmtx_lock(&c->pool->mutex);
  value = runtime_value(c);
  ngx_shmtx_unlock(&c->pool->mutex);
  if (l->action == 2) {
    edge_stream *s;
    ngx_pool_cleanup_t *cleanup;
    ngx_int_t rc;
    ngx_shmtx_lock(&c->pool->mutex);
    if (c->shared->streams >= 256) {
      ngx_shmtx_unlock(&c->pool->mutex);
      return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
    c->shared->streams++;
    ngx_shmtx_unlock(&c->pool->mutex);
    s = ngx_pcalloc(r->pool, sizeof(*s));
    cleanup = ngx_pool_cleanup_add(r->pool, 0);
    if (!s || !cleanup) {
      ngx_shmtx_lock(&c->pool->mutex);
      c->shared->streams--;
      ngx_shmtx_unlock(&c->pool->mutex);
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    s->request = r;
    s->started = ngx_time();
    s->timer.handler = stream_tick;
    s->timer.data = s;
    s->timer.log = r->connection->log;
    cleanup->handler = stream_cleanup;
    cleanup->data = s;
    r->headers_out.status = 200;
    r->headers_out.content_length_n = -1;
    ngx_str_set(&r->headers_out.content_type, "text/event-stream");
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
      stream_cleanup(s);
      return rc;
    }
    r->main->count++;
    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_request_empty_handler;
    stream_tick(&s->timer);
    return NGX_DONE;
  }
  snprintf(text, sizeof(text), "{\"ready\":%s,\"known\":%s,\"checkedAt\":%lld}",
           (value & 1) ? "true" : "false", (value & 2) ? "true" : "false",
           (long long)ngx_time());
  return send_json(r, text, 200);
}

typedef struct {
  char *data;
  size_t length;
} kube_buffer;
static size_t kube_write(char *ptr, size_t size, size_t count, void *data) {
  kube_buffer *b = data;
  size_t n = size * count;
  char *next;
  if (n > 4 * 1024 * 1024 - b->length) {
    return 0;
  }
  next = realloc(b->data, b->length + n + 1);
  if (!next)
    return 0;
  b->data = next;
  memcpy(b->data + b->length, ptr, n);
  b->length += n;
  b->data[b->length] = 0;
  return n;
}
static void kube_refresh(edge_conf *c) {
  const char *root = "/var/run/secrets/kubernetes.io/serviceaccount/";
  char token[8193], path[256], auth[8220], url[4096], selector[2300];
  int fd;
  ssize_t n;
  unsigned i, j;
  CURL *curl;
  CURLcode result;
  long status = 0;
  struct curl_slist *headers = NULL;
  char *escaped;
  kube_buffer body = {NULL, 0};
  json_object *o = NULL, *items, *meta, *continuation;
  unsigned up[SERVICE_CAP] = {0}, valid = 0;
  snprintf(path, sizeof(path), "%stoken", root);
  fd = open(path, O_RDONLY);
  if (fd < 0)
    goto done;
  n = read(fd, token, sizeof(token) - 1);
  close(fd);
  if (n <= 0 || n == (ssize_t)sizeof(token) - 1)
    goto done;
  while (n > 0 && (token[n - 1] == '\n' || token[n - 1] == '\r')) {
    n--;
  }
  token[n] = 0;
  for (i = 0; i < (unsigned)n; i++)
    if ((unsigned char)token[i] < 32)
      goto done;
  curl = curl_easy_init();
  if (!curl)
    goto done;
  strcpy(selector, "kubernetes.io/service-name in (");
  for (i = 0; i < c->service_count; i++) {
    if (i)
      strcat(selector, ",");
    strcat(selector, c->services[i]);
  }
  strcat(selector, ")");
  escaped = curl_easy_escape(curl, selector, 0);
  if (!escaped) {
    curl_easy_cleanup(curl);
    goto done;
  }
  snprintf(url, sizeof(url),
           "https://kubernetes.default.svc/apis/discovery.k8s.io/v1/namespaces/"
           "%s/endpointslices?labelSelector=%s",
           c->namespace, escaped);
  curl_free(escaped);
  snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
  headers = curl_slist_append(headers, auth);
  headers = curl_slist_append(headers, "Accept: application/json");
  snprintf(path, sizeof(path), "%sca.crt", root);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_CAINFO, path);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 3000L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, kube_write);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
  result = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (result != CURLE_OK || status != 200 || !body.data)
    goto done;
  o = json_tokener_parse(body.data);
  if (!o || !json_object_object_get_ex(o, "items", &items) ||
      json_object_get_type(items) != json_type_array ||
      json_object_array_length(items) > 2048)
    goto done;
  if (!json_object_object_get_ex(o, "metadata", &meta))
    goto done;
  if (json_object_object_get_ex(meta, "continue", &continuation) &&
      json_object_get_string_len(continuation) > 0)
    goto done;
  for (i = 0; i < json_object_array_length(items); i++) {
    json_object *slice = json_object_array_get_idx(items, i), *metadata,
                *labels, *service, *endpoints;
    unsigned si;
    if (!json_object_object_get_ex(slice, "metadata", &metadata) ||
        !json_object_object_get_ex(metadata, "labels", &labels) ||
        !json_object_object_get_ex(labels, "kubernetes.io/service-name",
                                   &service) ||
        json_object_get_type(service) != json_type_string)
      continue;
    for (si = 0; si < c->service_count; si++)
      if (!strcmp(c->services[si], json_object_get_string(service)))
        break;
    if (si == c->service_count ||
        !json_object_object_get_ex(slice, "endpoints", &endpoints) ||
        json_object_get_type(endpoints) != json_type_array)
      continue;
    for (j = 0; j < json_object_array_length(endpoints); j++) {
      json_object *ep = json_object_array_get_idx(endpoints, j), *conditions,
                  *ready, *terminating;
      if (!json_object_object_get_ex(ep, "conditions", &conditions) ||
          !json_object_object_get_ex(conditions, "ready", &ready) ||
          json_object_get_type(ready) != json_type_boolean ||
          !json_object_get_boolean(ready))
        continue;
      if (json_object_object_get_ex(conditions, "terminating", &terminating) &&
          json_object_get_boolean(terminating))
        continue;
      up[si] = 1;
    }
  }
  valid = 1;
done:
  if (o) {
    json_object_put(o);
  }
  free(body.data);
  ngx_shmtx_lock(&c->pool->mutex);
  c->shared->kube_known = valid;
  c->shared->kube_ready = valid;
  for (i = 0; i < c->service_count; i++) {
    if (!up[i])
      c->shared->kube_ready = 0;
  }
  c->shared->kube_checked = ngx_time();
  ngx_shmtx_unlock(&c->pool->mutex);
}
#if (NGX_THREADS)
static ngx_thread_task_t *background_task;
static ngx_thread_pool_t *background_pool;
static unsigned background_busy;
static void background_work(void *data, ngx_log_t *log) {
  edge_conf *c = *(edge_conf **)data;
  static time_t last_summary, last_kube;
  time_t now = ngx_time();
  json_object *o;
  (void)log;
  refresh_manual(c);
  refresh_saved_bans(c);
  persist_bans(c);
  if (now - last_summary >= 30) {
    o = summary(c);
    if (!write_json(SUMMARY_FILE, o))
      ngx_log_error(NGX_LOG_ERR, log, errno,
                    "cannot persist nginx traffic summary");
    json_object_put(o);
    last_summary = now;
  }
  if (c->kubernetes && now - last_kube >= 5) {
    kube_refresh(c);
    last_kube = now;
  }
}
static void background_done(ngx_event_t *ev) {
  (void)ev;
  background_busy = 0;
}
#endif
static void edge_tick(ngx_event_t *ev) {
  if (ngx_exiting || ngx_quit || ngx_terminate)
    return;
#if (NGX_THREADS)
  if (!background_busy) {
    background_busy = 1;
    if (ngx_thread_task_post(background_pool, background_task) != NGX_OK)
      background_busy = 0;
  }
#endif
  ngx_add_timer(ev, 1000);
}
static ngx_int_t edge_init_process(ngx_cycle_t *cycle) {
  worker_conf =
      ngx_http_cycle_get_module_main_conf(cycle, ngx_http_edge_module);
  if (!worker_conf || !worker_conf->shared || ngx_worker != 0 ||
      ngx_process != NGX_PROCESS_WORKER)
    return NGX_OK;
#if (NGX_THREADS)
  ngx_str_t name = ngx_string("myscoutee_background");
  background_pool = ngx_thread_pool_get(cycle, &name);
  if (!background_pool) {
    ngx_log_error(
        NGX_LOG_EMERG, cycle->log, 0,
        "configure thread_pool myscoutee_background threads=1 max_queue=1;");
    return NGX_ERROR;
  }
  background_task = ngx_thread_task_alloc(cycle->pool, sizeof(edge_conf *));
  if (!background_task)
    return NGX_ERROR;
  *(edge_conf **)background_task->ctx = worker_conf;
  background_task->handler = background_work;
  background_task->event.handler = background_done;
  background_task->event.log = cycle->log;
#else
  ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                "native edge module requires nginx threads");
  return NGX_ERROR;
#endif
  memset(&maintenance, 0, sizeof(maintenance));
  maintenance.handler = edge_tick;
  maintenance.log = cycle->log;
  ngx_add_timer(&maintenance, 1);
  return NGX_OK;
}

/* A normal stop flushes the final dirty state before workers disappear. */
static void edge_exit_process(ngx_cycle_t *cycle) {
    json_object *o;
    (void)cycle;
    if (ngx_worker != 0 || !worker_conf || !worker_conf->shared || ngx_process != NGX_PROCESS_WORKER) return;
    persist_bans(worker_conf);
    o = summary(worker_conf);
    write_json(SUMMARY_FILE, o);
    json_object_put(o);
}
