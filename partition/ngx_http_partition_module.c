#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <math.h>
#include "geometry.h"

typedef struct { ngx_str_t file; void *cache; ngx_flag_t enabled; } msc_conf;
static void *msc_create(ngx_conf_t *cf);
static char *msc_init(ngx_conf_t *cf, void *data);
static char *msc_check(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static ngx_int_t msc_handler(ngx_http_request_t *r);

static ngx_command_t commands[] = {
    {ngx_string("myscoutee_partition_file"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_MAIN_CONF_OFFSET, offsetof(msc_conf,file), NULL},
    {ngx_string("myscoutee_partition_check"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
     msc_check, 0, 0, NULL}, ngx_null_command
};
static ngx_http_module_t context={NULL,NULL,msc_create,msc_init,NULL,NULL,NULL,NULL};
ngx_module_t ngx_http_partition_module={NGX_MODULE_V1,&context,commands,NGX_HTTP_MODULE,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NGX_MODULE_V1_PADDING};

static void *msc_create(ngx_conf_t *cf) { return ngx_pcalloc(cf->pool,sizeof(msc_conf)); }
static char *msc_init(ngx_conf_t *cf, void *data) {
    msc_conf *conf=data;
    char error[256];
    char *flag=getenv("AUTH_REGION_SECURITY_ENABLED");
    conf->enabled=!(flag && (!strcmp(flag,"false") || !strcmp(flag,"0")));
    if (!conf->file.len) return NGX_CONF_OK;
    if (ngx_conf_full_name(cf->cycle,&conf->file,0)!=NGX_OK) return NGX_CONF_ERROR;
    conf->cache=msc_geometry_load((char *)conf->file.data,error,sizeof(error));
    if (!conf->cache) { ngx_conf_log_error(NGX_LOG_EMERG,cf,0,"partition snapshot: %s",error); return NGX_CONF_ERROR; }
    ngx_pool_cleanup_t *cleanup=ngx_pool_cleanup_add(cf->pool,0);
    if (!cleanup) { msc_geometry_free(conf->cache); return NGX_CONF_ERROR; }
    cleanup->handler=msc_geometry_free; cleanup->data=conf->cache;
    return NGX_CONF_OK;
}
static char *msc_check(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    ngx_http_core_loc_conf_t *location=ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
    (void)cmd; (void)data;
    location->handler=msc_handler;
    return NGX_CONF_OK;
}
static ngx_int_t coordinate(ngx_http_request_t *r, char *name, double max, double *value) {
    ngx_str_t arg; char buffer[128], *end;
    if (ngx_http_arg(r,(u_char *)name,ngx_strlen(name),&arg)!=NGX_OK) return NGX_DECLINED;
    if (!arg.len || arg.len>=sizeof(buffer)) return NGX_ERROR;
    u_char *source=arg.data, *destination=(u_char *)buffer;
    ngx_unescape_uri(&destination,&source,arg.len,0); *destination=0;
    *value=strtod(buffer,&end);
    if (end==buffer || end!=(char *)destination || !isfinite(*value) || fabs(*value)>max) return NGX_ERROR;
    return NGX_OK;
}
static ngx_int_t msc_handler(ngx_http_request_t *r) {
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) return NGX_HTTP_NOT_ALLOWED;
    msc_conf *conf=ngx_http_get_module_main_conf(r,ngx_http_partition_module);
    if (!conf->cache) return NGX_HTTP_SERVICE_UNAVAILABLE;
    double latitude=0, longitude=0;
    ngx_int_t lat=coordinate(r,"latitude",90,&latitude), lon=coordinate(r,"longitude",180,&longitude);
    if (lat==NGX_ERROR || lon==NGX_ERROR || (lat==NGX_OK)!=(lon==NGX_OK)) return NGX_HTTP_BAD_REQUEST;
    ngx_int_t missing=lat==NGX_DECLINED;
    const char *key=conf->enabled && !missing ? msc_geometry_find(conf->cache,latitude,longitude):NULL;
    ngx_int_t eligible=!conf->enabled || key!=NULL;
    size_t key_length=key?ngx_strlen(key):0;
    size_t extra=key?ngx_escape_json(NULL,(u_char *)key,key_length):0;
    ngx_buf_t *buffer=ngx_create_temp_buf(r->pool,512+key_length+extra);
    if (!buffer) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    buffer->last=ngx_sprintf(buffer->last,"{\"eligible\":%s,\"partitionKey\":",eligible?"true":"false");
    if (key) { *buffer->last++='"'; buffer->last=(u_char *)ngx_escape_json(buffer->last,(u_char *)key,key_length); *buffer->last++='"'; }
    else buffer->last=ngx_sprintf(buffer->last,"null");
    buffer->last=ngx_sprintf(buffer->last,",\"message\":%s,\"securityGateEnabled\":%s,\"locationRequired\":%s}\n",
        !eligible && !missing ? "\"Login is currently unavailable from your country or region for security reasons. Please come back later.\"":"null",
        conf->enabled?"true":"false", conf->enabled && missing?"true":"false");
    r->headers_out.status=NGX_HTTP_OK;
    r->headers_out.content_length_n=buffer->last-buffer->pos;
    ngx_str_set(&r->headers_out.content_type,"application/json");
    ngx_int_t result=ngx_http_send_header(r);
    if (result==NGX_ERROR || result>NGX_OK || r->header_only) return result;
    buffer->last_buf=1;
    ngx_chain_t out={buffer,NULL};
    return ngx_http_output_filter(r,&out);
}
