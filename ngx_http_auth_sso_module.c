/*
 * Copyright (C) 2009 Michal Kowalski <superflouos{at}gmail[dot]com>
 *
 * Blah, blah, blah...
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Module handler */
static ngx_int_t ngx_http_auth_sso_handler(ngx_http_request_t*);

static void *ngx_http_auth_sso_create_loc_conf(ngx_conf_t*);
static char *ngx_http_auth_sso_merge_loc_conf(ngx_conf_t*, void*, void*);
static ngx_int_t ngx_http_auth_sso_init(ngx_conf_t*);

/* Module Configuration Struct(s) (main|srv|loc) */

typedef struct {
  ngx_flag_t protect;
  ngx_str_t realm;
  ngx_str_t keytab;
  ngx_str_t srvcname;
} ngx_http_auth_sso_loc_conf_t;

/* Module Directives */

static ngx_command_t ngx_http_auth_sso_commands[] = {

  /*
     { ngx_str_t name;
       ngx_uint_t type;
       char *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
       ngx_uint_t conf;
       ngx_uint_t offset;
       void *post; }
  */

  { ngx_string("auth_sso"),
    NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_sso_loc_conf_t, protect),
    NULL },

  { ngx_string("auth_sso_realm"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_sso_loc_conf_t, realm),
    NULL },

  { ngx_string("auth_sso_keytab"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_sso_loc_conf_t, keytab),
    NULL },

  { ngx_string("auth_sso_srvcname"),
    /* TODO change to NGX_CONF_1MORE for "http", "khttp", besides "HTTP" */
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_sso_loc_conf_t, srvcname),
    NULL },

  ngx_null_command
};

/* Module Context */

static ngx_http_module_t ngx_http_auth_sso_module_ctx = {
  NULL, /* preconf */
  ngx_http_auth_sso_init, /* postconf */

  NULL, /* create main conf (defaults) */
  NULL, /* init main conf (what's in nginx.conf) */

  NULL, /* create server conf */
  NULL, /* merge with main */

  ngx_http_auth_sso_create_loc_conf, /* create location conf */
  ngx_http_auth_sso_merge_loc_conf /* merge with server */
};

/* Module Definition */

/* really ngx_module_s /shrug */
ngx_module_t ngx_http_auth_sso_module = {
  /* ngx_uint_t ctx_index, index, spare{0-3}, version; */
  NGX_MODULE_V1, /* 0, 0, 0, 0, 0, 0, 1 */
  &ngx_http_auth_sso_module_ctx, /* void *ctx */
  ngx_http_auth_sso_commands, /* ngx_command_t *commands */
  NGX_HTTP_MODULE, /* ngx_uint_t type = 0x50545448 */
  NULL, /* ngx_int_t (*init_master)(ngx_log_t *log) */
  NULL, /* ngx_int_t (*init_module)(ngx_cycle_t *cycle) */
  NULL, /* ngx_int_t (*init_process)(ngx_cycle_t *cycle) */
  NULL, /* ngx_int_t (*init_thread)(ngx_cycle_t *cycle) */
  NULL, /* void (*exit_thread)(ngx_cycle_t *cycle) */
  NULL, /* void (*exit_process)(ngx_cycle_t *cycle) */
  NULL, /* void (*exit_master)(ngx_cycle_t *cycle) */
  NGX_MODULE_V1_PADDING /* 0, 0, 0, 0, 0, 0, 0, 0 */
  /* uintptr_t spare_hook{0-7}; */
};

static void *
ngx_http_auth_sso_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_auth_sso_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_sso_loc_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->protect = NGX_CONF_UNSET;

  /* temporary "debug" */
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		     "auth_sso: allocated loc_conf_t (0x%p)", conf);
  /* TODO find out if there is way to enable it only in debug mode */

  return conf;
}

static char *
ngx_http_auth_sso_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_sso_loc_conf_t *prev = parent;
  ngx_http_auth_sso_loc_conf_t *conf = child;

  /* "off" by default */
  ngx_conf_merge_off_value(conf->protect, prev->protect, 0);

  ngx_conf_merge_str_value(conf->realm, prev->realm, "LOCALDOMAIN");
  ngx_conf_merge_str_value(conf->keytab, prev->keytab, "/etc/krb5.keytab");
  ngx_conf_merge_str_value(conf->srvcname, prev->srvcname, "HTTP");

  /* TODO make it only shout in debug */
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "auth_sso: protect = %i",
		     conf->protect);
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "auth_sso: realm@0x%p = %s",
		     conf->realm.data, conf->realm.data);
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "auth_sso: keytab@0x%p = %s",
		     conf->keytab.data, conf->keytab.data);
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "auth_sso: srvcname@0x%p = %s",
		     conf->srvcname.data, conf->srvcname.data);

  return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_sso_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_sso_handler;

  return NGX_OK;
}

static ngx_int_t
ngx_http_auth_sso_negotiate_headers(ngx_http_request_t *r, ngx_str_t *token)
{
  r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
  if (r->headers_out.www_authenticate == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  r->headers_out.www_authenticate->hash = 1;
  r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
  r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
  r->headers_out.www_authenticate->value.len = sizeof("Negotiate") - 1;
  r->headers_out.www_authenticate->value.data = (u_char *) "Negotiate";

  return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t
ngx_http_auth_sso_handler(ngx_http_request_t *r)
{
  ngx_int_t ret;
  /*  ngx_http_auth_pam_ctx_t  *ctx; */
  ngx_http_auth_sso_loc_conf_t *alcf;

  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_sso_module);

  if (alcf->protect == 0) {
    return NGX_DECLINED;
  }

  return ngx_http_auth_sso_negotiate_headers(r, NULL);
}
