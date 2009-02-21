/*
 * Copyright (C) 2009 Michal Kowalski <superflouos{at}gmail[dot]com>
 *
 * Blah, blah, blah...
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  ngx_flag_t protect;
  ngx_str_t realm;
  ngx_str_t keytab;
  ngx_str_t srvcname;
} ngx_http_auth_sso_loc_conf_t;

static ngx_command_t ngx_http_auth_sso_commands[] = {

  { ngx_string("auth_sso"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
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

statix ngx_http_module_t ngx_http_auth_sso_module_ctx = {
  NULL, /* preconf */
  NULL, /* postconf */

  NULL, /* create main conf (defaults) */
  NULL, /* init main conf (what's in nginx.conf) */

  NULL, /* create server conf */
  NULL, /* merge with main */

  ngx_http_auth_sso_create_loc_conf, /* create location conf */
  ngx_http_auth_sso_merge_loc_conf /* merge with server */
};

static void *
ngx_http_auth_sso_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_auth_sso_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_sso_loc_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  return conf;
}

static char *
ngx_http_auth_pam_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_pam_loc_conf_t *prev = parent;
  ngx_http_auth_pam_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->realm, prev->realm, "LOCALDOMAIN");
  ngx_conf_merge_str_value(conf->keytab, prev->keytab, "/etc/krb5.keytab");
  ngx_conf_merge_str_value(conf->srvcname, prev->srvcname, "HTTP");

  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "protect = %i", conf->protect);
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "realm = %s", conf->realm.data);
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "keytab = %s", conf->keytab.data);
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "srvcname = %s", conf->srvcname.data);

  return NGX_CONF_OK;
}
