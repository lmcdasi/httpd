dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(sip)

if test "$enable_sip" = "shared"; then
  sip_mods_enable=shared
elif test "$enable_sip" = "yes"; then
  sip_mods_enable=yes
else
  sip_mods_enable=most
fi

sip_objs="mod_sip.lo"
APACHE_MODULE(sip, Apache SIP module, $sip_objs, , $sip_mods_enable, [
   if  test "x$sip_mods_enable" != "xmost" && test "x$sip_mods_enable" != "x"; then
      AC_MSG_NOTICE([Using OSIP library from srclib])
      APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current -I\$(top_srcdir)/srclib/osip/include])
      APR_ADDTO(MOD_SIP_LDADD, [-L\$(top_srcdir)/srclib/osip/src/osip2/.libs -losip2 -L\$(top_srcdir)/srclib/osip/src/osipparser2/.libs -losipparser2])
   fi
])

APACHE_MODPATH_FINISH
