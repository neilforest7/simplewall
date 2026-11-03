from pathlib import Path
import os, subprocess, tempfile

root = Path(__file__).resolve().parents[1]

def function(path, marker):
    source = (root / path).read_text(encoding='utf-8')
    start = source.index(marker)
    brace = source.index('{', start)
    level = 1
    end = brace + 1
    while level:
        level += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

messages = (root / 'src/messages.c').read_text(encoding='utf-8')
for name, end in [('_app_command_delete', '_app_command_disable'), ('_app_command_purgeunused', '_app_command_purgetimers')]:
    section = messages[messages.index('VOID ' + name):messages.index('VOID ' + end)]
    assert '_app_revokeappassociations (hengine, ptr_app, affected_rules, TRUE)' in section
    assert section.index('_app_revokeappassociations') < section.index('_app_freeapplication') < section.index('_wfp_createrulefilters')
    assert 'if (!is_revoke_failed)\n\t\t\t\t_app_autoallow_refresh' not in section
    assert '_app_autoallow_refresh (hwnd)' in section

common = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#undef _In_
#define _In_
#undef _Inout_
#define _Inout_
#undef _Inout_opt_
#define _Inout_opt_
#define FALSE 0
#define TRUE 1
#define DBG_ARG L"test", 1
#define DATA_RULE_USER 1
#define FWP_ACTION_PERMIT 2
#define FWP_ACTION_BLOCK 3
typedef unsigned GUID; typedef unsigned long long ULONG_PTR; typedef int BOOLEAN; typedef void *HANDLE;
typedef struct { GUID items[32]; size_t count; } ARRAY, *PR_ARRAY;
typedef struct { void *items[32]; size_t count; } LIST, *PR_LIST;
typedef struct { unsigned bits; } TABLE, *PR_HASHTABLE;
typedef struct { int type, action, is_enabled, is_haveerrors; PR_HASHTABLE apps, auto_apps; PR_ARRAY guids; } RULE, *PITEM_RULE;
typedef struct { ULONG_PTR app_hash; PR_ARRAY guids; int is_haveerrors, is_enabled, is_autoallow_blocked; } APP, *PITEM_APP;
static int lock_rules, lock_autoapps, fail, calls;
static LIST allrules, *rules_list=&allrules;
static void _r_queuedlock_acquireshared(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseshared(int *l) {assert(*l);*l=0;}
static PR_ARRAY _r_obj_createarray(size_t size,int cap,void *f) {(void)size;(void)cap;(void)f;return calloc(1,sizeof(ARRAY));}
static int _r_obj_isempty(PR_ARRAY a) {return !a || !a->count;}
static void _r_obj_addarrayitems(PR_ARRAY a, GUID *items,size_t n) {for(size_t i=0;i<n;i++)a->items[a->count++]=items[i];}
static void _r_obj_cleararray(PR_ARRAY a) {if(a)a->count=0;}
static size_t _r_obj_getlistsize(PR_LIST a) {return a->count;}
static void *_r_obj_getlistitem(PR_LIST a,size_t i) {return a->items[i];}
static void _r_obj_addlistitem(PR_LIST a,void *p) {a->items[a->count++]=p;}
static void *_r_obj_reference(void *p) {return p;}
static void _r_obj_dereference(void *p) {(void)p;}
static void *_r_obj_findhashtable(PR_HASHTABLE t,ULONG_PTR h) {return (t && (t->bits & (1u<<h))) ? t : NULL;}
static int has(PR_ARRAY a, GUID g) {for(size_t i=0;i<a->count;i++)if(a->items[i]==g)return 1;return 0;}
static int _wfp_destroyfilters_array_silent(void *h,PR_ARRAY a,const wchar_t *f,int line) {
 (void)h;(void)f;(void)line;calls++; assert(!lock_rules && !lock_autoapps); assert(!has(a,4));
 if (fail) { return 0; }
 a->count=0;
 return 1;
}
'''
helper_tests = r'''
int main(void) {
 ARRAY appids={{1},1}, autoids={{2},1}, manualids={{3},1}, blockids={{4},1};
 TABLE none={0}, member={1u<<1};
 APP app={1,&appids,0,1,0};
 RULE automatic={1,2,1,0,&none,&member,&autoids}, manual={1,2,1,0,&member,&none,&manualids}, block={1,3,1,0,&member,&none,&blockids};
 LIST affected={0};allrules.items[0]=&automatic;allrules.items[1]=&manual;allrules.items[2]=&block;allrules.count=3;
 fail=1; assert(!_app_revokeappassociations(NULL,&app,&affected,TRUE));
 assert(app.is_haveerrors && appids.count==1 && autoids.count==1 && manualids.count==1 && blockids.count==1 && affected.count==3);
 affected.count=0;fail=0;assert(_app_revokeappassociations(NULL,&app,&affected,TRUE));
 assert(!appids.count && !autoids.count && !manualids.count && blockids.count==1 && affected.count==3);
 appids.count=autoids.count=manualids.count=1;affected.count=0;
 assert(_app_revokeappassociations(NULL,&app,&affected,FALSE));
 assert(!appids.count && !autoids.count && manualids.count==1 && blockids.count==1 && affected.count==1);
 assert(calls==3 && !lock_rules && !lock_autoapps);
 puts("associated permit revocation and block retention passed");return 0;
}
'''
timer_stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <wchar.h>
#undef _Inout_
#define _Inout_
#undef _Inout_opt_
#define _Inout_opt_
#define CALLBACK
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define DBG_ARG L"test",1
#define TRUE 1
#define FALSE 0
#define S_OK 0
#define S_FALSE 1
#define COINIT_APARTMENTTHREADED 1
#define COINIT_DISABLE_OLE1DDE 2
#define PR_UPDATE_TYPE 1
#define PR_UPDATE_FORCE 2
#define NIIF_INFO 1
#define NIIF_NOSOUND 2
#define IDS_STATUS_TIMER_DONE 1
#define RTL_NUMBER_OF(x) (sizeof(x)/sizeof((x)[0]))
typedef int BOOLEAN; typedef int HRESULT; typedef unsigned ULONG; typedef uintptr_t ULONG_PTR;
typedef void VOID; typedef void *PVOID; typedef wchar_t WCHAR; typedef void *HANDLE; typedef void *HWND; typedef void *PTP_CALLBACK_INSTANCE; typedef void *PTP_TIMER;
typedef struct {long long QuadPart;} LARGE_INTEGER;
typedef struct {int count;} ARRAY,*PR_ARRAY;
typedef struct {void *htimer;long long timer;int is_enabled,is_haveerrors,type;uintptr_t app_hash;ARRAY *guids;} APP,*PITEM_APP;
typedef void *PR_STRING;
static int lock_autoallow,fail,retries,warnings,saves,updates,removed,uninit,notification,missing;
static long long now=100;static APP app;static ARRAY ids;static int timer_handle;static int GUID_TrayIcon;
static int CoInitializeEx(void *p,int flags) {(void)p;(void)flags;return S_OK;}
static void CoUninitialize(void) {uninit++;}
static void *_r_app_gethwnd(void) {return NULL;}
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static APP *_app_getappitem(uintptr_t h) {(void)h;assert(lock_autoallow);return missing?NULL:&app;}
static long long _r_unixtime_now(void) {return now;}
static void *_wfp_getenginehandle(void) {return NULL;}
static int _wfp_destroyfilters_array_silent(void *h,ARRAY *a,const wchar_t *file,int line) {(void)h;(void)file;(void)line;assert(lock_autoallow);if(fail)return 0;a->count=0;return 1;}
static void TpSetTimer(void *t,LARGE_INTEGER *due,int p,int w) {(void)t;(void)p;(void)w;assert(lock_autoallow && due->QuadPart==-300000000LL);retries++;}
static void _app_timer_reset(HWND h,APP *a) {(void)h;assert(lock_autoallow);a->timer=0;a->is_enabled=0;a->is_haveerrors=0;}
static void _app_timer_remove(APP *a) {assert(lock_autoallow);a->htimer=NULL;removed++;}
static void _app_listview_updateitemby_param(HWND h,uintptr_t p,int b) {(void)h;(void)p;(void)b;assert(!lock_autoallow);updates++;}
static void _app_listview_updateby_id(HWND h,int a,int b) {(void)h;(void)a;(void)b;assert(!lock_autoallow);}
static void _app_profile_save(HWND h) {(void)h;assert(!lock_autoallow);saves++;}
static void _wfp_warnruleupdate(HWND h) {(void)h;assert(!lock_autoallow);warnings++;}
static int _r_config_getboolean(const wchar_t *s,int d) {(void)s;(void)d;return notification;}
static PR_STRING _app_getappdisplayname(APP *a,int b) {(void)a;(void)b;return NULL;}
static const wchar_t *_r_obj_getstringorempty(PR_STRING s) {(void)s;return L"";}
static const wchar_t *_r_app_getname(void) {return L"";}
static void _r_str_printf(wchar_t *b,size_t n,const wchar_t *f,...) {(void)b;(void)n;(void)f;}
static const wchar_t *_r_locale_getstring(int n) {(void)n;return L"";}
static void _r_tray_popup(HWND h,void *g,int i,wchar_t *b,const wchar_t *s) {(void)h;(void)g;(void)i;(void)b;(void)s;}
static void _r_obj_dereference(void *p) {(void)p;}
'''
timer_tests = r'''
int main(void) {
 ids.count=1;app.htimer=&timer_handle;app.timer=100;app.is_enabled=1;app.guids=&ids;
 fail=1;_app_timer_callback(NULL,(void*)1,&timer_handle);
 assert(app.is_enabled && app.timer==100 && app.htimer==&timer_handle && app.is_haveerrors && ids.count==1);
 assert(retries==1 && warnings==1 && saves==1 && updates==1 && !removed && !lock_autoallow);
 fail=0;_app_timer_callback(NULL,(void*)1,&timer_handle);
 assert(!app.is_enabled && !app.timer && !app.htimer && !ids.count && removed==1);
 assert(warnings==1 && saves==2 && updates==2 && uninit==2 && !lock_autoallow);
 _app_timer_callback(NULL,(void*)1,&timer_handle);assert(saves==2 && uninit==3);
 puts("timer revoke failure, deadline preservation, retry and success passed");return 0;
}
'''

checkbox_stubs = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#undef _In_
#define _In_
#define VOID void
#define TRUE 1
#define FALSE 0
#define INT_ERROR -1
#define IDM_CHECK 1
#define IDC_APPS_PROFILE 10
#define IDC_APPS_UWP 12
#define IDC_RULES_BLOCKLIST 20
#define IDC_RULES_CUSTOM 22
#define DBG_ARG L"test",1
#define PR_UPDATE_FORCE 1
typedef int BOOLEAN;typedef int INT;typedef uintptr_t ULONG_PTR;typedef void *HANDLE;typedef void *HWND;
typedef struct {int count;} ARRAY,*PR_ARRAY;
typedef struct {int is_enabled,is_autoallow_blocked,is_haveerrors,timer;ARRAY *guids;} APP,*PITEM_APP;
typedef struct {int is_enabled,is_haveerrors;ARRAY *guids;} RULE,*PITEM_RULE;
typedef struct {void *items[4];int count;} LIST,*PR_LIST;
typedef struct {int listview_id;} CONTEXT;
static int lock_autoallow, mode=10, warnings, saves, rebuilds;
static APP apps[2];static RULE ruleitems[2];static ARRAY ids[2];static CONTEXT ctx;
static CONTEXT *_app_listview_getcontext(HWND h,int n) {(void)h;(void)n;ctx.listview_id=mode;return &ctx;}
static int _r_listview_getnextselected(HWND h,int id,int i) {(void)h;(void)id;return i<1?i+1:INT_ERROR;}
static uintptr_t _app_listview_getitemcontext(HWND h,int id,int i) {(void)h;(void)id;return (uintptr_t)i;}
static APP *_app_getappitem(uintptr_t i) {return &apps[i];}
static RULE *_app_getrulebyid(uintptr_t i) {return &ruleitems[i];}
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static PR_LIST _r_obj_createlist(int n,void *f) {(void)n;(void)f;return calloc(1,sizeof(LIST));}
static void _r_obj_addlistitem(PR_LIST l,void *p) {l->items[l->count++]=p;}
static void *_r_obj_reference(void *p) {return p;}
static void _r_obj_dereference(void *p) {(void)p;}
static int _r_obj_isempty2(PR_LIST l) {return !l->count;}
static int _app_revokeappassociations(void *h,APP *a,PR_LIST l,int m) {(void)h;(void)l;(void)m;assert(lock_autoallow);if(a==&apps[0]){a->is_haveerrors=1;return 0;}a->guids->count=0;return 1;}
static void _app_timer_reset(HWND h,APP *a) {(void)h;assert(lock_autoallow);a->timer=0;a->is_enabled=0;}
static int _wfp_isfiltersinstalled(void) {return 1;}
static void *_wfp_getenginehandle(void) {assert(!lock_autoallow);return NULL;}
static int _wfp_createappfilters(void *h,PR_LIST l,const wchar_t *f,int n,int t) {(void)h;(void)l;(void)f;(void)n;(void)t;assert(!lock_autoallow);rebuilds++;return 1;}
static int _wfp_createrulefilters(void *h,PR_LIST l,const wchar_t *f,int n,int t) {(void)h;(void)l;(void)f;(void)n;(void)t;assert(!lock_autoallow);rebuilds++;return 1;}
static int _wfp_destroyfilters_array_silent(void *h,ARRAY *a,const wchar_t *f,int n) {(void)h;(void)f;(void)n;assert(lock_autoallow);if(a==&ids[0])return 0;a->count=0;return 1;}
static void _app_ruleenable(RULE *r,int value,int cfg) {(void)cfg;assert(lock_autoallow);r->is_enabled=value;}
static void _app_notify_freeobject(void *h,APP *a) {(void)h;(void)a;}
static void _app_autoallow_refresh(HWND h) {(void)h;assert(!lock_autoallow);}
static void _app_listview_lock(HWND h,int id,int b) {(void)h;(void)id;(void)b;}
static void _app_setappiteminfo(HWND h,int id,int i,APP *a) {(void)h;(void)id;(void)i;(void)a;}
static void _app_setruleiteminfo(HWND h,int id,int i,RULE *r,int b) {(void)h;(void)id;(void)i;(void)r;(void)b;}
static void _app_listview_updateby_id(HWND h,int id,int f) {(void)h;(void)id;(void)f;}
static void _app_profile_save(HWND h) {(void)h;assert(!lock_autoallow);saves++;}
static void _wfp_warnruleupdate(HWND h) {(void)h;assert(!lock_autoallow);warnings++;}
"""
checkbox_tests = r"""
int main(void) {
 ids[0].count=ids[1].count=1;
 apps[0]=(APP){1,0,0,99,&ids[0]};apps[1]=(APP){1,0,0,99,&ids[1]};
 _app_command_checkbox(NULL,0);
 assert(apps[0].is_enabled && !apps[0].is_autoallow_blocked && apps[0].timer==99 && ids[0].count==1);
 assert(!apps[1].is_enabled && apps[1].is_autoallow_blocked && !apps[1].timer && !ids[1].count);
 assert(saves==1 && warnings==1 && !lock_autoallow);
 mode=20;ids[0].count=ids[1].count=1;ruleitems[0]=(RULE){1,0,&ids[0]};ruleitems[1]=(RULE){1,0,&ids[1]};
 _app_command_checkbox(NULL,0);
 assert(ruleitems[0].is_enabled && ruleitems[0].is_haveerrors && ids[0].count==1);
 assert(!ruleitems[1].is_enabled && !ids[1].count);
 assert(saves==2 && warnings==2 && !lock_autoallow);
 puts("batch disable failure preserves state and timers; other items succeed");return 0;
}
"""

profile_source = (root / 'src/profile.c').read_text(encoding='utf-8')
getter_start = profile_source.index('case INFO_HASH:')
getter_end = profile_source.index('case INFO_TIMESTAMP:', getter_start)
setter_start = profile_source.index('case INFO_HASH:', profile_source.index('VOID _app_setappinfo ('))
setter_end = profile_source.index('case INFO_TIMESTAMP:', setter_start)
hash_source = ('static int get_hash(APP *ptr_app,void *buffer,size_t length) { switch(1) {\n' +
               profile_source[getter_start:getter_end] + '} return 0;}\n' +
               'static void set_hash(APP *ptr_app,void *value) { switch(1) {\n' +
               profile_source[setter_start:setter_end] + '} }\n')
hash_stubs = r"""
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define INFO_HASH 1
#define TRUE 1
#define FALSE 0
typedef void *PVOID;typedef struct {void *hash;} APP;
static int lock_apps, reads, writes;
static void _r_queuedlock_acquireshared(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseshared(int *l) {assert(*l==1);*l=0;}
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=2;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l==2);*l=0;}
static void *_r_obj_referencesafe(void *p) {assert(lock_apps==1);reads++;return p;}
static void _r_obj_movereference(void **p,void *v) {assert(lock_apps==2);writes++;*p=v;}
#define RtlCopyMemory memcpy
"""
hash_tests = r"""
int main(void) {int one,two;void *result=NULL;APP app={&one};
 assert(get_hash(&app,&result,sizeof(result)) && result==&one && reads==1);
 set_hash(&app,&two);assert(app.hash==&two && writes==1);
 result=NULL;assert(get_hash(&app,&result,sizeof(result)) && result==&two && !lock_apps);
 puts("profile hash snapshots and writes share lock_apps");return 0;}
"""

timer_state_stubs = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#undef _In_
#define _In_
#define TRUE 1
#define FALSE 0
typedef int BOOLEAN;typedef struct {void *htimer;long long timer;} APP,*PITEM_APP;
static int IsThreadpoolTimerSet(void *t) {(void)t;return 0;}
"""
timer_state_tests = r"""
int main(void) {int handle;APP app={&handle,42};
 assert(_app_istimerset(&app));app.timer=0;assert(!_app_istimerset(&app));
 app.timer=42;app.htimer=NULL;assert(_app_istimerset(&app));
 puts("fired timer remains visible for profile save");return 0;}
"""


notification_source = function('src/notifications.c', 'BOOLEAN _app_notify_command (')
notification_stubs = r"""
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#undef _In_
#undef _In_opt_
#define _In_
#define _In_opt_
#define IDC_ALLOW_BTN 1
#define IDC_BLOCK_BTN 2
#define IDM_DISABLENOTIFICATIONS 3
#define TRUE 1
#define FALSE 0
#define PR_UPDATE_TYPE 1
#define DBG_ARG L"test",1
typedef int BOOLEAN;typedef int INT;typedef long long LONG64;typedef uintptr_t ULONG_PTR;
typedef void *HWND;typedef void *HANDLE;typedef void *PTP_TIMER;
typedef struct {int is_enabled,is_autoallow_blocked,is_silent,is_haveerrors,type;long long timer,last_notify;void *htimer;} APP,*PITEM_APP;
typedef struct {int count;} LIST,*PR_LIST;
static int lock_autoallow, timers, updates, warnings, frees, saves, refreshes, app_builds, rule_builds;
static int fail_revoke, fail_rule, fail_app, fail_timer, add_affected=1;
static APP app;static LIST lists[2];static int list_index;
static ULONG_PTR _app_notify_getapp_id(HWND h) {(void)h;return 7;}
static APP *_app_getappitem(ULONG_PTR h) {(void)h;return &app;}
static void _r_obj_dereference(void *p) {(void)p;}
static PR_LIST _r_obj_createlist(int n,void *f) {(void)n;(void)f;LIST *l=&lists[list_index++%2];l->count=0;return l;}
static void _r_obj_addlistitem(PR_LIST l,void *p) {(void)p;l->count++;}
static int _r_obj_isempty2(PR_LIST l) {return !l->count;}
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static int _app_revokeappassociations(void *h,APP *a,PR_LIST l,int include) {(void)h;assert(lock_autoallow && a==&app && !include);if(fail_revoke)return 0;l->count=add_affected;return 1;}
static void _app_timer_set(void *h,APP *a,long long seconds) {assert(!h && lock_autoallow && a->is_enabled && seconds>0);timers++;if(fail_timer){a->is_haveerrors=1;return;}a->htimer=a;a->timer=seconds;}
static int _wfp_isfiltersinstalled(void) {return 1;}
static void *_wfp_getenginehandle(void) {assert(!lock_autoallow);return NULL;}
static int _wfp_createappfilters(void *h,LIST *l,const wchar_t *f,int line,int tx) {(void)h;(void)l;(void)f;(void)line;(void)tx;assert(!lock_autoallow);app_builds++;return !fail_app;}
static int _wfp_createrulefilters(void *h,LIST *l,const wchar_t *f,int line,int tx) {(void)h;(void)l;(void)f;(void)line;(void)tx;assert(!lock_autoallow);rule_builds++;return !fail_rule;}
static void *_r_app_gethwnd(void) {return NULL;}
static void _app_autoallow_refresh(HWND h) {(void)h;assert(!lock_autoallow);refreshes++;}
static void _app_listview_updateitemby_param(HWND h,ULONG_PTR hash,int b) {(void)h;(void)hash;(void)b;assert(!lock_autoallow);updates++;}
static void _app_listview_updateby_id(HWND h,int type,int flags) {(void)h;(void)type;(void)flags;assert(!lock_autoallow);}
static void _wfp_warnruleupdate(HWND h) {(void)h;assert(!lock_autoallow);warnings++;}
static void _app_notify_freeobject(HWND h,APP *a) {(void)h;(void)a;assert(!lock_autoallow);frees++;}
static long long _r_unixtime_now(void) {return 100;}
static void _app_profile_save(HWND h) {(void)h;assert(!lock_autoallow);saves++;}
"""
notification_tests = r"""
int main(void) {int h;app=(APP){1,0,0,0,1,99,5,&h};
 fail_revoke=1;assert(!_app_notify_command(NULL,IDC_BLOCK_BTN,0));
 assert(app.is_enabled && !app.is_autoallow_blocked && !app.is_silent && app.timer==99 && app.htimer==&h);
 assert(warnings==1 && !frees && !rule_builds && updates==1 && saves==1);
 fail_revoke=0;fail_rule=1;assert(!_app_notify_command(NULL,IDC_BLOCK_BTN,0));
 assert(app.is_enabled && !app.is_autoallow_blocked && !app.is_silent && app.timer==99 && app.htimer==&h);
 assert(warnings==2 && !frees && rule_builds==1 && app_builds==1 && refreshes==1);
 fail_rule=0;assert(_app_notify_command(NULL,IDC_BLOCK_BTN,0));
 assert(!app.is_enabled && app.is_autoallow_blocked && app.is_silent && app.timer==99 && frees==1);
 assert(_app_notify_command(NULL,IDC_ALLOW_BTN,60));
 assert(app.is_enabled && !app.is_autoallow_blocked && !app.is_silent && app.timer==60 && timers==1 && frees==2);
 app.is_enabled=0;app.is_autoallow_blocked=1;app.is_silent=1;app.htimer=NULL;app.timer=0;fail_timer=1;
 assert(!_app_notify_command(NULL,IDC_ALLOW_BTN,60));
 assert(!app.is_enabled && app.is_autoallow_blocked && app.is_silent && !app.timer && !app.htimer && warnings==3 && frees==2);
 assert(!lock_autoallow && updates==5 && saves==5);
 puts("notification revoke, rebuild and timer failures preserve selection and timer");return 0;}
"""

init_source = (function('src/listview.c', 'VOID _app_listview_additems (') + '\n' +
               function('src/packages.c', 'static VOID _app_package_populatelist ('))
init_stubs = r"""
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#undef _In_
#define _In_
#define VOID void
#define DATA_APP_REGULAR 1
#define DATA_APP_SERVICE 2
#define DATA_APP_UWP 3
typedef int BOOLEAN;typedef int ENUM_TYPE_DATA;typedef void *HWND;typedef long long LONG64;typedef uintptr_t ULONG_PTR;
typedef struct {uintptr_t app_hash;int type;long long timer;void *htimer;} APP,*PITEM_APP;
typedef struct {int unused;} RULE,*PITEM_RULE;
typedef struct {void *items[8];size_t count;} LIST,*PR_LIST;
static int lock_apps,lock_autoallow,lock_rules,added,timers,missing,fail_timer,warnings;static APP apps[3];static LIST allrules,*rules_list=&allrules;
static int dummy;static void *apps_table=&dummy;static long long now=10;
static void _r_queuedlock_acquireshared(int *l) {assert(!*l);if(l==&lock_apps)assert(!lock_autoallow);*l=1;}
static void _r_queuedlock_releaseshared(int *l) {assert(*l);*l=0;}
static void _r_queuedlock_acquireexclusive(int *l) {assert(l==&lock_autoallow && !*l && !lock_apps);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(l==&lock_autoallow && *l && !lock_apps);*l=0;}
static LIST *_r_obj_createlist(int n,void *f) {(void)n;(void)f;return calloc(1,sizeof(LIST));}
static void _r_obj_dereference(void *p) {(void)p;}
static void *_r_obj_reference(void *p) {return p;}
static void _r_obj_addlistitem(LIST *l,void *p) {l->items[l->count++]=p;}
static size_t _r_obj_getlistsize(LIST *l) {return l->count;}
static void *_r_obj_getlistitem(LIST *l,size_t i) {return l->items[i];}
static int _r_obj_enumhashtablepointer(void *table,APP **out,void *unused,uintptr_t *key) {(void)table;(void)unused;assert(lock_apps);if(*key>=3)return 0;*out=&apps[(*key)++];return 1;}
static APP *_app_getappitem(uintptr_t hash) {assert(lock_autoallow && !lock_apps);return missing==(int)hash?NULL:&apps[hash-1];}
static void _app_listview_addappitem(HWND h,APP *a) {(void)h;(void)a;assert(!lock_apps && !lock_autoallow);added++;}
static void _app_listview_addruleitem(HWND h,RULE *r,uintptr_t i,int f) {(void)h;(void)r;(void)i;(void)f;}
static long long _r_unixtime_now(void) {return now;}
static void _app_timer_set(HWND h,APP *a,long long seconds) {assert(!h && lock_autoallow && !lock_apps && seconds>0);timers++;if(!fail_timer){a->htimer=&dummy;a->timer=now+seconds;}}
static void _wfp_warnruleupdate(HWND h) {(void)h;assert(!lock_autoallow && !lock_apps);warnings++;}
#define FALSE 0
#define TRUE 1
"""
init_tests = r"""
int main(void) {apps[0]=(APP){1,1,5,NULL};apps[1]=(APP){2,2,20,NULL};apps[2]=(APP){3,3,30,&dummy};
 _app_listview_additems(NULL);assert(added==3 && timers==2 && apps[0].timer==5 && apps[1].timer==20 && apps[2].timer==30);
 assert(!lock_apps && !lock_autoallow && !lock_rules);
 apps[1].htimer=NULL;missing=2;_app_package_populatelist(NULL,DATA_APP_SERVICE);
 assert(added==4 && timers==2 && !apps[1].htimer && !lock_apps && !lock_autoallow);
 missing=0;_app_package_populatelist(NULL,DATA_APP_SERVICE);
 assert(added==5 && timers==3 && apps[1].timer==20 && apps[1].htimer && !lock_apps && !lock_autoallow);
 apps[1].htimer=NULL;fail_timer=1;_app_package_populatelist(NULL,DATA_APP_SERVICE);
 assert(added==6 && timers==4 && apps[1].timer==20 && !apps[1].htimer && warnings==1 && !lock_autoallow && !lock_apps);
 puts("timer initialization preserves deadlines and respects lock order");return 0;}
"""

timer_alloc_stubs = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#undef _In_
#undef _Inout_
#undef _In_opt_
#define _In_
#define _Inout_
#define _In_opt_
#define VOID void
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(s) ((s)>=0)
typedef int BOOLEAN;typedef long long LONG64;typedef long NTSTATUS;typedef void *HWND;typedef void *PVOID;typedef void *PTP_TIMER;
typedef struct {long long value;} FILETIME;typedef struct {long long QuadPart;} LARGE_INTEGER;
typedef struct {PTP_TIMER htimer;uintptr_t app_hash;long long timer;int is_enabled,is_haveerrors;} APP,*PITEM_APP;
static int fail_alloc=1,dummy,lock_autoallow=1,updates;
static void _app_timer_callback(void *a,void *b,void *c) {(void)a;(void)b;(void)c;}
static void _app_timer_reset(HWND h,APP *a) {(void)h;a->timer=0;a->is_enabled=0;}
static long long _r_unixtime_now(void) {return 100;}
static void _r_unixtime_to_filetime(long long t,FILETIME *f) {f->value=t;}
static void _r_calc_filetime2largeinteger(FILETIME *f,LARGE_INTEGER *l) {l->QuadPart=f->value;}
static void TpSetTimer(PTP_TIMER t,LARGE_INTEGER *l,int p,int w) {(void)t;(void)l;(void)p;(void)w;assert(lock_autoallow);}
static NTSTATUS TpAllocTimer(PTP_TIMER *p,void (*cb)(void*,void*,void*),void *ctx,void *env) {(void)cb;(void)ctx;(void)env;assert(lock_autoallow);if(fail_alloc)return -1;*p=&dummy;return 0;}
static void _app_listview_updateitemby_param(HWND h,uintptr_t hash,int b) {(void)h;(void)hash;(void)b;updates++;}
"""
timer_alloc_tests = r"""
int main(void) {APP app={NULL,1,75,1,0};_app_timer_set(NULL,&app,30);
 assert(app.is_enabled && app.timer==75 && !app.htimer && app.is_haveerrors);
 fail_alloc=0;_app_timer_set(NULL,&app,30);assert(app.is_enabled && app.timer==130 && app.htimer && !updates);
 puts("failed timer allocation preserves the previous application state");return 0;}
"""

for stubs, source, tests in [
    (common, function('src/profile.c', 'BOOLEAN _app_revokeappassociations ('), helper_tests),
    (checkbox_stubs, function('src/messages.c', 'VOID _app_command_checkbox ('), checkbox_tests),
    (timer_stubs, function('src/timer.c', 'VOID CALLBACK _app_timer_callback ('), timer_tests),
    (timer_state_stubs, function('src/timer.c', 'BOOLEAN _app_istimerset ('), timer_state_tests),
    (timer_alloc_stubs, function('src/timer.c', 'VOID _app_timer_set ('), timer_alloc_tests),
    (hash_stubs, hash_source, hash_tests),
    (notification_stubs, notification_source, notification_tests),
    (init_stubs, init_source, init_tests),
]:
    with tempfile.TemporaryDirectory(prefix='simplewall-security-') as directory:
        source_path = Path(directory) / 'test.c'
        executable = Path(directory) / ('test.exe' if os.name == 'nt' else 'test')
        source_path.write_text(stubs + source + tests, encoding='utf-8')
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(source_path), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
print('partial deletion rebuild call paths passed')
