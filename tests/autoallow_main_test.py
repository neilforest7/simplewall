from pathlib import Path
import os,subprocess,tempfile
root = Path(__file__).resolve().parents[1]
s=(root/'src/main.c').read_text(); start=s.index('case LVN_ITEMCHANGED:',s.index('INT_PTR CALLBACK DlgProc'))
a=s.index('_r_queuedlock_acquireexclusive (&lock_autoallow);',start); b=s.index('is_changed = TRUE;',a); app=s[a:b]
a=s.index('_r_queuedlock_acquireexclusive (&lock_autoallow);',b); b=s.index('is_changed = TRUE;',a); rule=s[a:b]
stubs=r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#ifdef _In_
#undef _In_
#endif
#define TRUE 1
#define FALSE 0
#define DBG_ARG L"test", 1
typedef int BOOLEAN; typedef void *HANDLE; typedef void *HWND;
typedef struct {int is_enabled,is_autoallow_blocked,is_haveerrors,timer;} APP, *PITEM_APP;
typedef struct {int is_enabled,is_haveerrors;} RULE, *PITEM_RULE;
typedef struct {int count;} LIST, *PR_LIST;
typedef struct {int iItem;} NM;
static int lock_autoallow, fail, installed=1, warnings, refreshes, ui, timer_resets, frees, calls;
static LIST list;
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static int _wfp_isfiltersinstalled(void) {return installed;}
static void *_wfp_getenginehandle(void) {return NULL;}
static PR_LIST _r_obj_createlist(int n,void *f) {(void)n;(void)f;return &list;}
static void _r_obj_addlistitem(PR_LIST l,void *x) {(void)l;(void)x;}
static void _r_obj_dereference(void *p) {(void)p;}
static int _wfp_createappfilters(HANDLE h,PR_LIST l,const wchar_t *f,int n,int t) {(void)h;(void)l;(void)f;(void)n;(void)t;assert(!lock_autoallow);calls++;return !fail;}
static int _wfp_createrulefilters(HANDLE h,PR_LIST l,const wchar_t *f,int n,int t) {(void)h;(void)l;(void)f;(void)n;(void)t;assert(!lock_autoallow);calls++;return !fail;}
static void _wfp_warnruleupdate(HWND h) {(void)h;assert(!lock_autoallow);warnings++;}
static void _app_notify_freeobject(void *p,APP *a) {(void)p;(void)a;frees++;}
static int _app_istimerset(APP *a) {return a->timer;}
static void _app_timer_reset(HWND h,APP *a) {(void)h;a->timer=0;timer_resets++;}
static void _app_autoallow_refresh(HWND h) {(void)h;assert(!lock_autoallow);refreshes++;}
static void _app_listview_lock(HWND h,int id,int b) {(void)h;(void)id;(void)b;}
static void _app_setappiteminfo(HWND h,int id,int i,APP *a) {(void)h;(void)id;(void)i;(void)a;ui++;}
static void _app_ruleenable(RULE *r,int enable,int c) {(void)c;assert(lock_autoallow);r->is_enabled=enable;}
static void _app_setruleiteminfo(HWND h,int id,int i,RULE *r,int b) {(void)h;(void)id;(void)i;(void)r;(void)b;ui++;}
'''
wrap='''
static void app_change(APP *ptr_app,int is_enabled) {
 HWND hwnd=NULL;int listview_id=0;NM nm={0},*lpnmlv=&nm;HANDLE hengine;PR_LIST rules;BOOLEAN old_enabled,old_auto_blocked,auto_block_changed,is_rebuild_failed;
'''+app+'''
}
static void rule_change(RULE *ptr_rule,int is_enabled) {
 HWND hwnd=NULL;int listview_id=0;NM nm={0},*lpnmlv=&nm;HANDLE hengine;PR_LIST rules;BOOLEAN old_enabled,is_rebuild_failed;
'''+rule+'''
}
'''
tests=r'''
int main(void) {
 APP app={1,0,0,1}; RULE rule={1,0}; fail=1;
 app_change(&app,0);assert(app.is_enabled==1 && !app.is_autoallow_blocked && app.timer==1 && warnings==1 && !refreshes && !timer_resets && ui==1);
 rule_change(&rule,0);assert(rule.is_enabled==1 && rule.is_haveerrors && warnings==2 && ui==2);
 fail=0;app_change(&app,0);assert(!app.is_enabled && app.is_autoallow_blocked && !app.timer && refreshes==1 && timer_resets==1);
 rule_change(&rule,0);assert(!rule.is_enabled && warnings==2);
 fail=1;rule_change(&rule,1);assert(rule.is_enabled && rule.is_haveerrors && warnings==3);
 assert(!lock_autoallow && calls==5);
 puts("main checkbox failure, state restoration, and lock checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='wfp-main-') as d:
 p=Path(d)/'test.c';e=Path(d)/'test.exe';p.write_text(stubs+wrap+tests)
 subprocess.run([os.environ.get('CC', 'cc'),'-std=c11','-Wall','-Wextra','-Werror',str(p),'-o',str(e)],check=True)
 subprocess.run([str(e)],check=True)
