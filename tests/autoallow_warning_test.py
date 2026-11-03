from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parents[1]
s = (root/'src/wfp.c').read_text()
def extract(marker):
 a=s.index(marker); b=s.index('{',a); i=b+1; depth=1
 while depth:
  depth+=(s[i]=='{')-(s[i]=='}'); i+=1
 return s[a:i]
funcs='\n'.join(extract(x) for x in ('VOID _wfp_schedulewarning (','VOID _wfp_warnruleupdate (','VOID _wfp_showwarning ('))
stubs=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#undef _In_opt_
#endif
#define _In_
#define _In_opt_
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define VOID void
#define TRUE 1
#define LOG_LEVEL_ERROR 1
#define WM_WFP_WARNING 55
#define WFP_WARNING_TIMER 66
#define MB_OK 0
#define MB_ICONERROR 1
typedef long LONG;
typedef void *HWND;
static volatile LONG wfp_warning_pending, wfp_warning_scheduled;
static int lock_apply, posts, timers, kills, dialogs, logs, has_window=1, post_ok=1, timer_ok=1, display_ok=1, during_dialog, race;
void _wfp_warnruleupdate(HWND hwnd);
static LONG InterlockedCompareExchange(volatile LONG *p,LONG v,LONG cmp) {LONG n=*p;if(n==cmp)*p=v;return n;}
static LONG InterlockedExchange(volatile LONG *p,LONG v) {LONG n=*p;*p=v;if(race && p==&wfp_warning_pending && v==0){race=0;_wfp_warnruleupdate(NULL);}return n;}
static HWND _r_app_gethwnd(void) {return has_window ? (HWND)(uintptr_t)1 : NULL;}
static int PostMessageW(HWND h,int m,int a,int b) {(void)h;(void)m;(void)a;(void)b;posts++;return post_ok;}
static uintptr_t SetTimer(HWND h,int id,int ms,void *p) {(void)h;(void)id;(void)ms;(void)p;timers++;return timer_ok;}
static int KillTimer(HWND h,int id) {(void)h;(void)id;kills++;return 1;}
static int _r_queuedlock_islocked(int *p) {return *p;}
static int MessageBoxW(HWND h,const wchar_t *text,const wchar_t *title,int flags) {(void)h;(void)title;(void)flags;assert(wcsstr(text,L"Previous permissions may still be active"));dialogs++;if(during_dialog){during_dialog=0;_wfp_warnruleupdate(NULL);}return display_ok;}
static unsigned GetLastError(void){return 5;}
static void _r_log(int level,void *id,const wchar_t *title,unsigned status,const wchar_t *desc) {(void)level;(void)id;(void)title;(void)status;(void)desc;logs++;}
'''
tests=r'''
static void reset(void) {wfp_warning_pending=wfp_warning_scheduled=0;lock_apply=posts=timers=kills=dialogs=logs=during_dialog=race=0;has_window=post_ok=timer_ok=display_ok=1;}
int main(void) {
 HWND h=(HWND)(uintptr_t)1;
 reset(); for(int i=0;i<20;i++)_wfp_warnruleupdate(h);
 assert(posts==1 && logs==1 && !dialogs && wfp_warning_pending);
 lock_apply=1;_wfp_showwarning(h);assert(!dialogs && timers==1 && wfp_warning_pending);
 lock_apply=0;during_dialog=1;_wfp_showwarning(h);assert(dialogs==1 && posts==1 && !wfp_warning_pending);
 reset();has_window=0;_wfp_warnruleupdate(NULL);assert(wfp_warning_pending && !posts);has_window=1;_wfp_schedulewarning();assert(posts==1);_wfp_showwarning(h);assert(dialogs==1);
 reset();post_ok=0;_wfp_warnruleupdate(h);assert(posts==1 && timers==1 && wfp_warning_scheduled);_wfp_showwarning(h);assert(dialogs==1);
 reset();post_ok=timer_ok=0;_wfp_warnruleupdate(h);assert(wfp_warning_pending && !wfp_warning_scheduled && logs==2);post_ok=1;_wfp_schedulewarning();assert(posts==2);_wfp_showwarning(h);assert(dialogs==1);
 reset();_wfp_warnruleupdate(h);display_ok=0;_wfp_showwarning(h);assert(wfp_warning_pending && wfp_warning_scheduled && timers==1);display_ok=1;_wfp_showwarning(h);assert(dialogs==2 && !wfp_warning_pending);
 reset();_wfp_warnruleupdate(h);race=1;_wfp_showwarning(h);assert(wfp_warning_pending && posts==2 && wfp_warning_scheduled);_wfp_showwarning(h);assert(dialogs==2 && !wfp_warning_pending);
 puts("warning coalescing, apply deferral, delivery failures, startup and race checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='wfp-warning-') as d:
 src=Path(d)/'test.c'; exe=Path(d)/'test.exe'; src.write_text(stubs+funcs+tests)
 subprocess.run([os.environ.get('CC', 'cc'),'-std=c11','-Wall','-Wextra','-Werror',str(src),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
