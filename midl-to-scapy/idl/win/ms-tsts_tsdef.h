// [ms-tsts] v31.0 (Fri, 23 May 2025)
 //#ifdef __cplusplus
 //extern "C" {
 //#endif
  
 typedef ULONG TNotificationId;
  
 #define WTS_NOTIFY_NONE ( 0x0 )
 #define WTS_NOTIFY_CREATE ( 0x1 )
 #define WTS_NOTIFY_CONNECT ( 0x2 )
 #define WTS_NOTIFY_DISCONNECT ( 0x4 )
 #define WTS_NOTIFY_LOGON ( 0x8 )
 #define WTS_NOTIFY_LOGOFF ( 0x10 )
 #define WTS_NOTIFY_SHADOW_START ( 0x20 )
 #define WTS_NOTIFY_SHADOW_STOP ( 0x40 )
 #define WTS_NOTIFY_TERMINATE ( 0x80 )
 #define WTS_NOTIFY_CONSOLE_CONNECT ( 0x100 )
 #define WTS_NOTIFY_CONSOLE_DISCONNECT ( 0x200 )
 #define WTS_NOTIFY_LOCK ( 0x400 )
 #define WTS_NOTIFY_UNLOCK ( 0x800 )
 #define WTS_NOTIFY_ALL ( 0xffffffff )
  
 typedef enum _WINSTATIONUPDATECFGCLASS {
     WINSTACFG_LEGACY,
     WINSTACFG_SESSDIR
 } WINSTATIONUPDATECFGCLASS;
  
 typedef struct _SESSION_CHANGE
     {
     LONG SessionId;
     TNotificationId NotificationId;
     } SESSION_CHANGE;
  
 typedef struct _SESSION_CHANGE *PSESSION_CHANGE;
  
 #ifndef _TS_TIME_ZONE_INFORMATION_
 #define _TS_TIME_ZONE_INFORMATION_
     typedef struct _TS_SYSTEMTIME {
         USHORT wYear;
         USHORT wMonth;
         USHORT wDayOfWeek;
         USHORT wDay;
         USHORT wHour;
         USHORT wMinute;
         USHORT wSecond;
         USHORT wMilliseconds;
     } TS_SYSTEMTIME;
  
     typedef struct _TS_TIME_ZONE_INFORMATION {
         LONG Bias;
         WCHAR StandardName[ 32 ];
         TS_SYSTEMTIME StandardDate;
         LONG StandardBias;
         WCHAR DaylightName[ 32 ];
         TS_SYSTEMTIME DaylightDate;
         LONG DaylightBias;
     } TS_TIME_ZONE_INFORMATION;
  
 #endif //_TS_TIME_ZONE_INFORMATION_
  
     typedef enum _SESSION_FILTER {
         SF_SERVICES_SESSION_POPUP
     } SESSION_FILTER;
  
     typedef struct _CLIENT_ID {
  
         HANDLE UniqueProcess; 
  
         HANDLE UniqueThread; 
  
     } CLIENT_ID; 
  
  
     typedef struct _SYSTEM_THREAD_INFORMATION {
  
         LARGE_INTEGER KernelTime; 
  
         LARGE_INTEGER UserTime;
  
         LARGE_INTEGER CreateTime; 
  
         ULONG WaitTime; 
  
         PVOID StartAddress; 
  
         CLIENT_ID ClientId; 
  
         LONG Priority; 
  
         LONG BasePriority; 
  
         ULONG ContextSwitches;
  
         ULONG ThreadState;
  
         ULONG WaitReason; 
  
     } SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION; 
  
  
  
  
  
 //#ifdef __cplusplus
 //}
 //#endif
  
  
