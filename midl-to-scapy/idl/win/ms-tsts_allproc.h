 import "ms-dtyp.idl";
 
 #ifndef TS_ALLPROC_ALREADY_SET
 #define TS_ALLPROC_ALREADY_SET
  
 #ifdef  __midl
 cpp_quote( "#define TS_PROCESS_INFO_MAGIC_NT4  0x23495452" )
 #else
 #define TS_PROCESS_INFO_MAGIC_NT4  0x23495452
 #endif
  
 typedef struct _TS_PROCESS_INFORMATION_NT4 {
     ULONG MagicNumber;
     ULONG LogonId;
     PVOID ProcessSid;
     ULONG Pad;
 } TS_PROCESS_INFORMATION_NT4, * PTS_PROCESS_INFORMATION_NT4;
  
 // sizes of TS4.0 structures (size has changed in Windows 2000)
 #ifdef  __midl
 cpp_quote( "#define SIZEOF_TS4_SYSTEM_THREAD_INFORMATION    64" )
 cpp_quote( "#define SIZEOF_TS4_SYSTEM_PROCESS_INFORMATION   136" )
 #else
 #define SIZEOF_TS4_SYSTEM_THREAD_INFORMATION 64
 #define SIZEOF_TS4_SYSTEM_PROCESS_INFORMATION 136
 #endif
  
  
 #ifdef  __midl
 cpp_quote( "#define GAP_LEVEL_BASIC 0" )
 #else
 #define GAP_LEVEL_BASIC 0
 #endif
  
 typedef struct _TS_UNICODE_STRING {
     USHORT Length;
     USHORT MaximumLength;
 #ifdef __midl
     [size_is(MaximumLength),length_is(Length)]PWSTR  Buffer;
 #else
//      PWSTR  Buffer;
//  #endif
 } TS_UNICODE_STRING;
  
  
 typedef struct _TS_SYS_PROCESS_INFORMATION {
     ULONG NextEntryOffset;
     ULONG NumberOfThreads;
     LARGE_INTEGER SpareLi1;
     LARGE_INTEGER SpareLi2;
     LARGE_INTEGER SpareLi3;
     LARGE_INTEGER CreateTime;
     LARGE_INTEGER UserTime;
     LARGE_INTEGER KernelTime;
     TS_UNICODE_STRING ImageName;
     LONG BasePriority;                     // KPRIORITY in ntexapi.h
     DWORD UniqueProcessId;                 // HANDLE in ntexapi.h
     DWORD InheritedFromUniqueProcessId;    // HANDLE in ntexapi.h
     ULONG HandleCount;
     ULONG SessionId;
     ULONG SpareUl3;
     SIZE_T PeakVirtualSize;
     SIZE_T VirtualSize;
     ULONG PageFaultCount;
     ULONG PeakWorkingSetSize;
     ULONG WorkingSetSize;
     SIZE_T QuotaPeakPagedPoolUsage;
     SIZE_T QuotaPagedPoolUsage;
     SIZE_T QuotaPeakNonPagedPoolUsage;
     SIZE_T QuotaNonPagedPoolUsage;
     SIZE_T PagefileUsage;
     SIZE_T PeakPagefileUsage;
     SIZE_T PrivatePageCount;
 } 
 TS_SYS_PROCESS_INFORMATION, *PTS_SYS_PROCESS_INFORMATION;
  
 typedef struct _TS_ALL_PROCESSES_INFO {
     PTS_SYS_PROCESS_INFORMATION pTsProcessInfo;
     DWORD                           SizeOfSid;
 #ifdef __midl
     [size_is(SizeOfSid)] PBYTE      pSid;
//  #else
//      PBYTE                           pSid;
//  #endif
 } 
 TS_ALL_PROCESSES_INFO, *PTS_ALL_PROCESSES_INFO;
  
  
 //=======================================================================
  
 // The following structures are defined for taking care of interface 
 // change in Whistler.
  
 typedef struct _NT6_TS_UNICODE_STRING {
     USHORT Length;
     USHORT MaximumLength;
 #ifdef __midl
     [size_is(MaximumLength / 2),length_is(Length / 2)]PWSTR  Buffer;
//  #else
//      PWSTR  Buffer;
//  #endif
 } NT6_TS_UNICODE_STRING;
  
  
 typedef struct _TS_SYS_PROCESS_INFORMATION_NT6 {
     ULONG NextEntryOffset;
     ULONG NumberOfThreads;
     LARGE_INTEGER SpareLi1;
     LARGE_INTEGER SpareLi2;
     LARGE_INTEGER SpareLi3;
     LARGE_INTEGER CreateTime;
     LARGE_INTEGER UserTime;
     LARGE_INTEGER KernelTime;
     NT6_TS_UNICODE_STRING ImageName;
     LONG BasePriority;                     // KPRIORITY in ntexapi.h
     DWORD UniqueProcessId;                 // HANDLE in ntexapi.h
     DWORD InheritedFromUniqueProcessId;    // HANDLE in ntexapi.h
     ULONG HandleCount;
     ULONG SessionId;
     ULONG SpareUl3;
     SIZE_T PeakVirtualSize;
     SIZE_T VirtualSize;
     ULONG PageFaultCount;
     ULONG PeakWorkingSetSize;
     ULONG WorkingSetSize;
     SIZE_T QuotaPeakPagedPoolUsage;
     SIZE_T QuotaPagedPoolUsage;
     SIZE_T QuotaPeakNonPagedPoolUsage;
     SIZE_T QuotaNonPagedPoolUsage;
     SIZE_T PagefileUsage;
     SIZE_T PeakPagefileUsage;
     SIZE_T PrivatePageCount;
 } 
 TS_SYS_PROCESS_INFORMATION_NT6, *PTS_SYS_PROCESS_INFORMATION_NT6;
  
 typedef struct _TS_ALL_PROCESSES_INFO_NT6 {
     PTS_SYS_PROCESS_INFORMATION_NT6 pTsProcessInfo;
     DWORD                           SizeOfSid;
 #ifdef __midl
     [size_is(SizeOfSid)] PBYTE      pSid;
//  #else
//      PBYTE                           pSid;
//  #endif
 } 
 TS_ALL_PROCESSES_INFO_NT6, *PTS_ALL_PROCESSES_INFO_NT6;
  
 //=========================================================================================
  
 //
 // TermSrv Counter Header
 // 
 typedef struct _TS_COUNTER_HEADER {
     DWORD dwCounterID;     // identifies counter
     boolean bResult;       // result of operation performed on counter
 } TS_COUNTER_HEADER, *PTS_COUNTER_HEADER;
  
 typedef struct _TS_COUNTER {
     TS_COUNTER_HEADER counterHead; 
     DWORD             dwValue;      // returned value
     LARGE_INTEGER     startTime;    // start time for counter
 } TS_COUNTER, *PTS_COUNTER;
  
 #endif  //  TS_ALLPROC_ALREADY_SET
  
 #define  TSVIP_MAX_ADAPTER_ADDRESS_LENGTH  16
  
 typedef  struct  _TSVIP_SOCKADDR {
//  #ifdef __midl
     [switch(short type)] union _u
     {
      [case(2)]                       // AF_INET
         struct {
             USHORT  sin_port;
             ULONG   in_addr;
             UCHAR   sin_zero[8];
         }  ipv4;
      [case(23)]                      // AF_INET6
         struct {
             USHORT  sin6_port;
             ULONG   sin6_flowinfo;
             USHORT  sin6_addr[8];
             ULONG   sin6_scope_id;
         }  ipv6;
     } u;
//  #else
//      USHORT  sin_family;
//      union
//      {
//          struct  {
//              USHORT  sin_port;
//              ULONG   in_addr;
//              UCHAR   sin_zero[8];
//          }  ipv4;
//          struct {
//              USHORT  sin6_port;
//              ULONG   sin6_flowinfo;
//              USHORT  sin6_addr[8];
//              ULONG   sin6_scope_id;
//          }  ipv6;
//      }  u;
//  #endif
 }  TSVIP_SOCKADDR,
    *PTSVIP_SOCKADDR;
  
 typedef  struct  _TSVIPAddress {
     DWORD             dwVersion;   //Structure version
     TSVIP_SOCKADDR    IPAddress;    //IPv4 is in network byte order.
     ULONG             PrefixOrSubnetMask;    //IPv4 is a mask in network byte order,
 #ifdef  __midl                                //IPv6 is prefix length.
     [range(0, TSVIP_MAX_ADAPTER_ADDRESS_LENGTH)]  
       UINT            PhysicalAddressLength;
     [length_is(PhysicalAddressLength)] 
       BYTE  PhysicalAddress[TSVIP_MAX_ADAPTER_ADDRESS_LENGTH];
//  #else
//      UINT              PhysicalAddressLength;
//      BYTE              PhysicalAddress[TSVIP_MAX_ADAPTER_ADDRESS_LENGTH];
//  #endif
     ULONG             LeaseExpires;
     ULONG             T1;
     ULONG             T2;
 }  TSVIPAddress,
    *PTSVIPAddress;
  
 typedef  struct  _TSVIPSession {
     DWORD             dwVersion;   //Structure version
     DWORD             SessionId;   //Session ID
     TSVIPAddress      SessionIP;   //IPAddress assign to session
 }  TSVIPSession,
    *PTSVIPSession;    
  
 //NBD   end