/* -*- c-file-style: "qgnu" -*- */
#define UNICODE 1
#define _UNICODE 1
#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <wchar.h>

static const struct {
  DWORD bit;
  const char* desc;
} page_bits[] = {
#define B(N) { N, #N }
  B (PAGE_EXECUTE),
  B (PAGE_EXECUTE_READ),
  B (PAGE_EXECUTE_READWRITE),
  B (PAGE_EXECUTE_WRITECOPY),
  B (PAGE_NOACCESS),
  B (PAGE_READONLY),
  B (PAGE_READWRITE),
  B (PAGE_WRITECOPY),
  B (PAGE_GUARD),
  B (PAGE_NOCACHE),
  B (PAGE_WRITECOMBINE),
#undef B
};

#define countof(x) ( sizeof (x) / sizeof (x[0]) )

volatile int var_in_bss;
volatile int var_in_data = 42;

const char*
describe_protection (DWORD prot)
{
  static char buf[1024];
  int i;
  
  buf[0] = '\0';
  for (i = 0; i < countof (page_bits); ++i)
    if (page_bits[i].bit & prot)
      {
        strcat (buf, page_bits[i].desc + 5);
        strcat (buf, ",");
      }

  if (buf[0])
    buf[strlen (buf) - 1] = '\0';
  
  return buf;
}

int
main (int argc, char** argv)
{
  MEMORY_BASIC_INFORMATION mbi;
  char* region = 0;
  const char* type;
  wchar_t namebuf[4096];
  DWORD winpid = (argv[1] ? atoi (argv[1]) : GetCurrentProcessId ());
  HANDLE proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, winpid);

  if (!proc)
    {
      fprintf (stderr, "OpenProcess(%lu): 0x%lx\n",
               winpid, GetLastError ());
      return 1;
    }
               

  var_in_data = 43;
    
  for (;; region += mbi.RegionSize)
    {
      if (!VirtualQueryEx (proc, region, &mbi, sizeof (mbi)))
        {
          if (GetLastError () != ERROR_INVALID_PARAMETER)
            fprintf (stderr, "VirtualQuery: 0x%lx\n", GetLastError ());
          
          break;
        }

      if (mbi.State == MEM_FREE)
        continue;

#if 0
      if (mbi.Type == MEM_IMAGE)
        continue;
#endif

      if (mbi.State == MEM_FREE)
        type = "free";
      else if (mbi.Type == MEM_IMAGE)
        type = "image";
      else if (mbi.Type == MEM_MAPPED)
        type = "mapped";
      else if (mbi.Type == MEM_PRIVATE)
        type = "private";
      else
        type = "unknown";

      printf ("0x%08lx %-9s %010lu %-8s %s\n",
              (unsigned long) region,
              mbi.State == MEM_COMMIT ? "commit" : "reserved",
              mbi.RegionSize,
              type,
              describe_protection (mbi.Protect)
              );

      if (winpid == GetCurrentProcessId ())
        {
          if (region <= (char*) &var_in_bss &&
              (char*) &var_in_bss < (region + mbi.RegionSize))
            {
              printf (" ^^^^ BSS\n");
            }

          if (region <= (char*) &var_in_data &&
              (char*) &var_in_data < (region + mbi.RegionSize))
            {
              printf (" ^^^^ DATA\n");
            }

          if (mbi.Type == MEM_MAPPED)
            {
              namebuf[0] = L'\0';
              wcscpy (namebuf, L"[unknown]");
              GetMappedFileNameW (GetCurrentProcess (),
                                  region,
                                  &namebuf[0],
                                  countof (namebuf));
              printf (" ^^^^ - %S\n", namebuf);
            }
        }
    }
}
