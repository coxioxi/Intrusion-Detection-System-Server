#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "client.h"
#include "ids.h"
#include "server.h"
#include "support.h"

static bool get_args (int, char **, char **, int *, char **, bool *);
static void usage ();

int
main (int argc, char **argv)
{
  char *pidfile = NULL; // server process's PID file
  int index = -1;       // index of first file to query
  bool k_flag = false;
  char *o_flag = NULL;

  if (!get_args (argc, argv, &pidfile, &index, &o_flag, &k_flag))
    {
      usage ();
      return EXIT_FAILURE;
    }

  if (index >= argc - 2)
    {
      usage ();
      return EXIT_FAILURE;
    }

  if (pidfile == NULL)
    pidfile = "PID";

  char *mqreq = argv[index++];  // name of the request message queue
  char *mqresp = argv[index++]; // name of the response message queue

  int count = 0;
  ids_resp_t *response;
  int buffer_size = argc - index;
  ids_entry_t *buffer = NULL;
  int fd = -1;

  if (o_flag)
    {
      fd = open (o_flag, O_RDWR | O_CREAT, 0644);
      ftruncate (fd, sizeof (ids_entry_t) * buffer_size);
      buffer = mmap (NULL, sizeof (ids_entry_t) * buffer_size, PROT_WRITE,
                     MAP_SHARED, fd, 0);
    }

  if (access (pidfile, F_OK) == -1)
    {
      if (!start_server (pidfile, mqreq, mqresp))
        return EXIT_FAILURE;
    }
  for (int i = index; i < argc; i++)
    {
      response = NULL;
      if (get_record (argv[i], mqreq, mqresp, &response))
        {
          bool check = check_record (argv[i], response);
          if (o_flag != NULL)
            {
              strncpy (buffer[count].filename, argv[i], 64);
              buffer[count].mode = response->mode;
              buffer[count].size = response->size;
              strncpy (buffer[count].cksum, response->cksum, 12);
              buffer[count].valid = check;
              ++count;
            }
        }
      else
        printf ("ERROR: Failed to get record for %s\n", argv[i]);

      free (response);
    }
  if (o_flag != NULL)
    {
      munmap (buffer, sizeof (ids_entry_t) * buffer_size);
      close (fd);
    }

  if (k_flag)
    stop_server (pidfile);

  return EXIT_SUCCESS;
}

/* Parse the command-line arguments. */
static bool
get_args (int argc, char **argv, char **pidfile, int *index, char **outputfile,
          bool *k_flag)
{
  int ch = 0;
  while ((ch = getopt (argc, argv, "p:o:kh")) != -1)
    {
      switch (ch)
        {
        case 'p':
          *pidfile = optarg;
          break;
        case 'o':
          *outputfile = optarg;
          break;
        case 'k':
          *k_flag = true;
          break;
        default:
          return false;
        }
    }

  *index = optind;
  return true;
}

static void
usage (void)
{
  printf ("ids, a message-queue based intrusion-detection system\n\n");
  printf ("usage: ids [options] mqreq mqresp file1 ...\n");
  printf ("file1 is a file on disk to query from the server to get\n");
  printf ("the file info from the last time it was checked.\n\n");
  printf ("mqreq and mqresp are used to identify the message queues\n");
  printf ("to communicate with the server.\n\n");
  printf ("options can be one or more of the following:\n");
  printf ("  -k          Kill the server after performing the queries\n");
  printf ("  -o outfile  Write the query results to the file \"outfile\"\n");
  printf ("  -p pidfile  Use \"pidfile\" to store the server's PID");
  printf (" (default \"PID\")\n");
}
