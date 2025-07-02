#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "server.h"

/* Creates a new process running the server program. The server takes
   two required argument (mqreq and mqresp) and one optional (pidfile).
   The required arguments indicate the names of the message queues to
   use. The optional pidfile specifies the name of a file to store the
   server's PID in. The server uses this file to detect if it is already
   running. You can also look in this file to determine the PID if you
   need to kill it using the kill utility. Run ./server -h on the command
   line to see the required format of the command-line arguments.

   CRITICAL: It is important to get the timing of this function correct.
   This function will create the process and execute the server program;
   it must wait long enough to ensure the server starts successfully, but
   it cannot wait for the server to exit (which would defeat the purpose
   of a server!). Instead, this function must redirect the server's
   STDOUT to a pipe for reading from. The server will write a message
   containing "SUCCESS" once it is ready. If the server encountered an
   error and could not start, it will print an "ERROR" message. This
   function should wait until it receives one of these messages, then
   return.
 */
bool
start_server (char *pidfile, char *mqreq, char *mqresp)
{
  int pipefd[2];
  pid_t pid;

  if (pipe (pipefd) == -1)
    {
      perror ("pipe");
      return false;
    }

  pid = fork ();
  if (pid < 0)
    {
      perror ("fork");
      return false;
    }

  if (pid == 0)
    {
      // Redirect STDOUT to pipe
      close (pipefd[0]);
      dup2 (pipefd[1], STDOUT_FILENO); // Redirect stdout to write end of pipe

      // Execute server program
      execlp ("./server", "./server", "-p", pidfile, mqreq, mqresp,
              (char *)NULL);

      perror ("execl");
      exit (EXIT_FAILURE);
    }

  close (pipefd[1]);

  char buffer[256];
  ssize_t nbytes;

  // Read server output
  while ((nbytes = read (pipefd[0], buffer, 256 - 1)) > 0)
    {
      buffer[nbytes] = '\0';
      if (strstr (buffer, "SUCCESS") != NULL)
        {
          close (pipefd[0]);
          return true;
        }
      else if (strstr (buffer, "ERROR") != NULL)
        {
          close (pipefd[0]);
          return false;
        }
    }

  // Close read end of pipe
  close (pipefd[0]);
  return false;
}

/* Stops the server. Opens the file (pidfile) that contains the server's
   PID as an int. After reading that value into a variable, sends the
   SIGUSR1 signal to the server. The server contains a signal handler that
   will cleanly shut down (deleting the message queues and the pidfile in
   the process) when it receives this signal. Returns true if the server
   has shut down (by detecting the deletion of pidfile), false otherwise.

   Note that there may be a time delay between sending the signal and when
   the server deletes the file. After sending the SIGUSR1 signal, this
   function should check for the file to be deleted up to 5 times (waiting
   for 1 second between each check). Return false only if the file is still
   around after the fifth check.
 */
bool
stop_server (char *pidfile)
{
  // Open PID file
  // Send SIGUSR1 to PID specified in it
  // Try up to 5 times of checking for the file deletion
  int fd = open (pidfile, O_RDONLY);
  char buffer[255];
  int bytes_read = read (fd, buffer, sizeof (buffer));
  close (fd);
  buffer[bytes_read] = '\0';
  int PID = atoi (buffer);
  kill (PID, SIGUSR1);
  for (int i = 0; i < 5; i++)
    {
      if (access (pidfile, F_OK) == -1)
        { // not entirely sure
          return true;
        }
      sleep (1);
    }
  return false;
}
