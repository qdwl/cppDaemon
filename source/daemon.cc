//
// Copyright (C) 2011-2012 Yaroslav Stavnichiy <yarosla@gmail.com>
// Copyright (C) 2014 OnlineCity Aps <hd@oc.dk>
//
// Inspired by: https://bitbucket.org/yarosla/nxweb/src/tip/src/lib/daemon.c
//
// Licensed under The MIT License:
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <iostream>
#include "daemon.h"
namespace oc
{
namespace daemon
{

void ContinueAsDaemon(const std::string &work_dir, bool keep_stderr_open)
{
  // Our process ID and Session ID
  pid_t pid, sid;

  // Fork off the parent process
  pid = fork();
  if (pid < 0)
  {
    exit(EXIT_FAILURE);
  }
  // If we got a good PID, then we can exit the parent process.
  if (pid > 0)
  {
    exit(EXIT_SUCCESS);
  }

  // Create a new SID for the child process
  sid = setsid();
  if (sid < 0)
  {
    std::cout << "setsid() failed" << std::endl;
  }

  // Change the file mode mask
  umask(0);

  // Change the current working directory
  if (!work_dir.empty() && chdir(work_dir.c_str()) < 0)
  {
    std::cout << "chdir(work_dir) failed" << std::endl;
  }

  // Close the standard file descriptors
  int zfd = open("/dev/null", O_RDONLY);
  if (zfd == -1)
  {
    std::cout << "open(/dev/null) failed";
  }
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  if (dup2(zfd, STDIN_FILENO) == -1 || dup2(zfd, STDOUT_FILENO) == -1)
  {
    std::cout << "dup2(stdin/stdout) failed";
  }
  if (!keep_stderr_open)
  {
    close(STDERR_FILENO);
    if (dup2(zfd, STDERR_FILENO) == -1)
    {
      std::cout << "dup2(stderr) failed";
    }
  }
  close(zfd);
}

void CreatePidFile(const std::string &pid_file, pid_t pid)
{
  auto pid_str = std::to_string(pid);
  int fd = open(pid_file.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
  if (fd == -1)
  {
    std::cout << "can't create pid file " << pid_file << " [" << errno << "]";
    return;
  }
  if (write(fd, pid_str.c_str(), pid_str.length()))
  {
    close(fd);
  }
}

int Relauncher(const std::function<void()> &main, const std::string &pid_file)
{
  pid_t pid = fork();

  if (pid < 0)
  {
    exit(EXIT_FAILURE);
  }
  else if (pid > 0)
  { // we are the parent
    int status;

    if (!pid_file.empty())
    {
      CreatePidFile(pid_file, pid);
    }
    if (waitpid(pid, &status, 0) == -1)
    {
      std::cout << "waitpid failure";
      exit(EXIT_FAILURE);
    }
    if (!pid_file.empty())
    {
      unlink(pid_file.c_str());
    }

    if (WIFEXITED(status))
    {
      if (WEXITSTATUS(status) == EXIT_SUCCESS)
      {
        std::cout << "Server closing";
      }
      else
      {
        std::cout << "Server exited, status=" << WEXITSTATUS(status);
      }
      return WEXITSTATUS(status);
    }
    else if (WIFSIGNALED(status))
    {
      std::cout << "Server killed by signal " << WTERMSIG(status);
      return 1;
    }
  }
  else
  { // we are the child
    // Drop privileges if user and group is specified
    /*if (FLAGS_user.length() > 0 && FLAGS_group.length() > 0)
    {
      DropPrivileges(FLAGS_user, FLAGS_group);
    }*/
    std::cout << "Starting server loop";
    main();
    std::cout << "Server loop end";
    exit(EXIT_SUCCESS);
  }
  return 0;
}

static uid_t get_uid_by_name(const std::string &user_name)
{
  auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (buflen == -1)
  {
    buflen = 1024; // fallback on systems where it returns -1 (ie. FreeBSD)
  }
  char *buf = static_cast<char *>(malloc(buflen));
  struct passwd pwbuf, *pwbufp;
  getpwnam_r(user_name.c_str(), &pwbuf, buf, buflen, &pwbufp);
  free(buf);
  return pwbufp ? pwbufp->pw_uid : -1;
}

static gid_t get_gid_by_name(const std::string &group_name)
{
  auto buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
  if (buflen == -1)
  {
    buflen = 1024; // fallback on systems where it returns -1 (ie. FreeBSD)
  }
  char *buf = static_cast<char *>(malloc(buflen));
  struct group grbuf, *grbufp;
  getgrnam_r(group_name.c_str(), &grbuf, buf, buflen, &grbufp);
  free(buf);
  return grbufp ? grbufp->gr_gid : -1;
}

int RunDaemon(const std::string &work_dir, const std::string &pid_file, bool keep_stderr_open,
              const std::function<void()> &main)
{
  ContinueAsDaemon(work_dir, keep_stderr_open);
  while (Relauncher(main, pid_file) != EXIT_SUCCESS)
  {
    sleep(2); // sleep 2 sec and launch again until child exits with EXIT_SUCCESS
  }
  return EXIT_SUCCESS;
}

int RunNormal(const std::string &work_dir, const std::string &pid_file, bool keep_stderr_open,
              const std::function<void()> &main)
{
  if (!work_dir.empty() && chdir(work_dir.c_str()) < 0)
  {
    std::cout << "chdir(work_dir) failed";
  }
  if (!pid_file.empty())
  {
    CreatePidFile(pid_file, getpid());
  }
  // Drop privileges if user and group is specified
  /*if (FLAGS_user.length() > 0 && FLAGS_group.length() > 0)
  {
    DropPrivileges(FLAGS_user, FLAGS_group);
  }*/
  main();
  if (!pid_file.empty())
  {
    unlink(pid_file.c_str()); // this might not always succeed since the privileges are dropped
  }
  return EXIT_SUCCESS;
}

int DropPrivileges(const std::string &group_name, const std::string &user_name)
{
  if (!user_name.empty() && !group_name.empty())
  {
    uid_t uid = get_uid_by_name(user_name);
    gid_t gid = get_gid_by_name(group_name);
    if (uid == -1 || gid == -1)
    {
      std::cout << "uid=" << uid << " gid=" << gid << " can't set uid&gid";
      return -1;
    }
    else
    {
    // change them permanently
#if defined(__linux) || defined(linux)
      if (setresgid(gid, gid, gid) == -1)
      {
        std::cout << "can't set gid=" << gid << " errno=" << errno;
        return -1;
      }
      if (setresuid(uid, uid, uid) == -1)
      {
        std::cout << "can't set uid=" << uid << " errno=" << errno;
        return -1;
      }
#else
      if (setgid(gid) == -1)
      {
        std::cout << "can't set gid=" << gid << " errno=" << errno;
        return -1;
      }
      if (setuid(uid) == -1)
      {
        std::cout << "can't set uid=" << uid << " errno=" << errno;
        return -1;
      }
#endif
      std::cout << "privileges dropped to " << group_name << "[" << gid << "] " << user_name << "[" << uid << "]";
    }
  }
  return 0;
}

int MainStub(int argc, char **argv, const MainFunctionCallback &main)
{
  // Initialize gflags and glog

  // Do we need to keep stderr open?
  //bool keep_stderr_open = FLAGS_logtostderr || FLAGS_alsologtostderr;

  // Forking daemon with re-launch
  //if (FLAGS_daemon)
  //{
    RunDaemon("/home/dennis/", "", true, std::bind(main, argc, argv));
  //}
  //else
  //{
    //RunNormal(FLAGS_workdir, FLAGS_pidfile, keep_stderr_open, std::bind(main, argc, argv));
  //}

  return EXIT_SUCCESS;
}

// There is no standard (non pthread specific) way of doing this, so
// use pthread_sigmask for this
int BlockSignals()
{
  /*sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGPIPE);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGQUIT);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGUSR1);
  int res = pthread_sigmask(SIG_BLOCK, &set, NULL);
  if (res)
  {
    std::cout << "can't set pthread_sigmask";
    exit(EXIT_SUCCESS); // simulate normal exit so we don't respawn
  }
  return res;*/
  return 0;
}

int InstallStopCallback(void (*func)(int))
{
  /*signal(SIGTERM, func);
  signal(SIGINT, func);

  // Unblock signals for the main thread;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGINT);
  int res = pthread_sigmask(SIG_UNBLOCK, &set, NULL);
  if (res)
  {
    std::cout << "can't unset pthread_sigmask";
    exit(EXIT_SUCCESS); // simulate normal exit so we don't respawn
  }
  return res;*/

  return 0;
}

} // namespace daemon
} // namespace oc