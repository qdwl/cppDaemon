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

#pragma once

#include <unistd.h>
#include <functional>
#include <string>
namespace oc {
namespace daemon {

typedef std::function<void(int)> FuncCall;
typedef std::function<void(int, char **)> MainFunctionCallback;

// Initializes gflags, glog and starts either in daemon or normal mode as specified by flags
int MainStub(int argc, char **argv, const MainFunctionCallback &main);

// Performs all the steps required to become a daemon
void ContinueAsDaemon(const std::string &work_dir, bool keep_stderr_open);

// Create a PID file and writes pid to it
void CreatePidFile(const std::string &pid_file, pid_t pid);

// Fork and wait for something to happen
// Called in a loop until it returns EXIT_SUCCESS, thus the server is simply relaunched if it fails
int Relauncher(const std::function<void()> &main, const std::string &pid_file);

// Becomes a daemon and then calls relauncher in a loop
int RunDaemon(const std::string &work_dir, const std::string &pid_file, bool keep_stderr_open,
              const std::function<void()> &main);

// Performs the same steps as Relauncher but without daemonizing to looping
int RunNormal(const std::string &work_dir, const std::string &pid_file, bool keep_stderr_open,
              const std::function<void()> &main);

// Drop current process privileges to a group and user
int DropPrivileges(const std::string &group_name, const std::string &user_name);

// Block signals on all threads, otherwise a child thread may receive signal
// Without doing this SIGINT/SIGTERM handlers won't work as expected on Linux/FreeBSD
// Must be called before starting (child) threads
int BlockSignals();

// Install a callback for SIGINT and SIGTERM (stop signals)
// Call after starting threads
int InstallStopCallback(void (*func)(int));

}  // namespace daemon
}  // namespace oc