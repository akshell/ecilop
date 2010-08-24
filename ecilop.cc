// (c) 2010 by Anton Korenyushkin

#include <boost/program_options.hpp>
#include <boost/unordered_map.hpp>
#include <boost/foreach.hpp>
#include <boost/utility.hpp>

#include <iostream>
#include <fstream>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/wait.h>


using namespace std;
namespace po = boost::program_options;


////////////////////////////////////////////////////////////////////////////////
// Globals
////////////////////////////////////////////////////////////////////////////////

const size_t SPACE_COUNT = 128;
const size_t MAX_NAME_SIZE = 30;
const size_t BUF_SIZE = 8192;

string data_path;
string locks_path;
string patsak_path;
string patsak_config_path;
string common_git_path_pattern;

////////////////////////////////////////////////////////////////////////////////
// Utils
////////////////////////////////////////////////////////////////////////////////

void PrintPrefix()
{
    time_t t = time(0);
    const struct tm* tm_ptr = localtime(&t);
    const size_t size = 28;
    char buf[size];
    strftime(buf, size, "%F %T ecilop ", tm_ptr);
    cerr << buf;
}


void Fail(const string& message)
{
    PrintPrefix();
    cerr << message << ": " << strerror(errno) << '\n';
    exit(1);
}


void FailOnAssertion(const string& file,
                     size_t line,
                     const string& pretty_function,
                     const string& assertion)
{
    PrintPrefix();
    cerr << file << ':' << line << ": " << pretty_function
         << ": Assertion `" << assertion << "' failed\n";
    exit(1);
}


#define ASSERT(cond)                                                    \
    ((cond)                                                             \
     ? static_cast<void>(0)                                             \
     : FailOnAssertion(__FILE__, __LINE__, __PRETTY_FUNCTION__, #cond))


void Reply(char op, int conn_fd, const string& object)
{
    string reply;
    if (op == 'E') {
        reply = 'E' + object + " not found";
    } else {
        string content("<h2>" + object + " not found</h2>");
        ostringstream oss;
        oss << ("HTTP/1.0 404 Not found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: ")
            << content.size() << "\r\n\r\n" << content;
        reply = oss.str();
    }
    size_t sent = 0;
    ssize_t count;
    do {
        count = write(conn_fd, reply.data() + sent, reply.size() - sent);
        sent += count;
    } while (count > 0 && sent < reply.size());
    shutdown(conn_fd, SHUT_WR);
    char buf[BUF_SIZE];
    do {
        count = read(conn_fd, buf, BUF_SIZE);
    } while (count > 0);
    exit(1);
}

////////////////////////////////////////////////////////////////////////////////
// Host
////////////////////////////////////////////////////////////////////////////////

class Host : boost::noncopyable {
public:
    static Host* GetLastPtr();

    Host(const string& id,
         const string& dev,
         const string& app,
         const string& env,
         char op,
         int conn_fd);

    ~Host();

    string GetId() const;
    vector<string>& GetDomains();
    time_t GetTime() const;
    void Run(char op, int conn_fd);

private:
    static Host* first_ptr;
    static Host* last_ptr;

    string id_, dev_, app_, env_;
    vector<string> domains_;
    int carrier_fd_;
    time_t time_;
    Host* next_ptr_;
    Host* prev_ptr_;

    bool Send(char op, int conn_fd) const;
    void Launch(char op, int conn_fd);

};


Host* Host::first_ptr = 0;
Host* Host::last_ptr = 0;


Host* Host::GetLastPtr()
{
    return last_ptr;
}


Host::Host(const string& id,
           const string& dev,
           const string& app,
           const string& env,
           char op,
           int conn_fd)
    : id_(id)
    , dev_(dev)
    , app_(app)
    , env_(env)
    , next_ptr_(0)
{
    Launch(op, conn_fd);
    time_ = time(0);
    if (first_ptr) {
        first_ptr->next_ptr_ = this;
        prev_ptr_ = first_ptr;
        first_ptr = this;
    } else {
        prev_ptr_ = 0;
        first_ptr = last_ptr = this;
    }
}


Host::~Host()
{
    (next_ptr_ ? next_ptr_->prev_ptr_ : first_ptr) = prev_ptr_;
    (prev_ptr_ ? prev_ptr_->next_ptr_ : last_ptr) = next_ptr_;
    close(carrier_fd_);
}


string Host::GetId() const
{
    return id_;
}


vector<string>& Host::GetDomains()
{
    return domains_;
}


time_t Host::GetTime() const
{
    return time_;
}


void Host::Run(char op, int conn_fd)
{
    if (!Send(op, conn_fd)) {
        close(carrier_fd_);
        Launch(op, conn_fd);
    }
    time_ = time(0);
    if (next_ptr_) {
        next_ptr_->prev_ptr_ = prev_ptr_;
        (prev_ptr_ ? prev_ptr_->next_ptr_ : last_ptr) = next_ptr_;
        next_ptr_ = 0;
        first_ptr->next_ptr_ = this;
        prev_ptr_ = first_ptr;
        first_ptr = this;
    }
}


bool Host::Send(char op, int conn_fd) const
{
    struct msghdr msg;
    msg.msg_name = 0;
    msg.msg_namelen = 0;
    struct iovec iov;
    iov.iov_base = &op;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    char control[CMSG_SPACE(sizeof(int))];
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    struct cmsghdr* cmsg_ptr = CMSG_FIRSTHDR(&msg);
    cmsg_ptr->cmsg_level = SOL_SOCKET;
    cmsg_ptr->cmsg_type = SCM_RIGHTS;
    cmsg_ptr->cmsg_len = CMSG_LEN(sizeof(int));
    *reinterpret_cast<int*>(CMSG_DATA(cmsg_ptr)) = conn_fd;
    return sendmsg(carrier_fd_, &msg, 0) == 1;
}


void Host::Launch(char op, int conn_fd)
{
    int fd_pair[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_pair);
    ASSERT(ret == 0);
    carrier_fd_ = fd_pair[0];
    pid_t pid = fork();
    ASSERT(pid != -1);
    if (pid) {
        close(fd_pair[1]);
        return;
    }
    string lock_path(locks_path + '/' + dev_);
    int lock_fd = open(lock_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    ASSERT(lock_fd != -1);
    ret = flock(lock_fd, LOCK_SH);
    ASSERT(ret == 0);
    string dev_path(data_path + "/devs/" + dev_);
    string app_path(dev_path + "/apps/" + app_);
    string check_path(env_.empty() ? app_path : app_path + "/envs/" + env_);
    struct stat st;
    if (stat(check_path.c_str(), &st)) {
        ret = unlink(lock_path.c_str());
        ASSERT(ret == 0);
        if (stat(dev_path.c_str(), &st))
            Reply(op, conn_fd, "Developer " + dev_);
        if (env_.empty() || stat(app_path.c_str(), &st))
            Reply(op, conn_fd, "App " + app_ + ' ' + env_);
        else
            Reply(op, conn_fd, "Environment " + env_);
    }
    Send(op, conn_fd);
    int dup_fd = dup2(fd_pair[1], STDIN_FILENO);
    ASSERT(dup_fd == STDIN_FILENO);
    string code_path(app_path + "/code");
    string grantor_git_path_pattern(dev_path + "/grantors/%s/%s/git");
    const char* args[] = {
        patsak_path.c_str(), "work",
        "--app", code_path.c_str(),
        "--schema", id_.c_str(),
        "--tablespace", dev_.c_str(),
        "--log-id", id_.c_str(),
        "--git", common_git_path_pattern.c_str(),
        "--git", grantor_git_path_pattern.c_str(),
        0, 0, 0, 0, 0
    };
    size_t i = 14;
    string repo_name(dev_ + '/' + app_);
    if (env_.empty()) {
        args[i++] = "--repo";
        args[i++] = repo_name.c_str();
    }
    if (!patsak_config_path.empty()) {
        args[i++] = "--config";
        args[i] = patsak_config_path.c_str();
    }
    execv(patsak_path.c_str(), const_cast<char**>(args));
    Fail("Failed to launch patsak");
}

////////////////////////////////////////////////////////////////////////////////
// main
////////////////////////////////////////////////////////////////////////////////

void MakePathAbsolute(const string& curr_path, string& path)
{
    if (path.empty() || path[0] != '/')
        path = curr_path + '/' + path;
}


void RequireOption(const string& name, const string& value)
{
    if (value.empty()) {
        cerr << "Option " << name << " is required\n";
        exit(1);
    }
}


void HandleStop(int /*signal*/)
{
    exit(0);
}


string ParseId(const char* start_ptr) {
    const char* end_ptr = ++start_ptr;
    while (*end_ptr != ' ')
        ++end_ptr;
    return string(start_ptr, end_ptr);
}


string ReadDomainId(const string& domain)
{
    string path(data_path + "/domains/" + domain);
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1)
        return "";
    char buf[SPACE_COUNT];
    ssize_t size = read(fd, buf, SPACE_COUNT);
    ASSERT(size != -1);
    close(fd);
    char* start_ptr = buf;
    while (isspace(*start_ptr) && start_ptr < buf + size)
        ++start_ptr;
    char* end_ptr = buf + size;
    while (isspace(*(end_ptr - 1)) && end_ptr > start_ptr)
        --end_ptr;
    return string(start_ptr, end_ptr);
}


int main(int argc, char** argv) {
    po::options_description generic_options("Generic options");
    generic_options.add_options()
        ("help,h", "print help message")
        ("config,c", po::value<string>()->default_value("/etc/ecilop.conf"),
         "config file")
        ;

    string socket_descr, log_path;
    int timeout;
    po::options_description config_options("Config options");
    config_options.add_options()
        ("socket,s", po::value<string>(&socket_descr), "serve socket")
        ("data,d", po::value<string>(&data_path), "data directory")
        ("locks,l", po::value<string>(&locks_path), "locks directory")
        ("log,o", po::value<string>(&log_path), "log file")
        ("patsak,p", po::value<string>(&patsak_path), "patsak executable")
        ("patsak-config,a", po::value<string>(&patsak_config_path),
         "alternative patsak config")
        ("timeout,t", po::value<int>(&timeout)->default_value(60),
         "stop timeout")
        ("background,b", "run in background")
        ;

    po::options_description cmdline_options(
        string("Usage: ") + argv[0] + " [options]");
    cmdline_options.add(generic_options).add(config_options);

    po::variables_map vm;
    try {
        po::store(
            po::command_line_parser(argc, argv).options(cmdline_options).run(),
            vm);
        ifstream config_file(vm["config"].as<string>().c_str());
        if (config_file.is_open()) {
            po::store(po::parse_config_file(config_file, config_options), vm);
            config_file.close();
        }
        po::notify(vm);
    } catch (po::error& err) {
        cerr << err.what() << '\n';
        return 1;
    }

    if (vm.count("help")) {
        cout << cmdline_options;
        return 0;
    }

    RequireOption("socket", socket_descr);
    RequireOption("patsak", patsak_path);
    RequireOption("data", data_path);
    RequireOption("locks", locks_path);

    common_git_path_pattern = data_path + "/devs/%s/libs/%s/git";

    size_t colon_idx = socket_descr.find_first_of(':');
    string socket_path(socket_descr.substr(0, colon_idx));
    string socket_mode;
    if (colon_idx != string::npos)
        socket_mode = socket_descr.substr(colon_idx + 1);

    if (vm.count("background")) {
        RequireOption("log-file", log_path);
        if (!freopen(log_path.c_str(), "a", stderr)) {
            cout << "Failed to open log file: " << strerror(errno) << '\n';
            return 1;
        }
        char* curr_path = get_current_dir_name();
        MakePathAbsolute(curr_path, socket_path);
        MakePathAbsolute(curr_path, patsak_path);
        MakePathAbsolute(curr_path, data_path);
        MakePathAbsolute(curr_path, locks_path);
        free(curr_path);
        pid_t pid = fork();
        ASSERT(pid != -1);
        if (pid)
            return 0;
        umask(0);
        pid_t sid = setsid();
        ASSERT(sid != -1);
        int ret = chdir("/");
        ASSERT(ret == 0);
    }

    int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT(listen_fd != -1);
    unlink(socket_path.c_str());
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,
            socket_path.c_str(),
            sizeof(address.sun_path) - 1);
    if (bind(listen_fd,
             reinterpret_cast<struct sockaddr*>(&address),
             SUN_LEN(&address)))
        Fail("Failed to bind");
    if (!socket_mode.empty())
        chmod(socket_path.c_str(), strtol(socket_mode.c_str(), 0, 8));
    int ret = listen(listen_fd, SOMAXCONN);
    ASSERT(ret == 0);

    cout << "Running at " << socket_path << endl;
    if (vm.count("background")) {
        FILE* file_ptr = freopen("/dev/null", "w", stdout);
        ASSERT(file_ptr);
        file_ptr = freopen("/dev/null", "r", stdin);
        ASSERT(file_ptr);
    } else {
        cout << "Quit with Control-C." << endl;
    }

    struct sigaction action;
    action.sa_handler = HandleStop;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    ret = sigaction(SIGTERM, &action, 0);
    ASSERT(ret == 0);
    ret = sigaction(SIGINT, &action, 0);
    ASSERT(ret == 0);

    typedef boost::unordered_map<string, Host*> HostMap;
    HostMap host_map;

    for (;;) {
        int conn_fd = accept4(listen_fd, 0, 0, SOCK_CLOEXEC);
        ASSERT(conn_fd != -1);
        char buf[SPACE_COUNT];
        ssize_t count = read(conn_fd, buf, SPACE_COUNT);
        ASSERT(count == static_cast<ssize_t>(SPACE_COUNT));
        ASSERT(buf[count - 1] == ' ');
        const char* ptr = buf;
        while (*ptr != ' ')
            ++ptr;
        string method(const_cast<const char*>(buf), ptr);
        if (method == "STOP") {
            HostMap::iterator itr = host_map.find(ParseId(ptr));
            if (itr != host_map.end()) {
                Host* host_ptr(itr->second);
                host_map.erase(itr);
                BOOST_FOREACH(const string& domain, host_ptr->GetDomains())
                    host_map.erase(domain);
                delete host_ptr;
            }
        } else {
            HostMap::iterator itr = host_map.end();
            string id, dev, app, env, domain;
            char op;
            if (method == "EVAL") {
                op = 'E';
                id = ParseId(ptr);
            } else {
                op = 'H';
                const char* ptrs[SPACE_COUNT] = {ptr};
                size_t size = 1;
                do {
                    do {
                        ++ptr;
                    } while (*ptr != '.' && *ptr != ' ');
                    ptrs[size++] = ptr;
                } while (*ptr == '.');
                ASSERT(size > 2);
                if (size > 6 &&
                    (string(ptrs[size - 4] + 1, ptrs[size - 1]) ==
                     "dev.akshell.com")) {
                    dev.assign(ptrs[size - 5] + 1, ptrs[size - 4]);
                    app.assign(ptrs[size - 6] + 1, ptrs[size - 5]);
                    env.assign(ptrs[size - 7] + 1, ptrs[size - 6]);
                    if (env == "release")
                        env = "";
                    id = dev + ':' + app + (env.empty() ? "" : ':' + env);
                } else {
                    string domain3;
                    if (size > 3) {
                        domain3.assign(ptrs[size - 4] + 1, ptrs[size - 1]);
                        itr = host_map.find(domain3);
                    }
                    if (itr == host_map.end()) {
                        string domain2(ptrs[size - 3] + 1, ptrs[size - 1]);
                        itr = host_map.find(domain2);
                        if (itr == host_map.end()) {
                            if (!domain3.empty())
                                id = ReadDomainId(domain3);
                            if (!id.empty()) {
                                domain = domain3;
                            } else {
                                id = ReadDomainId(domain2);
                                if (!id.empty()) {
                                    domain = domain2;
                                } else {
                                    pid_t pid = fork();
                                    ASSERT(pid != -1);
                                    if (!pid)
                                        Reply(op, conn_fd,
                                              ("Domain " +
                                               string(ptrs[0] + 1,
                                                      ptrs[size -1])));
                                    close(conn_fd);
                                    continue;
                                }
                            }
                        }
                    }
                }
                count = read(conn_fd, buf, ptr - buf);
                ASSERT(count == ptr - buf);
            }
            if (itr == host_map.end())
                itr = host_map.insert(HostMap::value_type(id, 0)).first;
            Host*& host_ptr(itr->second);
            if (host_ptr) {
                host_ptr->Run(op, conn_fd);
            } else {
                if (dev.empty()) {
                    size_t i1 = id.find_first_of(':');
                    ASSERT(i1 != string::npos);
                    dev = id.substr(0, i1);
                    size_t i2 = id.find_first_of(':', i1 + 1);
                    app = id.substr(i1 + 1, i2 - i1 - 1);
                    if (i2 != string::npos)
                        env = id.substr(i2 + 1);
                }
                host_ptr = new Host(id, dev, app, env, op, conn_fd);
            }
            if (!domain.empty()) {
                host_ptr->GetDomains().push_back(domain);
                host_map.insert(HostMap::value_type(domain, host_ptr));
            }
        }
        close(conn_fd);
        time_t now = time(0);
        for (;;) {
            Host* host_ptr = Host::GetLastPtr();
            if (!host_ptr || now - host_ptr->GetTime() < timeout)
                break;
            host_map.erase(host_ptr->GetId());
            BOOST_FOREACH(const string& domain, host_ptr->GetDomains())
                host_map.erase(domain);
            delete host_ptr;
        }
        while (waitpid(-1, 0, WNOHANG) > 0)
            ;
    }
}
