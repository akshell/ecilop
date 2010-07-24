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

////////////////////////////////////////////////////////////////////////////////
// Host
////////////////////////////////////////////////////////////////////////////////

class Host : boost::noncopyable {
public:
    static Host* GetLastPtr();

    Host(const string& domain,
         const string& app,
         const string& dev,
         const string& ws,
         const string& env,
         char op,
         int conn_fd);

    ~Host();

    string GetDomain() const;
    time_t GetTime() const;
    void Run(char op, int conn_fd);

private:
    static Host* first_ptr;
    static Host* last_ptr;

    string domain_, app_, dev_, ws_, env_;
    int carrier_fd_;
    time_t time_;
    Host* next_ptr_;
    Host* prev_ptr_;

    static void Reply(int conn_fd, const string& object);
    bool Send(char op, int conn_fd) const;
    void Launch(char op, int conn_fd);

};


Host* Host::first_ptr = 0;
Host* Host::last_ptr = 0;


Host* Host::GetLastPtr()
{
    return last_ptr;
}


Host::Host(const string& domain,
           const string& app,
           const string& dev,
           const string& ws,
           const string& env,
           char op,
           int conn_fd)
    : domain_(domain)
    , app_(app)
    , dev_(dev)
    , ws_(ws)
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


string Host::GetDomain() const
{
    return domain_;
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


void Host::Reply(int conn_fd, const string& object)
{
    string content("<h2>" + object + " not found</h2>");
    ostringstream oss;
    oss << ("HTTP/1.0 404 Not found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: ")
        << content.size() << "\r\n\r\n" << content;
    string reply(oss.str());
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
    string host_path(
        data_path +
        (app_.empty() ? "/devs/" + dev_ + '/' + ws_ : "/apps/" + app_));
    string lock_path(locks_path + '/' + domain_);
    int lock_fd = open(lock_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    ASSERT(lock_fd != -1);
    ret = flock(lock_fd, LOCK_SH);
    ASSERT(ret == 0);
    struct stat st;
    string media_path(
        host_path + (app_.empty() ? "/envs/" + env_ : "/media"));
    if (stat(media_path.c_str(), &st)) {
        ret = unlink(lock_path.c_str());
        ASSERT(ret == 0);
        if (!app_.empty())
            Reply(conn_fd, "Application " + app_);
        string dev_path(data_path + "/devs/" + dev_);
        if (stat(dev_path.c_str(), &st))
            Reply(conn_fd, "Developer " + dev_);
        string ws_path(dev_path + '/' + ws_);
        if (stat(ws_path.c_str(), &st))
            Reply(conn_fd, "Workspace " + ws_);
        else
            Reply(conn_fd, "Environment " + env_);
    }
    Send(op, conn_fd);
    string code_path(host_path + "/code");
    string schema_name(
        ':' + (app_.empty() ? dev_ + ':' + ws_ + ':' + env_ : app_));
    string tablespace_name(dev_);
    if (tablespace_name.empty()) {
        char buf[MAX_NAME_SIZE];
        int admin_fd = open(
            (host_path + "/admin").c_str(), O_RDONLY | O_CLOEXEC);
        ASSERT(admin_fd != -1);
        ssize_t size = read(admin_fd, buf, MAX_NAME_SIZE);
        ASSERT(size != -1);
        tablespace_name.assign(buf, size);
    }
    int dup_fd = dup2(fd_pair[1], STDIN_FILENO);
    ASSERT(dup_fd == STDIN_FILENO);
    const char* args[] = {
        patsak_path.c_str(), "work",
        "--app", code_path.c_str(),
        "--media", media_path.c_str(),
        "--schema", schema_name.c_str(),
        "--tablespace", tablespace_name.c_str(),
        0, 0, 0};
    if (!patsak_config_path.empty()) {
        args[10] = "--config";
        args[11] = patsak_config_path.c_str();
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
        char* ptr = buf;
        while (*ptr != ' ')
            ++ptr;
        string method(buf, ptr);
        char* ptrs[SPACE_COUNT] = {ptr};
        size_t size = 1;
        do {
            do {
                ++ptr;
            } while (*ptr != '.' && *ptr != ' ');
            ptrs[size++] = ptr;
        } while (*ptr == '.');
        ASSERT(size > 3);
        ASSERT(string(ptrs[size - 3] + 1, ptrs[size - 2]) == "akshell");
        string domain;
        string app(ptrs[size - 4] + 1, ptrs[size - 3]);
        string dev, ws, env;
        if (app == "dev") {
            if (size < 7) {
                // TODO: send an error response
                close(conn_fd);
                continue;
            }
            app = "";
            dev.assign(ptrs[size - 5] + 1, ptrs[size - 4]);
            ws.assign(ptrs[size - 6] + 1, ptrs[size - 5]);
            env.assign(ptrs[size - 7] + 1, ptrs[size - 6]);
            domain = env + '.' + ws + '.' + dev + ".akshell.com";
        } else {
            domain = app + ".akshell.com";
        }
        if (method == "STOP") {
            HostMap::iterator itr = host_map.find(domain);
            if (itr != host_map.end()) {
                delete itr->second;
                host_map.erase(itr);
            }
        } else {
            char op;
            if (method == "EVAL") {
                op = 'E';
            } else {
                op = 'H';
                count = read(conn_fd, buf, ptr - buf);
                ASSERT(count == ptr - buf);
            }
            HostMap::iterator itr =
                host_map.insert(HostMap::value_type(domain, 0)).first;
            if (itr->second)
                itr->second->Run(op, conn_fd);
            else
                itr->second = new Host(domain, app, dev, ws, env, op, conn_fd);
        }
        close(conn_fd);
        time_t now = time(0);
        for (;;) {
            Host* host_ptr = Host::GetLastPtr();
            if (!host_ptr || now - host_ptr->GetTime() < timeout)
                break;
            host_map.erase(host_ptr->GetDomain());
            delete host_ptr;
        }
        while (waitpid(-1, 0, WNOHANG) > 0)
            ;
    }
}
