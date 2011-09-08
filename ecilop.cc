// (c) 2010-2011 by Anton Korenyushkin

#include <boost/program_options.hpp>
#include <boost/unordered_map.hpp>
#include <boost/foreach.hpp>
#include <boost/utility.hpp>

#include <iostream>
#include <fstream>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/wait.h>


using namespace std;
using boost::noncopyable;
using boost::unordered_map;
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

void SetCloseOnExec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    ASSERT(flags != -1);
    int ret = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    ASSERT(ret == 0);
}

////////////////////////////////////////////////////////////////////////////////
// Worker
////////////////////////////////////////////////////////////////////////////////

class Worker : noncopyable {
public:
    enum State {
        READY,
        BUSY,
        DEAD
    };

    static void Init();

    Worker(const string& dev_name,
           const string& app_name,
           const string& env_name,
           char op,
           int conn_fd);

    ~Worker();

    State Send(char op, int conn_fd);

private:
    typedef unordered_map<pid_t, Worker*> Map;
    static Map pid_map;

    static void HandleChildEvent(int signal,
                                 siginfo_t* info_ptr,
                                 void* context_ptr);

    State state_;
    int carrier_fd_;
    pid_t pid_;
};


Worker::Map Worker::pid_map;


Worker::Worker(const string& dev_name,
               const string& app_name,
               const string& env_name,
               char op,
               int conn_fd)
    : state_(BUSY)
{
    int fd_pair[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd_pair);
    ASSERT(ret == 0);
    SetCloseOnExec(fd_pair[0]);
    SetCloseOnExec(fd_pair[1]);
    carrier_fd_ = fd_pair[0];
    pid_ = fork();
    ASSERT(pid_ != -1);
    if (pid_) {
        close(fd_pair[1]);
        pid_map.insert(Map::value_type(pid_, this));
        return;
    }
    string lock_path(locks_path + '/' + dev_name);
    int lock_fd = open(lock_path.c_str(), O_WRONLY | O_CREAT, 0600);
    ASSERT(lock_fd != -1);
    SetCloseOnExec(lock_fd);
    ret = flock(lock_fd, LOCK_SH);
    ASSERT(ret == 0);
    string dev_path(data_path + "/devs/" + dev_name);
    string app_path(dev_path + "/apps/" + app_name);
    string check_path(
        env_name.empty() ? app_path : app_path + "/envs/" + env_name);
    struct stat st;
    if (stat(check_path.c_str(), &st)) {
        if (stat(dev_path.c_str(), &st)) {
            ret = unlink(lock_path.c_str());
            ASSERT(ret == 0);
            Reply(op, conn_fd, "Developer " + dev_name);
        }
        if (env_name.empty() || stat(app_path.c_str(), &st))
            Reply(op, conn_fd, "App " + app_name);
        else
            Reply(op, conn_fd, "Environment " + env_name);
    }
    state_ = READY;
    Send(op, conn_fd);
    int dup_fd = dup2(fd_pair[1], STDIN_FILENO);
    ASSERT(dup_fd == STDIN_FILENO);
    string code_path(app_path + "/code");
    string schema_name(dev_name + ':' + app_name);
    if (!env_name.empty())
        schema_name += ':' + env_name;
    string grantor_git_path_pattern(dev_path + "/grantors/%s/%s/git");
    const char* args[] = {
        patsak_path.c_str(), "work",
        "--app", code_path.c_str(),
        "--schema", schema_name.c_str(),
        "--tablespace", dev_name.c_str(),
        "--log-id", schema_name.c_str(),
        "--git", common_git_path_pattern.c_str(),
        "--git", grantor_git_path_pattern.c_str(),
        0, 0, 0, 0, 0, 0, 0
    };
    size_t i = 14;
    string repo_name;
    if (env_name.empty()) {
        repo_name = dev_name + '/' + app_name;
        args[i++] = "--repo";
        args[i++] = repo_name.c_str();
    }
    if (!patsak_config_path.empty()) {
        args[i++] = "--config";
        args[i++] = patsak_config_path.c_str();
    }
    if (app_name == "kupishoes") {
        args[i++] = "--timeout";
        args[i++] = "10000";
    }
    execv(patsak_path.c_str(), const_cast<char**>(args));
    Fail("Failed to launch patsak");
}


Worker::~Worker()
{
    close(carrier_fd_);
    pid_map.erase(pid_);
}


void Worker::Init()
{
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = HandleChildEvent;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    int ret = sigaction(SIGRTMIN, &action, 0);
    ASSERT(ret == 0);
    action.sa_flags |= SA_NOCLDWAIT;
    ret = sigaction(SIGCHLD, &action, 0);
    ASSERT(ret == 0);
}


void Worker::HandleChildEvent(int signal,
                              siginfo_t* info_ptr,
                              void* /*context_ptr*/)
{
    Map::iterator itr = pid_map.find(info_ptr->si_pid);
    if (itr != pid_map.end())
        itr->second->state_ = signal == SIGCHLD ? DEAD : READY;
}


Worker::State Worker::Send(char op, int conn_fd)
{
    if (state_ != READY)
        return state_;
    state_ = BUSY;
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
    return sendmsg(carrier_fd_, &msg, 0) == 1 ? READY : state_ = DEAD;
}

////////////////////////////////////////////////////////////////////////////////
// Host and App declarations
////////////////////////////////////////////////////////////////////////////////

class App;


class Host : noncopyable {
public:
    static void Retire(int timeout);

    Host(App& app, const string& env_name, char op, int conn_fd);
    ~Host();

    string GetEnvName() const;
    void Run(char op, int conn_fd);

private:
    static Host* first_ptr;
    static Host* last_ptr;

    App& app_;
    string env_name_;
    vector<Worker*> worker_ptrs_;
    time_t time_;
    Host* next_ptr_;
    Host* prev_ptr_;
};


class App : noncopyable {
public:
    static App* Get(const string& dev_name, const string& app_name);
    static App& GetOrCreate(const string& dev_name, const string& app_name);
    static App* GetByDomain(const string& domain);

    ~App();

    string GetDevName() const;
    string GetAppName() const;
    void AddDomain(const string& domain);
    void Run(const string& env_name, char op, int conn_fd);
    void Stop(Host* host_ptr);
    void Stop(const string& env_name);
    void StopEnvs();

private:
    typedef unordered_map<string, App*> Map;
    static Map id_map;
    static Map domain_map;

    string dev_name_;
    string app_name_;
    string id_;
    vector<string> domains_;
    vector<Host*> host_ptrs_;

    static string GetId(const string& dev_name, const string& app_name);

    App(const string& dev_name, const string& app_name);

    void DoStop(size_t i);
};

////////////////////////////////////////////////////////////////////////////////
// Host definitions
////////////////////////////////////////////////////////////////////////////////

Host* Host::first_ptr = 0;
Host* Host::last_ptr = 0;


Host::Host(App& app, const string& env_name, char op, int conn_fd)
    : app_(app)
    , env_name_(env_name)
    , next_ptr_(0)
{
    worker_ptrs_.push_back(
        new Worker(app.GetDevName(), app.GetAppName(), env_name, op, conn_fd));
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
    BOOST_FOREACH(Worker* worker_ptr, worker_ptrs_)
        delete worker_ptr;
}


void Host::Retire(int timeout)
{
    time_t now = time(0);
    while (last_ptr && now - last_ptr->time_ >= timeout)
        last_ptr->app_.Stop(last_ptr);
}


string Host::GetEnvName() const
{
    return env_name_;
}


void Host::Run(char op, int conn_fd)
{
    ASSERT(!worker_ptrs_.empty());
    size_t i = 0;
    while (i < worker_ptrs_.size()) {
        Worker*& worker_ptr(worker_ptrs_[i]);
        Worker::State state = worker_ptr->Send(op, conn_fd);
        if (state == Worker::READY)
            break;
        if (state == Worker::BUSY) {
            ++i;
        } else {
            ASSERT(state == Worker::DEAD);
            delete worker_ptr;
            worker_ptr = *(worker_ptrs_.end() - 1);
            worker_ptrs_.erase(worker_ptrs_.end() - 1);
        }
    }
    if (i + 1 < worker_ptrs_.size())
        return;
    time_ = time(0);
    if (next_ptr_) {
        next_ptr_->prev_ptr_ = prev_ptr_;
        (prev_ptr_ ? prev_ptr_->next_ptr_ : last_ptr) = next_ptr_;
        next_ptr_ = 0;
        first_ptr->next_ptr_ = this;
        prev_ptr_ = first_ptr;
        first_ptr = this;
    }
    if (i == worker_ptrs_.size())
        worker_ptrs_.push_back(
            new Worker(app_.GetDevName(), app_.GetAppName(), env_name_,
                       op, conn_fd));
}

////////////////////////////////////////////////////////////////////////////////
// App definitions
////////////////////////////////////////////////////////////////////////////////

App::Map App::id_map;
App::Map App::domain_map;


App::App(const string& dev_name, const string& app_name)
    : dev_name_(dev_name)
    , app_name_(app_name)
{
    id_map.insert(Map::value_type(GetId(dev_name, app_name), this));
}


App::~App()
{
    id_map.erase(GetId(dev_name_, app_name_));
    BOOST_FOREACH(const string& domain, domains_)
        domain_map.erase(domain);
    BOOST_FOREACH(Host* host_ptr, host_ptrs_)
        delete host_ptr;
}


string App::GetId(const string& dev_name, const string& app_name)
{
    return dev_name + ':' + app_name;
}


App* App::Get(const string& dev_name, const string& app_name)
{
    Map::iterator itr = id_map.find(GetId(dev_name, app_name));
    return itr == id_map.end() ? 0 : itr->second;
}


App& App::GetOrCreate(const string& dev_name, const string& app_name)
{
    App* app_ptr = Get(dev_name, app_name);
    return *(app_ptr ? app_ptr : new App(dev_name, app_name));
}


App* App::GetByDomain(const string& domain)
{
    Map::iterator itr = domain_map.find(domain);
    return itr == domain_map.end() ? 0 : itr->second;
}


string App::GetDevName() const
{
    return dev_name_;
}


string App::GetAppName() const
{
    return app_name_;
}


void App::AddDomain(const string& domain)
{
    domain_map.insert(Map::value_type(domain, this));
    domains_.push_back(domain);
}


void App::Run(const string& env_name, char op, int conn_fd)
{
    BOOST_FOREACH(Host* host_ptr, host_ptrs_) {
        if (host_ptr->GetEnvName() == env_name) {
            host_ptr->Run(op, conn_fd);
            return;
        }
    }
    host_ptrs_.push_back(new Host(*this, env_name, op, conn_fd));
}


void App::Stop(Host* host_ptr)
{
    for (size_t i = 0;; ++i) {
        ASSERT(i < host_ptrs_.size());
        if (host_ptrs_[i] == host_ptr) {
            DoStop(i);
            return;
        }
    }
}


void App::Stop(const string& env_name)
{
    for (size_t i = 0; i < host_ptrs_.size(); ++i) {
        if (host_ptrs_[i]->GetEnvName() == env_name) {
            DoStop(i);
            return;
        }
    }
}


void App::StopEnvs()
{
    vector<Host*> new_host_ptrs;
    BOOST_FOREACH(Host* host_ptr, host_ptrs_) {
        if (host_ptr->GetEnvName().empty())
            new_host_ptrs.push_back(host_ptr);
        else
            delete host_ptr;
    }
    swap(host_ptrs_, new_host_ptrs);
    if (host_ptrs_.empty())
        delete this;
}


void App::DoStop(size_t i)
{
    ASSERT(i < host_ptrs_.size());
    if (host_ptrs_.size() == 1) {
        delete this;
    } else {
        delete host_ptrs_[i];
        host_ptrs_[i] = *(host_ptrs_.end() - 1);
        host_ptrs_.erase(host_ptrs_.end() - 1);
    }
}

////////////////////////////////////////////////////////////////////////////////
// main
////////////////////////////////////////////////////////////////////////////////

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


vector<string> Split(const string& str, char sep)
{
    vector<string> result;
    for (size_t i = 0; i <= str.size();) {
        size_t j = i;
        while (j < str.size() && str[j] != sep)
            ++j;
        result.push_back(str.substr(i, j - i));
        i = j + 1;
    }
    return result;
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
    return string(buf, size);
}


int main(int argc, char** argv) {
    Worker::Init();

    po::options_description generic_options("Generic options");
    generic_options.add_options()
        ("help,h", "print help message")
        ("config,c", po::value<string>()->default_value("/etc/ecilop.conf"),
         "config file")
        ;

    string log_path;
    string host;
    string port;
    int timeout;
    po::options_description config_options("Config options");
    config_options.add_options()
        ("data,d", po::value<string>(&data_path), "data directory")
        ("locks,l", po::value<string>(&locks_path), "locks directory")
        ("log,o", po::value<string>(&log_path), "log file")
        ("patsak,p", po::value<string>(&patsak_path), "patsak executable")
        ("patsak-config,C", po::value<string>(&patsak_config_path),
         "alternative patsak config")
        ("host,H", po::value<string>(&host)->default_value("127.0.0.1"), "host")
        ("port,P", po::value<string>(&port)->default_value("9864"), "port")
        ("timeout,t", po::value<int>(&timeout)->default_value(60),
         "stop timeout")
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

    RequireOption("patsak", patsak_path);
    RequireOption("data", data_path);
    RequireOption("locks", locks_path);

    common_git_path_pattern = data_path + "/devs/%s/libs/%s/git";

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* info_ptr;
    if (int ret = getaddrinfo(host.c_str(), port.c_str(), &hints, &info_ptr))
        Fail(gai_strerror(ret));
    int listen_fd = socket(
        info_ptr->ai_family, info_ptr->ai_socktype, info_ptr->ai_protocol);
    ASSERT(listen_fd != -1);
    int yes = 1;
    int ret = setsockopt(
        listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    ASSERT(ret == 0);
    if (bind(listen_fd, info_ptr->ai_addr, info_ptr->ai_addrlen))
        Fail(strerror(errno));
    freeaddrinfo(info_ptr);
    ret = listen(listen_fd, SOMAXCONN);
    ASSERT(ret == 0);

    struct sigaction action;
    action.sa_handler = HandleStop;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    ret = sigaction(SIGTERM, &action, 0);
    ASSERT(ret == 0);
    ret = sigaction(SIGINT, &action, 0);
    ASSERT(ret == 0);

    if (!log_path.empty()) {
        if (!freopen(log_path.c_str(), "a", stderr)) {
            cout << "Failed to open log file: " << strerror(errno) << '\n';
            return 1;
        }
    }

    cout << "Running at " << host << ':' << port
         << "\nQuit with Control-C." << endl;

    for (;;) {
        int conn_fd = accept(listen_fd, 0, 0);
        ASSERT(conn_fd != -1);
        SetCloseOnExec(conn_fd);
        char buf[SPACE_COUNT];
        ssize_t count = read(conn_fd, buf, SPACE_COUNT);
        ASSERT(count == static_cast<ssize_t>(SPACE_COUNT));
        ASSERT(buf[count - 1] == ' ');
        const char* ptr = buf;
        while (*ptr != ' ')
            ++ptr;
        string method(const_cast<const char*>(buf), ptr);
        bool has_leading_slash = *(++ptr) == '/';
        if (has_leading_slash)
            ++ptr;
        const char* descr_start_ptr = ptr;
        while (*ptr != ' ')
            ++ptr;
        string descr(descr_start_ptr, ptr);
        if (method == "STOP") {
            vector<string> parts(Split(descr, ':'));
            ASSERT(parts.size() == 2 || parts.size() == 3);
            if (App* app_ptr = App::Get(parts[0], parts[1])) {
                if (parts.size() == 2)
                    delete app_ptr;
                else if (parts[2].empty())
                    app_ptr->StopEnvs();
                else
                    app_ptr->Stop(parts[2]);
            }
        } else {
            App* app_ptr = 0;
            string env_name;
            char op;
            if (method == "EVAL") {
                op = 'E';
                vector<string> parts(Split(descr, ':'));
                ASSERT(parts.size() == 2 || parts.size() == 3);
                app_ptr = &App::GetOrCreate(parts[0], parts[1]);
                env_name = parts.size() == 3 ? parts[2] : "";
            } else {
                op = 'H';
                count = read(conn_fd, buf, ptr - buf);
                ASSERT(count == ptr - buf);
                vector<string> parts(Split(descr, '.'));
                ASSERT(parts.size() >= 2);
                if (has_leading_slash) {
                    app_ptr = &App::GetOrCreate(*(parts.end() - 4),
                                                *(parts.end() - 5));
                    env_name = *(parts.end() - 6);
                    if (env_name == "release")
                        env_name = "";
                } else {
                    string domain3;
                    if (parts.size() >= 3) {
                        domain3 = (*(parts.end() - 3) + '.' +
                                   *(parts.end() - 2) + '.' +
                                   *(parts.end() - 1));
                        app_ptr = App::GetByDomain(domain3);
                    }
                    if (!app_ptr) {
                        string domain2 = (*(parts.end() - 2) + '.' +
                                          *(parts.end() - 1));
                        app_ptr = App::GetByDomain(domain2);
                        if (!app_ptr) {
                            string domain;
                            string id;
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
                                        Reply(op, conn_fd, "Domain " + descr);
                                    close(conn_fd);
                                    continue;
                                }
                            }
                            vector<string> id_parts(Split(id, ':'));
                            ASSERT(id_parts.size() == 2);
                            app_ptr = &App::GetOrCreate(id_parts[0],
                                                        id_parts[1]);
                            app_ptr->AddDomain(domain);
                        }
                    }
                }
            }
            app_ptr->Run(env_name, op, conn_fd);
        }
        close(conn_fd);
        Host::Retire(timeout);
    }
}
