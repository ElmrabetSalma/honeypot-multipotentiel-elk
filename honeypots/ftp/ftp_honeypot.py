from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from datetime import datetime, timezone
import logging
from pythonjsonlogger import jsonlogger
from logging.handlers import RotatingFileHandler
from pathlib import Path

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
import seccomp

def configure_ftp_seccomp():
    """Filtre seccomp spécifique pour FTP"""
    filter = seccomp.SyscallFilter(seccomp.KILL)
    allowed_syscalls = ["renameat", "unlinkat", "fadvise64", "umount", "symlinkat", 
        "name_to_handle_at", "alarm", "setsid", "timer_create", "fchmod", "flock", "add_key", 
        "getpgrp", "timer_settime", "fchown", "capset", "getppid", "sched_setscheduler", 
        "socketpair", "keyctl", "setxattr", "sendfile64", "landlock_restrict_self", "sched_getaffinity", 
        "sched_getparam", "dup3", "mkdir", "inotify_rm_watch", "chdir", "ioprio_set", "sched_getscheduler", 
        "rmdir", "copy_file_range", "rt_sigsuspend", "shutdown", "setpriority", "setresgid", "pidfd_open", 
        "setresuid", "setfsgid", "landlock_create_ruleset", "clock_nanosleep", "listen", "mlock", "umask", 
        "getpriority", "setfsuid", "close_range", "accept4", "utimensat", "fallocate", "capget", "setpgid", 
        "link", "waitid", "exit_group", "fstatfs", "removexattr", "rename", "syslog", "clone", "execve", 
        "arch_prctl", "set_tid_address", "memfd_create", "getpeername", "exit", "epoll_pwait2", "unlink", 
        "fsync", "lgetxattr", "clone3", "seccomp", "pipe2", "bind", "uname", "ppoll", "connect", 
        "epoll_create1", "tgkill", "statfs", "faccessat2", "ftruncate", "rseq", "eventfd2", "statx", 
        "rt_sigreturn", "getrusage", "set_robust_list", "landlock_add_rule", "getsockname", "prlimit64", 
        "getcwd", "sched_yield", "kill", "readlinkat", "pwrite64", "kcmp", "prctl", "brk", "timerfd_create", 
        "perf_event_open", "getrandom", "rt_sigprocmask", "munmap", "recvmmsg", "epoll_pwait", "getdents64", 
        "dup", "madvise", "recvfrom", "pread64", "sendto", "getgid", "pselect6", "getegid", "lseek", "geteuid", 
        "getuid", "nanosleep", "dup2", "socket", "readlink", "access", "getsockopt", "setsockopt", "rt_sigaction", 
        "inotify_add_watch", "setitimer", "mmap", "writev", "fcntl", "gettid", "wait4", "newfstatat", "bpf", 
        "epoll_ctl", "fstat", "mprotect", "openat", "sendmsg", "epoll_wait", "times", "close", "getpid", "futex", 
        "ioctl", "timerfd_settime", "read", "poll", "write", "recvmsg"]
    
    for syscall in allowed_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall)
    filter.load()

    
def iso_utc_now():
    return datetime.now(timezone.utc).isoformat()

def setup_ftp_logger():
    capteur = logging.getLogger('ftp_honeypot')
    
    if capteur.handlers:
        return capteur
        
    capteur.setLevel(logging.INFO)
    capteur.propagate = False
    
    log_dossier = Path(__file__).parent / "ftp_logs"
    log_dossier.mkdir(exist_ok=True)
    
    log_fichier = log_dossier / "ftp_honeypot.log"
    destination = RotatingFileHandler(
        log_fichier,
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    
    formatteur = jsonlogger.JsonFormatter(
        '%(timestamp)s %(levelname)s %(name)s %(message)s '
        '%(client_ip)s %(username)s %(password)s %(ftp_command)s %(file_path)s '
        '%(response_code)s %(event_type)s %(payload)s',
        timestamp=True,
        rename_fields={
            'timestamp': 'timestamp',
            'levelname': 'level', 
            'name': 'logger'
        }
    )
    
    destination.setFormatter(formatteur)
    capteur.addHandler(destination)
    return capteur

ftp_logger = setup_ftp_logger()

class FTPHoneypotHandler(FTPHandler):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_attempts=0
        self.max_auth_attempts=5  # Nombre max de tentatives autorisées
    
    def ftp_CONN(self, line):
        """Nouvelle connexion"""
        ftp_logger.info("FTP_CONNECTION_START", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.remote_ip,
            'username': 'none',
            'password': 'none',
            'ftp_command': 'CONNECT',
            'file_path': '/',
            'response_code': 220,
            'event_type': 'connection_start',
            'payload': 'New FTP connection established',
            'honeypot_type': 'ftp'
        })
        return super().ftp_CONN(line)
    
    def ftp_USER(self, username):
        """Tentative de connexion utilisateur"""
        self.username = username
        self.auth_attempts = 0  # Réinitialiser les tentatives pour nouveau user
        ftp_logger.info("FTP_USER_ATTEMPT", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.remote_ip,
            'username': username,
            'password': 'none',
            'ftp_command': 'USER',
            'file_path': '/',
            'response_code': 331,
            'event_type': 'user_attempt',
            'payload': f'Username provided: {username}',
            'honeypot_type': 'ftp'
        })
        return super().ftp_USER(username)
    
    def ftp_PASS(self, password):
        """Mot de passe fourni"""
        username = getattr(self, 'username', 'unknown')
        self.auth_attempts += 1
        
        # Vérifier si l'authentification réussit
        auth_success = False
        try:
            if hasattr(self, 'authorizer') and self.authorizer.has_user(username):
                # Vérifier le mot de passe
                user_info = self.authorizer.user_table.get(username)
                if user_info and user_info['pwd'] == password:
                    auth_success = True
        except:
            auth_success = False
        
        # Logger selon le résultat
        if auth_success:
            ftp_logger.critical("FTP_ACCEPTED_CREDENTIALS", extra={
                'timestamp': iso_utc_now(),
                'client_ip': self.remote_ip,
                'username': username,
                'password': password,
                'ftp_command': 'PASS',
                'file_path': '/',
                'response_code': 230,
                'event_type': 'accepted_credentials',
                'payload': f'Successful authentication - User: {username}',
                'honeypot_type': 'ftp',
                'auth_attempt': self.auth_attempts
            })
            return super().ftp_PASS(password)
        else:
            ftp_logger.warning("FTP_REJECTED_CREDENTIALS", extra={
                'timestamp': iso_utc_now(),
                'client_ip': self.remote_ip,
                'username': username,
                'password': password,
                'ftp_command': 'PASS',
                'file_path': '/',
                'response_code': 530,
                'event_type': 'rejected_credentials',
                'payload': f'Failed authentication - User: {username}, Attempt: {self.auth_attempts}',
                'honeypot_type': 'ftp',
                'auth_attempt': self.auth_attempts
            })
            
            # permettre de réessayer
            if self.auth_attempts < self.max_auth_attempts:
                self.respond("530 Authenrification echouée. réessayez")
                # Réinitialiser l'état d'authentification pour permettre un nouveau USER
                self.authenticated = False
                self.username = None
                return None
            else:
                # Après trop de tentatives, fermer la connexion
                self.respond("530 Beaucoup de tentatives incorrectes")
                self.close_when_done()
                return None
    
    def ftp_RETR(self, filename):
        """Téléchargement de fichier"""
        if not getattr(self, 'authenticated', False):
            self.respond("530 Non authentifié")
            return
        
        ftp_logger.warning("FTP_FILE_DOWNLOADED", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.remote_ip,
            'username': getattr(self, 'username', 'unknown'),
            'password': 'none',
            'ftp_command': 'RETR',
            'file_path': filename,
            'response_code': 226,
            'event_type': 'file_downloaded',
            'payload': f'File downloaded: {filename}',
            'honeypot_type': 'ftp'
        })
        return super().ftp_RETR(filename)
    
    def ftp_STOR(self, filename):
        """Sockage d'un fichier """
        if not getattr(self, 'authenticated', False):
            self.respond("530 Non authentifié")
            return
            
        ftp_logger.critical("FTP_FILE_UPLOADED", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.remote_ip,
            'username': getattr(self, 'username', 'unknown'),
            'password': 'none',
            'ftp_command': 'STOR',
            'file_path': filename,
            'response_code': 226,
            'event_type': 'file_uploaded',
            'payload': f'File uploaded: {filename}',
            'honeypot_type': 'ftp' 
        })
        return super().ftp_STOR(filename)
    
    def ftp_DELE(self, filename):
        """Suppression de fichier"""
        if not getattr(self, 'authenticated', False):
            self.respond("530 Non authentifié.")
            return
            
        ftp_logger.critical("FTP_FILE_DELETED", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.remote_ip,
            'username': getattr(self, 'username', 'unknown'),
            'password': 'none',
            'ftp_command': 'DELE',
            'file_path': filename,
            'response_code': 250,
            'event_type': 'file_deleted',
            'payload': f'File deleted: {filename}',
            'honeypot_type': 'ftp'
        })
        return super().ftp_DELE(filename)
    
    def ftp_RMD(self, path):
        """Suppression de répertoire - ÉVÉNEMENT CRITIQUE"""
        if not getattr(self, 'authenticated', False):
            self.respond("530 Non authentifié.")
            return
            
        ftp_logger.critical("FTP_DIRECTORY_DELETED", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.remote_ip,
            'username': getattr(self, 'username', 'unknown'),
            'password': 'none',
            'ftp_command': 'RMD',
            'file_path': path,
            'response_code': 250,
            'event_type': 'directory_deleted',
            'payload': f'Directory deleted: {path}',
            'honeypot_type': 'ftp'
        })
        return super().ftp_RMD(path)
    
    def ftp_QUIT(self, line):
        """Déconnexion"""
        ftp_logger.info("FTP_CONNECTION_END", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.remote_ip,
            'username': getattr(self, 'username', 'unknown'),
            'password': 'none',
            'ftp_command': 'QUIT',
            'file_path': '/',
            'response_code': 221,
            'event_type': 'connection_end',
            'payload': 'Client disconnected',
            'honeypot_type': 'ftp'
        })
        return super().ftp_QUIT(line)

def autorisations():
    authorizer = DummyAuthorizer()
    authorizer.add_user("Salma", "password@", "/tmp/FTP/Salma", perm="elradfmw")
    authorizer.add_user("Douae", "password@12", "/tmp/FTP/Douae", perm="elradfmw")
    authorizer.add_user("Wijdane", "password@123", "/tmp/FTP/Wijdane", perm="elradfmw")
    authorizer.add_user("Wiam", "password@1234", "/tmp/FTP/Wiam", perm="elradfmw")
    return authorizer

def connexion_handler():
    handler = FTPHoneypotHandler
    handler.authorizer = autorisations()
    handler.banner = "220 Welcome to FTP Server - Authentication Required"
    handler.max_login_attempts = 5  # Permettre plusieurs tentatives
    return handler

def start_ftp_server():
    configure_ftp_seccomp()    
    FTP_Server = FTPServer(("0.0.0.0", 2121), connexion_handler())
    print(f"FTP serveur démarré sur 0.0.0.0:2121")
    print("Configuration: 5 tentatives de mot de passe autorisées par connexion")
    FTP_Server.serve_forever()

if __name__ == "__main__":
    start_ftp_server()
