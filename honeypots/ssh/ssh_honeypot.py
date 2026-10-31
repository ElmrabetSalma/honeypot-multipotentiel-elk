from datetime import datetime, timezone
import json
from pathlib import Path
import logging
from pythonjsonlogger import jsonlogger
from logging.handlers import RotatingFileHandler
import asyncssh
import asyncio
import subprocess
import sys
import os

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
import seccomp

def configure_ssh_seccomp():
    """Filtre seccomp spécifique pour SSH"""
    filter = seccomp.SyscallFilter(seccomp.KILL)
    allowed_syscalls = ["add_key", "clock_adjtime", "umount", "sched_getaffinity", "timer_settime", 
        "fchmod", "socketpair", "name_to_handle_at", "renameat", "alarm", "memfd_create", "flock", 
        "fchown", "fallocate", "setsid", "capset", "listen", "timer_create", "chmod", "symlinkat", 
        "exit", "rt_sigsuspend", "keyctl", "dup3", "epoll_create1", "shutdown", "fadvise64", "inotify_rm_watch", 
        "rmdir", "setxattr", "clone", "fsync", "clone3", "setresuid", "setresgid", "accept4", "setpgid", "mkdir", 
        "clock_nanosleep", "kill", "rename", "getpeername", "waitid", "capget", "setitimer", "umask", "utimensat", 
        "fstatfs", "removexattr", "syslog", "pidfd_open", "chdir", "getppid", "unlink", "ftruncate", "lgetxattr", 
        "sched_yield", "bind", "writev", "vfork", "getcwd", "exit_group", "epoll_pwait2", "statfs", "uname", 
        "arch_prctl", "set_tid_address", "madvise", "close_range", "tgkill", "faccessat2", "rseq", "getrusage", 
        "connect", "set_robust_list", "statx", "execve", "pipe2", "rt_sigreturn", "getsockname", "pread64", "munmap", 
        "prctl", "readlinkat", "prlimit64", "kcmp", "timerfd_create", "perf_event_open", "recvfrom", "brk", "sendto", 
        "recvmmsg", "epoll_pwait", "getdents64", "pselect6", "dup", "readlink", "getegid", "getgid", "geteuid", "getuid", 
        "nanosleep", "mmap", "dup2", "access", "socket", "epoll_ctl", "lseek", "getsockopt", "setsockopt", "mprotect", 
        "fcntl", "inotify_add_watch", "getrandom", "rt_sigaction", "gettid", "wait4", "newfstatat", "bpf", "ppoll", 
        "fstat", "openat", "sendmsg", "epoll_wait", "rt_sigprocmask", "times", "close", "getpid", "futex", "ioctl", 
        "timerfd_settime", "read", "poll", "recvmsg", "write"]
    
    for syscall in allowed_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall)
    filter.load()
    
# Résoudre le problème de différence de temps entre zones
def iso_utc_now():
    return datetime.now(timezone.utc).isoformat()

# Lecture de credentials.json
def charger_credentials():
    base_dir = Path.cwd()
    chemin_credentials = base_dir / "config" / "credentials.json"
    
    try:
        with open(chemin_credentials, "r") as f:
            credentials = json.load(f)
        print("credentials.json chargé avec succès")
        return credentials
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Erreur lors du chargement du fichier credentials.json : {e}")
        sys.exit(1)

# Création du logger 
def setup_ssh_logger():
    """Configure le logger une seule fois au démarrage"""
    
    capteur = logging.getLogger('ssh_honeypot')
    if capteur.handlers:
        return capteur
        
    capteur.setLevel(logging.INFO)
    capteur.propagate = False 
    
    log_dossier = Path(__file__).parent / "ssh_logs"
    log_dossier.mkdir(exist_ok=True)
    
    log_fichier = log_dossier / "ssh_honeypot.log"
    destination = RotatingFileHandler(
        log_fichier, 
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    
    formatteur = jsonlogger.JsonFormatter(
        '%(timestamp)s %(levelname)s %(name)s %(message)s '
        '%(client_ip)s %(username)s %(password)s %(event_type)s %(auth_attempt)s '
        '%(command)s %(error)s',
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

ssh_logger = setup_ssh_logger()

class SSHServer(asyncssh.SSHServer):
    def __init__(self, credentials):
        super().__init__()
        self.credentials = credentials
        self.auth_attempts = 0
        self.client_ip = None
        self.username = None
        self.authenticated_user = None
        self.connection = None

    def connection_made(self, conn):
        super().connection_made(conn)
        self.connection = conn
        self.client_ip = conn.get_extra_info('peername')[0]
        
        # Logger la connexion entrante
        ssh_logger.info("SSH_CONNECTION_ESTABLISHED", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.client_ip,
            'username': 'NONE',
            'password': 'NONE',
            'event_type': 'connection_start',
            'auth_attempt': 0,
            'command': 'none',
            'honeypot_type': 'ssh'
        })

    def connection_lost(self, exc):
        super().connection_lost(exc) 
        # Logger la fermeture de connexion
        ssh_logger.info("CONNECTION_CLOSED", extra={
            'timestamp': iso_utc_now(),
            'client_ip': self.client_ip,
            'username': self.username or 'NONE',
            'password': 'NONE',
            'event_type': 'connection_end',
            'auth_attempt': self.auth_attempts,
            'command': 'none',
            'honeypot_type': 'ssh'
        })

    def begin_auth(self, username):
        result = super().begin_auth(username) 
        self.username = username
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.auth_attempts += 1
        self.username = username
        
        accepted = self.credentials.get('accepted', {})
        valid_usernames = self.credentials.get('valid_usernames', [])
        
        # Logger TOUTES les tentatives d'authentification avec username et password
        if username in accepted and accepted[username] == password:
            self.authenticated_user = username
            if self.connection:
                self.connection.authenticated_user = username
            
            # Login réussi 
            ssh_logger.critical("LOGIN_SUCCESS", extra={
                'timestamp': iso_utc_now(),
                'client_ip': self.client_ip,
                'username': username,
                'password': password,
                'event_type': 'accepted_credentials',  
                'auth_attempt': self.auth_attempts,
                'command': 'none',
                'honeypot_type': 'ssh'
            })
            return True
        else:
            # Login rejeté 
            ssh_logger.warning("LOGIN_REJECTED", extra={
                'timestamp': iso_utc_now(),
                'client_ip': self.client_ip,
                'username': username,
                'password': password,
                'event_type': 'credentials_rejected',  
                'auth_attempt': self.auth_attempts,
                'command': 'none',
                'honeypot_type': 'ssh'
            })
            return False

def get_user_home_directory(username):
    """Retourne le chemin du répertoire home de l'utilisateur"""
    temp_base = Path("/tmp/users_home")
    user_home = temp_base / username
    
    try:
        user_home.mkdir(parents=True, exist_ok=True)
        os.chmod(user_home, 0o755)
    except Exception as e:
        user_home = Path("/tmp")
    
    return user_home

async def handle_client(process):
    """Gère les sessions SSH - Utilise le logger global"""
    
    client_ip = 'UNKNOWN'
    authenticated_user = 'UNKNOWN'
    
    try:
        # Obtenir l'IP du client et l'utilisateur authentifié
        try:
            if process.channel and process.channel.get_connection():
                conn = process.channel.get_connection()
                peername = conn.get_extra_info('peername')
                if peername:
                    client_ip = peername[0]
                
                if hasattr(conn, 'authenticated_user'):
                    authenticated_user = conn.authenticated_user
        except Exception:
            pass
        
        if authenticated_user == 'UNKNOWN':
            authenticated_user = 'guest'
        
        user_home = get_user_home_directory(authenticated_user)
        
        # Environnement minimal du shell
        env = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': str(user_home),
            'USER': authenticated_user,
            'TERM': 'xterm',
            'SHELL': '/bin/bash',
            'PS1': f'{authenticated_user}@ssh:\\w\\$ ',
            'PWD': str(user_home),
        }
        
        # Commande directe (non interactive)
        if hasattr(process, 'command') and process.command:
            # Logger les commandes directes
            ssh_logger.info("DIRECT_COMMAND", extra={
                'timestamp': iso_utc_now(),
                'client_ip': client_ip,
                'username': authenticated_user,
                'password': 'NONE',
                'event_type': 'direct_command',
                'auth_attempt': 1,
                'command': process.command,
                'honeypot_type': 'ssh'
            })
            
            try:
                result = await asyncio.create_subprocess_shell(
                    process.command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=str(user_home)
                )
                stdout, stderr = await result.communicate()
                
                if stdout:
                    process.stdout.write(stdout)
                if stderr:
                    process.stderr.write(stderr)
                    
                process.exit(result.returncode)
            except Exception as e:
                process.exit(1)
                
        # Shell interactif
        else:
            welcome_msg = f"""Bienvenue {authenticated_user}!
Vous êtes connecté au serveur SSH.

Tapez 'exit' pour vous déconnecter.

{authenticated_user}@ssh:~$ """
            
            process.stdout.write(welcome_msg)
            await process.stdout.drain()
            
            try:
                async for command in process.stdin:
                    command = command.rstrip('\n\r')
                    
                    if not command:
                        process.stdout.write(f"{authenticated_user}@ssh:~$ ")
                        await process.stdout.drain()
                        continue
                    
                    if command in ['exit', 'quit', 'logout']:
                        process.stdout.write("Déconnexion...\n")
                        await process.stdout.drain()
                        break
                    
                    # Logger les commandes exécutées
                    ssh_logger.info("COMMAND_EXECUTED", extra={
                        'timestamp': iso_utc_now(),
                        'client_ip': client_ip,
                        'username': authenticated_user,
                        'password': 'NONE',
                        'event_type': 'command_executed',
                        'auth_attempt': 1,
                        'command': command,
                        'honeypot_type': 'ssh'
                    })
                    
                    # Exécuter la commande
                    try:
                        proc = await asyncio.create_subprocess_shell(
                            command,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.STDOUT,
                            env=env,
                            cwd=str(user_home)
                        )
                        
                        stdout_bytes, _ = await proc.communicate()
                        
                        if stdout_bytes:
                            stdout_str = stdout_bytes.decode('utf-8', errors='replace')
                            process.stdout.write(stdout_str)
                        
                        process.stdout.write(f"{authenticated_user}@ssh:~$ ")
                        await process.stdout.drain()
                        
                    except Exception as e:
                        process.stdout.write(f"Erreur lors de l'exécution: {str(e)}\n")
                        process.stdout.write(f"{authenticated_user}@ssh:~$ ")
                        await process.stdout.drain()
                        
            except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, EOFError, Exception):
                pass
                        
    except Exception as e:
        # Logger uniquement les vraies erreurs
        ssh_logger.error("HANDLE_CLIENT_ERROR", extra={
            'timestamp': iso_utc_now(),
            'client_ip': client_ip,
            'username': authenticated_user,
            'password': 'NONE',
            'event_type': 'handle_client_error',
            'auth_attempt': 0,
            'command': 'none',
            'error': str(e),
            'honeypot_type': 'ssh'
        })

def verifier_cle_existante(host_key_path):
    """Vérifie que la clé host RSA existe"""
    if not host_key_path.exists():
        print(f"Clé host manquante: {host_key_path}")
        return False
    
    pub_key_path = host_key_path.with_suffix(host_key_path.suffix + '.pub')
    if not pub_key_path.exists():
        print(f"Clé publique manquante: {pub_key_path}")
        return False
    
    print(f"Clé host trouvée: {host_key_path}")
    return True

async def start_ssh_server():
    """Démarre le serveur SSH avec asyncssh"""
    configure_ssh_seccomp()
    credentials = charger_credentials()
    
    host_key_path = Path(__file__).parent / "ssh_rsa.key"
    
    if not verifier_cle_existante(host_key_path):
        print("Impossible de démarrer le serveur SSH: clé host manquante")
        return
        
    try:
        server = await asyncssh.create_server(
            lambda: SSHServer(credentials),
            '0.0.0.0',
            2222,
            server_host_keys=[str(host_key_path)],
            process_factory=handle_client,
            server_version='SSH-2.0-OpenSSH_8.9'
        )
        print("Serveur SSH démarré sur le port 2222")
        print("En attente de connexions...")
        
        await server.wait_closed()
        
    except Exception as e:
        ssh_logger.error("SERVER_START_ERROR", extra={
            'timestamp': iso_utc_now(),
            'client_ip': '0.0.0.0',
            'username': 'NONE',
            'password': 'NONE',
            'event_type': 'server_error',
            'auth_attempt': 0,
            'command': 'none',
            'error': str(e),
            'honeypot_type': 'ssh'
        })
        print(f"Erreur démarrage serveur SSH: {e}")

if __name__ == "__main__":
    asyncio.run(start_ssh_server())
