from datetime import datetime, timezone
import json
from pathlib import Path
import logging
from pythonjsonlogger import jsonlogger
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, session, redirect, url_for
import os

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
import seccomp

def configure_http_seccomp():
    """Filtre seccomp spécifique pour HTTP"""
    filter = seccomp.SyscallFilter(seccomp.KILL)
    allowed_syscalls = ["rmdir", "fallocate", "timer_create", "setpgid", "sysinfo","execve",
        "fadvise64", "clock_nanosleep", "timer_settime", "listen", "utimensat", "fstatfs", 
        "clock_gettime", "vfork", "syslog", "restart_syscall", "getppid", "kill", "copy_file_range", 
        "rt_sigsuspend", "getcwd", "sendmmsg", "clone", "exit_group", "bind", "recvmmsg", "eventfd2", 
        "arch_prctl", "faccessat2", "uname", "set_tid_address", "prlimit64", "setxattr", 
        "socketpair", "seccomp", "lgetxattr", "tgkill", "getpriority", "readlinkat", "setpriority", 
        "quotactl", "fsync", "statfs", "mkdir", "unlink", "sched_getaffinity", "timerfd_create", "rename", 
        "waitid", "rt_sigreturn", "accept4", "epoll_create1", "connect", "shutdown", "getrandom", "epoll_pwait", 
        "brk", "exit", "clone3", "pselect6", "statx", "getrusage", "getsockname", "rseq", "set_robust_list", 
        "readlink", "getdents64", "getgid", "getegid", "sendto", "geteuid", "sigaltstack", "pread64", "ppoll", 
        "perf_event_open", "setitimer", "getuid", "nanosleep", "memfd_create", "writev", "ftruncate", "socket", 
        "pwrite64", "getsockopt", "recvfrom", "inotify_add_watch", "dup", "access", "wait4", "rt_sigprocmask", 
        "setsockopt", "rt_sigaction", "dup2", "lseek", "prctl", "munmap", "bpf", "fstat", "mmap", "openat", 
        "epoll_ctl", "fcntl", "madvise", "newfstatat", "mprotect", "gettid", "getpid", "times", "close", "epoll_wait", 
        "timerfd_settime", "sendmsg", "ioctl", "read", "write", "recvmsg", "sched_yield", "poll", "futex"]
    
    for syscall in allowed_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall)
    filter.load()



def iso_utc_now():
    return datetime.now(timezone.utc).isoformat()

# Configuration
chemin_config = Path(__file__).resolve().parents[2] / "config" / "http_config.json"
try:
    with open(chemin_config, "r") as f:
        config_http = json.load(f)
    print("http_config.json chargé avec succès")
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"Erreur chargement http_config.json : {e}")
    config_http = {}

# Logger HTTP
def capteur_evenements_http():
    capteur = logging.getLogger('http_honeypot')
    capteur.setLevel(logging.INFO)
    capteur.propagate = False
    
    log_dossier = Path(__file__).parent / "http_logs"
    log_dossier.mkdir(exist_ok=True)
    
    log_fichier = log_dossier / "http_honeypot.log"
    destination = RotatingFileHandler(
        log_fichier,
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    
    formatteur = jsonlogger.JsonFormatter(
        '%(timestamp)s %(levelname)s %(name)s %(message)s '
        '%(client_ip)s %(method)s %(path)s %(user_agent)s '
        '%(status_code)s %(event_type)s %(payload)s',
        rename_fields={
            'levelname': 'level', 
            'name': 'logger'
        }
    )
    
    destination.setFormatter(formatteur)
    capteur.addHandler(destination)
    return capteur

capteur_http = capteur_evenements_http()

class HTTPHoneypot:
    def __init__(self):
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        self.app.secret_key = 'bite_delight_secret_key_2025'
        self.fake_creds = config_http.get('http_honeypot', {}).get('fake_website', {}).get('fake_credentials', {})
        self._setup_routes()
    
    def _log_request(self, event_type='normal_request', level='INFO', custom_message=None, username=None, password_tested=None):
        """Fonction centralisée pour logger les requêtes"""
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Gestion du payload selon la méthode
        if request.method == 'GET' and request.args:
            payload = '&'.join([f"{k}={v}" for k, v in request.args.items()])
        elif request.method == 'POST' and request.form:
            payload = '&'.join([f"{k}={v}" for k, v in request.form.items()])
        else:
            payload = request.get_data(as_text=True) or ''
        
        message = custom_message or "HTTP_REQUEST"
        
        # Préparer les données extra
        extra_data = {
            'timestamp': iso_utc_now(),
            'client_ip': client_ip,
            'method': request.method,
            'path': request.path,
            'user_agent': user_agent,
            'status_code': 200,
            'event_type': event_type,
            'payload': payload[:500],  # Limiter la taille
            'honeypot_type': 'http'
        }
        
        # Ajouter username et password_tested si fournis
        if username is not None:
            extra_data['username'] = username
        if password_tested is not None:
            extra_data['password_tested'] = password_tested
        
        log_method = getattr(capteur_http, level.lower())
        log_method(message, extra=extra_data)
    
    def _detect_suspicious_activity(self, path, data):
        """Détecte les activités suspectes"""
        suspicious_paths = ['/admin', '/phpmyadmin', '/wp-admin', '/.env', '/backup', '/shell', '/cmd']
        sql_keywords = ['union select', 'sleep(', 'drop table', 'or 1=1', 'insert into', 'update set']
        xss_keywords=['script','img','svg','onerror','<','`', '$']
        command_keywords = [';', '|', '&', '>', '*','cat','ls']
        
        path_lower = path.lower()
        data_lower = data.lower()
        
        # Scan de répertoire
        if any(scanner in path_lower for scanner in suspicious_paths):
            return 'directory_scan'
        
        # Injection SQL
        if any(sql in data_lower for sql in sql_keywords):
            return 'sql_injection_attempt'
            
        # Injection SQL
        if any(xss in data_lower for xss in xss_keywords):
            return 'xss_injection_attempt'
            
        # Injection de commande (pour la recherche)
        if '/api/recherche' in path and any(cmd in data_lower for cmd in command_keywords):
            return 'rce_injection_attempt'
        
        return 'normal_request'
    
    def _setup_routes(self):
        """Configure toutes les routes du honeypot"""
        
        @self.app.before_request
        def before_request():
            """Détection d'activités suspectes avant traitement"""
            # Ne pas logger les ressources statiques
            if request.path.startswith('/static/'):
                return
            
            request_data = request.get_data(as_text=True) or ''
            if request.method == 'GET' and request.args:
                request_data = '&'.join([f"{k}={v}" for k, v in request.args.items()])
            
            event_type = self._detect_suspicious_activity(request.path, request_data)
            
            # Logger uniquement les événements suspects 
            if event_type != 'normal_request':
                self._log_request(
                    event_type=event_type, 
                    level='WARNING',
                    custom_message=f"HTTP_SUSPICIOUS_{event_type.upper()}"
                )
        
        @self.app.route('/')
        def index():
            """Page d'accueil principale"""
            # Logger uniquement une fois via after_request
            return render_template('index.html')
        
        @self.app.route('/api/login', methods=['POST'])
        def handle_login():
            """Traite les tentatives de login"""
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            
            # Vérification des credentials
            if username in self.fake_creds and self.fake_creds[username] == password:
                self._log_request(
                    event_type='accepted_credentials',
                    level='CRITICAL',
                    custom_message="HTTP_ACCEPTED_CREDENTIALS",
                    username=username,
                    password_tested=password
                )
                session['username'] = username
                return redirect(url_for('catalogue'))
            else:
                self._log_request(
                    event_type='rejected_credentials', 
                    level='CRITICAL',
                    custom_message="HTTP_REJECTED_CREDENTIALS",
                    username=username,
                    password_tested=password
                )
                return render_template('index.html', error="Identifiants invalides! Veuillez réessayer.")

        @self.app.route('/catalogue')
        def catalogue():
            """Page de plats"""
            if 'username' not in session:
                return redirect(url_for('index'))
            # Logger uniquement une fois via after_request
            return render_template('catalogue.html')

        @self.app.route('/api/recherche', methods=['GET'])
        def recherche():
            """Recherche vulnérable aux injections"""
            if 'username' not in session:
                return redirect(url_for('index'))
                
            plat = request.args.get('recherché', '')    
            
            # Logger seulement les recherches normales
            # Les injections sont déjà loggées dans before_request
            event_type = self._detect_suspicious_activity(request.path, plat)
            if event_type == 'normal_request':
                self._log_request(
                    event_type='search_query',
                    level='WARNING', 
                    custom_message="HTTP_SEARCH_ATTEMPT"
                )
            
            # Exécution vulnérable
            commande = f'cat /home/salma-elmrabet/Plateforme/honeypots/http/{plat}'
            os.system(commande + " > resultat.txt 2>&1")
            
            try:
                with open("resultat.txt", "r", encoding="utf-8", errors="ignore") as f:
                    sortie = f.read()
            except FileNotFoundError:
                sortie = "(aucune sortie)"

            return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Résultats de recherche</title>
                <style>
                    body {{ font-family: Arial; background: black; color: white; padding: 20px; }}
                    .result {{ background: #333; padding: 20px; border-radius: 10px; margin: 20px 0; }}
                    h1 {{ color: orange; }}
                    .back-btn {{ background: orange; color: black; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }}
                </style>
            </head>
            <body>
                <h1>Détails pour: "{plat}"</h1>
                <a href="/catalogue" class="back-btn">← Retour au catalogue</a>
                <div class="result">
                    <pre>{sortie}</pre>
                </div>
            </body>
            </html>
            '''
     
    def run(self, host='0.0.0.0', port=8080, debug=False):
        """Démarre le serveur Flask"""
        print(f"HTTP honeypot démarré sur {host}:{port}")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)

def start_http_honeypot():
    """Fonction appelée depuis main.py"""
    configure_http_seccomp()
    honeypot = HTTPHoneypot()
    honeypot.run(host="0.0.0.0", port=8080)

if __name__ == '__main__':
    start_http_honeypot()
