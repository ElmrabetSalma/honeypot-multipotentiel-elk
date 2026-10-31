<h1> Plateforme Multi-Honeypots avec Confinement (Seccomp/AppArmor) & Analyse ELK</h1>

Déploiement d'un réseau de honeypots (HTTP, SSH, FTP) pour la collecte de tentatives d'intrusion. Ce projet met en œuvre une approche en deux temps : <b>la détection/visualisation</b> des attaques via la stack ELK (SIEM), et <b>le confinement strict</b> des services avec Seccomp et AppArmor pour réduire la surface d'attaque, même en cas de compromission.

<h2> Aperçu du projet</h2>

<p><b>1. Simulation d'attaques (Détection & Logs)</b><br>
Les honeypots capturent et structurent en JSON toutes les tentatives (XSS, SQLi, Scan de répertoires, Brute Force).</p>
<p align="center">
  <img width="762" height="502" alt="image" src="https://github.com/user-attachments/assets/69baf93d-7e35-4c0e-bf0b-31f3690d3f2f" />
  <br>
  <em>Injection de commande (RCE) via le formulaire de recherche</em>
</p>
<p align="center">
  <img width="1156" height="240" alt="image" src="https://github.com/user-attachments/assets/6440cfe3-6b06-4b1a-af73-b940e9da2b7b" />
  <br>
  <em>Attaque par force brute sur le service SSH avec Hydra</em>
</p>

<p><b>2. Confinement (Seccomp & AppArmor)</b><br>
Même après une authentification SSH réussie, les commandes critiques (accès aux fichiers, suppression) sont bloquées par les filtres de sécurité.</p>
<p align="center">
  <img width="785" height="412" alt="image" src="https://github.com/user-attachments/assets/271cd847-20ce-43ca-9ad9-7d8b1edc3d2a" />
  <br>
  <em>Accès refusé (<code>Permission denied</code>) suite à l'application du filtre Seccomp et d'AppArmor</em>
</p>

<p><b>3. Analyse SIEM avec Kibana</b><br>
Visualisation en temps réel des tentatives d'attaques et des fichiers ciblés.</p>
<p align="center">
  <img width="985" height="495" alt="image" src="https://github.com/user-attachments/assets/068dcd62-c7fb-4892-abc6-e5ce4061b2c4" />
  <br>
  <em>Comparaison des types d'injections détectées</em>
</p>
<p align="center">
  <img width="952" height="502" alt="image" src="https://github.com/user-attachments/assets/69aefe7d-75a8-46b3-b131-7d744c44397b" />
  <br>
  <em>Analyse des répertoires les plus scannés par les attaquants</em>
</p>

<h2> Objectifs et Démarche</h2>

Ce projet s'articule autour de deux axes majeurs :

<h3> Axe 1 : Détection, Journalisation et Visualisation (SIEM)</h3>
<ul>
<li>Déploiement de 3 honeypots (HTTP, SSH, FTP) simulant des services vulnérables.</li>
<li><b>Collecte structurée (JSON)</b> : chaque tentative d'authentification, commande exécutée ou requête web est loguée.</li>
<li><b>Analyse ELK</b> : ingestion via Filebeat/Logstash, stockage dans Elasticsearch et création de dashboards Kibana pour cartographier les attaques (Brute Force, XSS, SQLi, Gobuster).</li>
</ul>

<h3> Axe 2 : Confinement et Réduction de la Surface d'Attaque</h3>
<ul>
<li>Les honeypots sont volontairement vulnérables (ex: RCE via <code>os.system</code> dans le HTTP, Shell interactif dans le SSH).</li>
<li><b>Filtres Seccomp</b> : Restriction stricte des appels système autorisés pour chaque honeypot (identifiés via <code>bpftrace</code>).</li>
<li><b>Profil AppArmor</b> : Blocage de la lecture des fichiers sensibles (ex: <code>/etc/passwd</code>, <code>/etc/shadow</code>) et interdiction des commandes de modification/suppression (ex: <code>rm</code>, <code>touch</code>).</li>
<li><i>Résultat</i> : L'attaquant peut interagir avec le leurre, mais ne peut ni compromettre l'hôte, ni exfiltrer de données réelles.</li>
</ul>

<h2> Architecture</h2>

<pre><code>[ Attaquant (Kali) ]
      │
      ├──> Honeypot HTTP (Port 8080)──┐
      ├──> Honeypot SSH (Port 2222) ──┼──> Logs JSONL sécurisés (Seccomp/AppArmor)
      └──> Honeypot FTP (Port 2121) ──┘
                                            │
                                            ▼ (Filebeat)
                                       [ Logstash ]
                                            │
                                            ▼
                                    [ Elasticsearch ]
                                            │
                                            ▼
                                    [ Kibana ] (Dashboards d'analyse)
</code></pre>

<h2> Technologies</h2>

<ul>
<li><b>Python 3.10+</b> (Flask, AsyncSSH, Pyftpdlib, Asyncio)</li>
<li><b>Seccomp / AppArmor</b> (Isolation des processus et contrôle d'accès)</li>
<li><b>Stack ELK</b> (Elasticsearch, Logstash, Kibana)</li>
<li><b>Filebeat</b> (Collecte des logs)</li>
<li><b>bpftrace</b> (Traçage des appels système)</li>
</ul>

<h2> Lancer le projet</h2>

<h3>1. Installer les dépendances</h3>
<p><code>pip install -r requirements.txt</code></p>

<h3>2. Démarrer les honeypots</h3>
<p><code>python main.py</code></p>
<p><i>Cela lancera les 3 serveurs en parallèle. Assurez-vous d'avoir configuré les fichiers <code>config/credentials.json</code> et <code>config/http_config.json</code>.</i></p>

<h3>3. Simuler des attaques</h3>
<ul>
<li><b>Injection de commande (HTTP)</b> : <br> <code>curl "http://localhost:8080/api/recherche?recherché=;cat%20/etc/passwd"</code></li>
<li><b>Brute Force (SSH)</b> : <br> <code>hydra -l web -P /usr/share/wordlists/rockyou.txt ssh://localhost:2222</code></li>
<li><b>Scan de répertoires (Gobuster)</b> : <br> <code>gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt</code></li>
</ul>

<h2> Analyse avec ELK</h2>

<p>Les logs générés au format JSON sont acheminés vers la stack ELK. Les dashboards Kibana permettent de filtrer par <code>honeypot_type</code> (http, ssh, ftp) et d'analyser :</p>
<ul>
<li>Les types d'injections (RCE, XSS, SQLi).</li>
<li>Les utilisateurs et mots de passe les plus testés (Brute Force).</li>
<li>Les chemins et fichiers ciblés par les attaquants.</li>
</ul>

<h2> Avertissement</h2>

Ce projet est <b>strictement éducatif</b>. Les honeypots sont conçus pour être déployés sur un réseau isolé (VM). <b>Ne jamais exposer ces services sur Internet sans mesures de sécurité supplémentaires.</b>

<h2> Auteures</h2>

<b>Salma Elmarabet : élèves ingénieures en cybersécurité (ENSA Fès) <br>
