import asyncio
from honeypots.http.http_honeypot import start_http_honeypot
from honeypots.ssh.ssh_honeypot import start_ssh_server
from honeypots.ftp.ftp_honeypot import start_ftp_server
async def run_all_servers():
    """Lance tous les serveurs en parallèle avec asyncio"""
    # Lancer HTTP et FTP dans des threads (car ils sont synchrone)
    http_task = asyncio.to_thread(start_http_honeypot)
    ftp_task = asyncio.to_thread(start_ftp_server)
    ssh_task = start_ssh_server()  
    
    await asyncio.gather(
        http_task,
        ftp_task, 
        ssh_task,
    )

def main():
    print("[+] HTTP sur le port 8080")
    print("[+] FTP sur le port 2221") 
    print("[+] SSH sur le port 2222")
    
    try:
        asyncio.run(run_all_servers())
    except KeyboardInterrupt:
        print("\n Arrêt propre des honeypots")
    except Exception as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    main()
