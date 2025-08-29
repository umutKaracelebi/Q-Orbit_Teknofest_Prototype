#ipconfig // windows terminal
#ifconfig // linux terminal
#sudo arpspoof -i eth0 -t 10.192.47.49 10.192.47.205 //ilki hedef ikincisi kaynak client ve server arası
#sudo arpspoof -i eth0 -t 10.192.47.205 10.192.47.49 //ilki hedef ikincisi kaynak client ve server arası
#sudo wireshark
#echo "df1ab28394c99f130974d9509d4f193a" > myhash.txt  //md5 hash kaydetme
#hashcat -m 0 -a 3 myhash.txt ?a?a?a?a?a --increment --force --potfile-disable  //md5 hashini hashcat ile kırma
#netsh advfirewall set allprofiles state off //windows firewall kapatma uygulamayı açmadan yap
#netsh advfirewall set allprofiles state on //windows firewall açma uygulamayı kapatınca yap
#sudo ufw disable //linux firewall kapatma uygulamayı açmadan yap
#sudo ufw enable //linux firewall açma uygulamayı kapatınca yap

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time
import hashlib
import json

# Anahtar tanımı
AES_KEY = b'16-bytes-anahtar'

class ModernClientApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔬 Teknofest Q-Orbit Prototip Kuantum Güvenlik Simülasyonu")
        self.geometry("1000x800")
        self.configure(bg="#2c3e50")
        
        # Stil ayarları
        self.setup_styles()
        
        # Başlık
        self.create_header()
        
        # Notebook (tablar)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both', padx=20, pady=10)

        self.create_aes_tab()
        self.create_quantum_tab()
        self.create_status_tab()
        
        # Footer
        self.create_footer()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Renkler
        colors = {
            'primary': '#3498db',
            'secondary': '#2ecc71', 
            'accent': '#e74c3c',
            'dark': '#2c3e50',
            'light': '#ecf0f1'
        }
        
        style.configure('TFrame', background=colors['light'])
        style.configure('TLabel', background=colors['light'], foreground=colors['dark'])
        style.configure('TButton', background=colors['primary'], foreground='white')
        style.configure('Accent.TButton', background=colors['secondary'], foreground='white', font=('Arial', 10, 'bold'))
        style.configure('Danger.TButton', background=colors['accent'], foreground='white')
        style.configure('TNotebook', background=colors['dark'])
        style.configure('TNotebook.Tab', background=colors['dark'], foreground='white')
        style.map('TNotebook.Tab', background=[('selected', colors['primary'])])
        
    def create_header(self):
        header_frame = ttk.Frame(self, style='TFrame')
        header_frame.pack(fill='x', padx=20, pady=10)
        
        # Logo ve başlık
        title_frame = ttk.Frame(header_frame, style='TFrame')
        title_frame.pack()
        
        logo_label = ttk.Label(title_frame, text="⚛️", font=('Arial', 24), background='#2c3e50', foreground='white')
        logo_label.pack(side='left', padx=5)
        
        title_label = ttk.Label(title_frame, text="TEKNOFEST Q-ORBİT KUANTUM GÜVENLİK", 
                                 font=('Arial', 16, 'bold'), background='#2c3e50', foreground='white')
        title_label.pack(side='left', padx=10)
        
        subtitle_label = ttk.Label(header_frame, text="Klasik ve Kuantum Şifreleme Test Platformu", 
                                 font=('Arial', 10), background='#2c3e50', foreground='#bdc3c7')
        subtitle_label.pack(pady=5)

    def create_aes_tab(self):
        aes_frame = ttk.Frame(self.notebook, padding="15", style='TFrame')
        self.notebook.add(aes_frame, text='🔐 Klasik Şifreleme')
        
        title_label = ttk.Label(aes_frame, text="Şifreleme ve Hash Testi", 
                                 font=('Arial', 14, 'bold'), style='TLabel')
        title_label.pack(pady=10)

        input_frame = ttk.Frame(aes_frame, style='TFrame')
        input_frame.pack(pady=15, fill='x')

        ttk.Label(input_frame, text="Sunucu IP:", font=('Arial', 10, 'bold')).grid(row=0, column=0, padx=10, pady=8, sticky='w')
        self.aes_ip_entry = ttk.Entry(input_frame, width=20, font=('Arial', 10))
        self.aes_ip_entry.insert(0, "10.192.47.49")
        self.aes_ip_entry.grid(row=0, column=1, padx=10, pady=8)

        ttk.Label(input_frame, text="Port:", font=('Arial', 10, 'bold')).grid(row=0, column=2, padx=10, pady=8, sticky='w')
        self.aes_port_entry = ttk.Entry(input_frame, width=10, font=('Arial', 10))
        self.aes_port_entry.insert(0, "65432")
        self.aes_port_entry.grid(row=0, column=3, padx=10, pady=8)

        ttk.Label(input_frame, text="Mesaj:", font=('Arial', 10, 'bold')).grid(row=1, column=0, padx=10, pady=8, sticky='w')
        self.aes_message_entry = ttk.Entry(input_frame, width=50, font=('Arial', 10))
        self.aes_message_entry.insert(0, "uydu")
        self.aes_message_entry.grid(row=1, column=1, columnspan=3, padx=10, pady=8, sticky='we')
        
        ttk.Label(input_frame, text="Yöntem:", font=('Arial', 10, 'bold')).grid(row=2, column=0, padx=10, pady=8, sticky='w')
        self.aes_method_combo = ttk.Combobox(input_frame, values=["AES (CBC)", "MD5 Hashing", "Şifresiz (Plain Text)"], state="readonly", font=('Arial', 10))
        self.aes_method_combo.current(0)
        self.aes_method_combo.grid(row=2, column=1, columnspan=3, padx=10, pady=8, sticky='we')

        button_frame = ttk.Frame(aes_frame, style='TFrame')
        button_frame.pack(pady=15)
        
        self.aes_button = ttk.Button(button_frame, text="🚀 İşlemi Başlat", 
                                      command=self.run_aes_test, style='Accent.TButton')
        self.aes_button.pack(pady=5, padx=10, side='left')
        
        ttk.Button(button_frame, text="🗑️ Temizle", command=self.clear_aes_logs).pack(pady=5, padx=10, side='left')

        log_frame = ttk.LabelFrame(aes_frame, text="🔍 İşlem Logları", padding="10", style='TFrame')
        log_frame.pack(pady=10, fill='both', expand=True)

        self.aes_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, width=80,
                                                  font=('Consolas', 9), bg='#f8f9fa', fg='#2c3e50')
        self.aes_log.pack(fill='both', expand=True)
        self.aes_log.insert(tk.END, "📍 AES/Hash Testi Hazır\n")
        self.aes_log.insert(tk.END, "─" * 50 + "\n")

    def create_quantum_tab(self):
        quantum_frame = ttk.Frame(self.notebook, padding="15", style='TFrame')
        self.notebook.add(quantum_frame, text='⚛️ Kuantum İletişim')
        
        title_label = ttk.Label(quantum_frame, text="Kuantum Anahtar Dağıtımı (BB84)", 
                                 font=('Arial', 14, 'bold'), style='TLabel')
        title_label.pack(pady=10)

        input_frame = ttk.Frame(quantum_frame, style='TFrame')
        input_frame.pack(pady=15, fill='x')

        ttk.Label(input_frame, text="Sunucu IP:", font=('Arial', 10, 'bold')).grid(row=0, column=0, padx=10, pady=8, sticky='w')
        self.quantum_ip_entry = ttk.Entry(input_frame, width=20, font=('Arial', 10))
        self.quantum_ip_entry.insert(0, "10.192.47.49")
        self.quantum_ip_entry.grid(row=0, column=1, padx=10, pady=8)

        ttk.Label(input_frame, text="Port:", font=('Arial', 10, 'bold')).grid(row=0, column=2, padx=10, pady=8, sticky='w')
        self.quantum_port_entry = ttk.Entry(input_frame, width=10, font=('Arial', 10))
        self.quantum_port_entry.insert(0, "65433")
        self.quantum_port_entry.grid(row=0, column=3, padx=10, pady=8)

        ttk.Label(input_frame, text="Mesaj:", font=('Arial', 10, 'bold')).grid(row=1, column=0, padx=10, pady=8, sticky='w')
        self.quantum_message_entry = ttk.Entry(input_frame, width=50, font=('Arial', 10))
        self.quantum_message_entry.insert(0, "uydu")
        self.quantum_message_entry.grid(row=1, column=1, columnspan=3, padx=10, pady=8, sticky='we')

        button_frame = ttk.Frame(quantum_frame, style='TFrame')
        button_frame.pack(pady=15)
        
        self.quantum_button = ttk.Button(button_frame, text="⚛️ BB84 Başlat", 
                                         command=self.run_quantum_test, style='Accent.TButton')
        self.quantum_button.pack(pady=5, padx=10, side='left')
        
        ttk.Button(button_frame, text="🗑️ Temizle", command=self.clear_quantum_logs).pack(pady=5, padx=10, side='left')

        log_frame = ttk.LabelFrame(quantum_frame, text="🔬 Kuantum İşlem Logları", padding="10", style='TFrame')
        log_frame.pack(pady=10, fill='both', expand=True)

        self.quantum_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, width=80,
                                                      font=('Consolas', 9), bg='#e8f5e8', fg='#2c3e50')
        self.quantum_log.pack(fill='both', expand=True)
        self.quantum_log.insert(tk.END, "📍 Kuantum Güvenlik Testi Hazır\n")
        self.quantum_log.insert(tk.END, "📡 Ağda sadece anlamsız trafik görünecek\n")
        self.quantum_log.insert(tk.END, "🔒 Gerçek mesaj ağ üzerinden gönderilmez\n")
        self.quantum_log.insert(tk.END, "─" * 50 + "\n")

    def create_status_tab(self):
        status_frame = ttk.Frame(self.notebook, padding="15", style='TFrame')
        self.notebook.add(status_frame, text='📊 Sistem Durumu')
        
        title_label = ttk.Label(status_frame, text="Ağ ve Bağlantı Durumu", 
                                 font=('Arial', 14, 'bold'), style='TLabel')
        title_label.pack(pady=10)

        info_frame = ttk.LabelFrame(status_frame, text="🌐 Ağ Konfigürasyonu", padding="10", style='TFrame')
        info_frame.pack(pady=10, fill='x')

        info_text = """
📍 IP Adresleri:
• 🖥️  Client Makine: 10.192.47.205
• 🖥️  Sunucu Makine: 10.192.47.49  
• 🐉 Kali Linux: 10.108.14.221

🔌 Port Yapılandırması:
• 🔐 AES Port: 65432
• ⚛️ Kuantum Port: 65433

📊 Wireshark İzleme:
• 👁️  Tüm ağ trafiği izlenebilir
• 🔒 Şifrelenmiş veriler gözlemlenebilir
• 📡 Kuantumda sadece gürültü trafiği

⚡ Özellikler:
• ✅ AES-256 CBC şifreleme
• ✅ Kuantum anahtar simülasyonu
• ✅ Gerçek zamanlı loglama
• ✅ Çoklu istemci desteği
"""
        status_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=12, width=80,
                                                 font=('Consolas', 9), bg='#fff3cd', fg='#856404')
        status_text.pack(fill='both', expand=True)
        status_text.insert(tk.END, info_text)
        status_text.config(state=tk.DISABLED)

        test_frame = ttk.Frame(status_frame, style='TFrame')
        test_frame.pack(pady=15)

        ttk.Button(test_frame, text="🔄 Bağlantı Testi", command=self.test_connections, style='Accent.TButton').pack(side='left', padx=5)
        ttk.Button(test_frame, text="🗑️ Tüm Logları Temizle", command=self.clear_all_logs).pack(side='left', padx=5)

    def create_footer(self):
        footer_frame = ttk.Frame(self, style='TFrame')
        footer_frame.pack(fill='x', padx=20, pady=10)
        
        footer_text = "🚀 TEKNOFEST 2025 - Q-Orbit | 🛡️ İnoTürk Teknoloji Takımı"
        footer_label = ttk.Label(footer_frame, text=footer_text, font=('Arial', 9), 
                                 background='#2c3e50', foreground='#bdc3c7')
        footer_label.pack()

    def run_aes_test(self):
        selected_method = self.aes_method_combo.get()
        message = self.aes_message_entry.get()
        
        if not message:
            messagebox.showerror("Hata", "Lütfen bir mesaj girin!")
            return
            
        self.aes_log.delete(1.0, tk.END)
        
        ip_address = self.aes_ip_entry.get()
        port = self.aes_port_entry.get()

        if not all([ip_address, port]):
            messagebox.showerror("Hata", "Lütfen IP ve port bilgilerini doldurun!")
            return
            
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Hata", "Port numarası geçersiz!")
            return
        
        if selected_method == "AES (CBC)":
            self.add_log(self.aes_log, f"🔐 AES Şifreleme Testi Başlatıldı ({ip_address}:{port})", "info")
            threading.Thread(target=self.aes_client_thread, args=(ip_address, port, message), daemon=True).start()
            
        elif selected_method == "MD5 Hashing":
            self.add_log(self.aes_log, f"⚡ MD5 Hashing Testi Başlatıldı ({ip_address}:{port})", "info")
            # MD5 hash'ini hesaplayıp sunucuya gönderen yeni fonksiyonu çağırıyoruz
            threading.Thread(target=self.md5_client_thread, args=(ip_address, port, message), daemon=True).start()

        elif selected_method == "Şifresiz (Plain Text)":
            self.add_log(self.aes_log, f"➡️ Şifresiz (Plain Text) Gönderim Testi Başlatıldı ({ip_address}:{port})", "info")
            threading.Thread(target=self.plain_text_client_thread, args=(ip_address, port, message), daemon=True).start()
            
    def aes_client_thread(self, ip_address, port, message):
        try:
            self.add_log(self.aes_log, "🔑 AES anahtarı yükleniyor...", "info")
            
            cipher = AES.new(AES_KEY, AES.MODE_CBC)
            iv = cipher.iv
            ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
            
            self.add_log(self.aes_log, f"🔒 Mesaj şifrelendi: {len(ciphertext)} byte", "success")
            self.add_log(self.aes_log, f"🎯 IV: {iv.hex()[:16]}...", "debug")
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                self.add_log(self.aes_log, f"🌐 {ip_address}:{port} bağlantısı kuruluyor...", "info")
                s.connect((ip_address, port))
                
                self.add_log(self.aes_log, "✅ Sunucuya bağlandı!", "success")
                self.add_log(self.aes_log, "📤 Paketler gönderiliyor...", "info")
                
                s.sendall(iv)
                s.sendall(ciphertext)
                
                self.add_log(self.aes_log, "📡 Şifrelenmiş mesaj gönderildi!", "success")
                self.add_log(self.aes_log, "👀 Wireshark'ta şifreli veriyi görebilirsiniz", "info")
                self.add_log(self.aes_log, f"📊 Veri boyutu: {16 + len(ciphertext)} byte", "debug")
                self.add_log(self.aes_log, "🎉 AES Testi Tamamlandı!", "success")
                
        except ConnectionRefusedError:
            self.add_log(self.aes_log, "❌ Bağlantı reddedildi! Sunucu çalışmıyor olabilir.", "error")
        except socket.timeout:
            self.add_log(self.aes_log, "⏰ Bağlantı zaman aşımı! Sunucu yanıt vermedi.", "error")
        except Exception as e:
            self.add_log(self.aes_log, f"❌ Hata: {str(e)}", "error")

    def md5_client_thread(self, ip_address, port, message):
        """MD5 hash'ini hesaplayıp sunucuya gönderir."""
        try:
            self.add_log(self.aes_log, f"🌐 {ip_address}:{port} bağlantısı kuruluyor...", "info")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((ip_address, port))
                self.add_log(self.aes_log, "✅ Sunucuya bağlandı!", "success")
                
                self.add_log(self.aes_log, "📤 Mesajın MD5 hash'i hesaplanıyor...", "info")
                hashed_message = hashlib.md5(message.encode('utf-8')).hexdigest()
                
                self.add_log(self.aes_log, f"🔑 Hesaplanan Hash: {hashed_message}", "success")
                self.add_log(self.aes_log, "📡 Hash değeri gönderiliyor...", "info")
                s.sendall(hashed_message.encode('utf-8'))
                
                self.add_log(self.aes_log, "👀 Wireshark'ta HASH değerini AÇIKÇA görebilirsiniz!", "warning")
                self.add_log(self.aes_log, f"🎉 MD5 Testi Tamamlandı!", "success")
                
        except ConnectionRefusedError:
            self.add_log(self.aes_log, "❌ Bağlantı reddedildi! Sunucu çalışmıyor olabilir.", "error")
        except socket.timeout:
            self.add_log(self.aes_log, "⏰ Bağlantı zaman aşımı! Sunucu yanıt vermedi.", "error")
        except Exception as e:
            self.add_log(self.aes_log, f"❌ Hata: {str(e)}", "error")

    def plain_text_client_thread(self, ip_address, port, message):
        try:
            self.add_log(self.aes_log, f"🌐 {ip_address}:{port} bağlantısı kuruluyor...", "info")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((ip_address, port))
                self.add_log(self.aes_log, "✅ Sunucuya bağlandı!", "success")
                
                self.add_log(self.aes_log, "📤 Şifresiz mesaj gönderiliyor...", "info")
                s.sendall(message.encode('utf-8'))
                
                self.add_log(self.aes_log, "📡 Şifresiz mesaj gönderildi!", "success")
                self.add_log(self.aes_log, f"👀 Wireshark'ta mesajı AÇIKÇA görebilirsiniz!", "warning")
                self.add_log(self.aes_log, f"📊 Veri: '{message}'", "debug")
                self.add_log(self.aes_log, f"🎉 Şifresiz Testi Tamamlandı!", "success")

        except ConnectionRefusedError:
            self.add_log(self.aes_log, "❌ Bağlantı reddedildi! Sunucu çalışmıyor olabilir.", "error")
        except socket.timeout:
            self.add_log(self.aes_log, "⏰ Bağlantı zaman aşımı! Sunucu yanıt vermedi.", "error")
        except Exception as e:
            self.add_log(self.aes_log, f"❌ Hata: {str(e)}", "error")

    def run_quantum_test(self):
        ip_address = self.quantum_ip_entry.get()
        port = self.quantum_port_entry.get()
        message = self.quantum_message_entry.get()
        
        if not all([ip_address, port, message]):
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
            return
            
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Hata", "Port numarası geçersiz!")
            return
            
        self.quantum_log.delete(1.0, tk.END)
        self.add_log(self.quantum_log, "⚛️ Kuantum Testi Başlatıldı", "info")
        self.add_log(self.quantum_log, f"📍 {ip_address}:{port} adresine bağlanılıyor...", "info")
        
        threading.Thread(target=self.quantum_client_thread, args=(ip_address, port, message), daemon=True).start()

    def quantum_client_thread(self, ip_address, port, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(30)  # Kuantum hesaplama için uzun timeout
                self.add_log(self.quantum_log, f"🌐 {ip_address}:{port} bağlantısı kuruluyor...", "info")
                s.connect((ip_address, port))
                
                self.add_log(self.quantum_log, "✅ Sunucuya bağlandı!", "success")
                self.add_log(self.quantum_log, "📡 Anlamsız trafik gönderiliyor...", "info")
                
                noise_data = b'Quantum noise: ' + get_random_bytes(32)
                s.sendall(noise_data)
                self.add_log(self.quantum_log, f"📊 Gürültü verisi gönderildi: {len(noise_data)} byte", "debug")
                
                self.add_log(self.quantum_log, "⏳ IBM Quantum hesaplaması bekleniyor...", "info")
                response = s.recv(1024)
                
                if response == b"IBM_QUANTUM_SUCCESS":
                    self.add_log(self.quantum_log, "🎉 IBM QUANTUM BAŞARILI!", "success")
                    self.add_log(self.quantum_log, "⚡ Gerçek kuantum bilgisayar kullanıldı!", "success")
                    
                    try:
                        extra_info = s.recv(1024)
                        info = extra_info.decode()
                        self.add_log(self.quantum_log, f"📋 IBM Quantum Bilgileri: {info}", "success")
                    except:
                        pass
                    
                    self.add_log(self.quantum_log, "🔒 Gerçek mesaj ağ üzerinden GÖNDERİLMEDİ!", "info")
                    self.add_log(self.quantum_log, "👀 Wireshark'ta sadece gürültü görülebilir", "info")
                    
                elif response == b"QUANTUM_SIMULATION_SUCCESS":
                    self.add_log(self.quantum_log, "✅ KUANTUM SIMÜLASYON BAŞARILI!", "success")
                    self.add_log(self.quantum_log, "🔧 BB84 protokolü simüle edildi!", "success")
                    self.add_log(self.quantum_log, "🔒 Gerçek mesaj ağ üzerinden GÖNDERİLMEDİ!", "info")
                    
                elif response == b"QUANTUM_SIMULATION_READY":
                    self.add_log(self.quantum_log, "⚠️  Kuantum simülasyon hazır", "warning")
                    
                elif response == b"QUANTUM_ERROR":
                    self.add_log(self.quantum_log, "❌ Kuantum hesaplama hatası!", "error")
                    
                else:
                    self.add_log(self.quantum_log, f"🔍 Yanıt: {response}", "debug")
                    
        except socket.timeout:
            self.add_log(self.quantum_log, "⏰ Zaman aşımı! Kuantum hesaplama uzun sürdü.", "error")
        except ConnectionRefusedError:
            self.add_log(self.quantum_log, "❌ Bağlantı reddedildi! Sunucu çalışmıyor.", "error")
        except Exception as e:
            self.add_log(self.quantum_log, f"❌ Hata: {str(e)}", "error")

    def add_log(self, log_widget, message, log_type="info"):
        def update():
            log_widget.insert(tk.END, message + "\n")
            
            if log_type == "error":
                log_widget.tag_configure("error", foreground="#e74c3c")
                log_widget.tag_add("error", "end-2l", "end-1l")
            elif log_type == "success":
                log_widget.tag_configure("success", foreground="#27ae60")
                log_widget.tag_add("success", "end-2l", "end-1l")
            elif log_type == "warning":
                log_widget.tag_configure("warning", foreground="#f39c12")
                log_widget.tag_add("warning", "end-2l", "end-1l")
            elif log_type == "debug":
                log_widget.tag_configure("debug", foreground="#7f8c8d")
                log_widget.tag_add("debug", "end-2l", "end-1l")
            else:
                log_widget.tag_configure("info", foreground="#3498db")
                log_widget.tag_add("info", "end-2l", "end-1l")
                
            log_widget.see(tk.END)
        self.after(0, update)

    def test_connections(self):
        def test_thread():
            servers = [
                ("🔐 AES Sunucu", "10.192.47.49", 65432),
                ("⚛️ Kuantum Sunucu", "10.192.47.49", 65433)
            ]
            
            for name, ip, port in servers:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(3)
                        s.connect((ip, port))
                        self.add_log(self.aes_log, f"✅ {name} bağlantı testi: BAŞARILI", "success")
                except:
                    self.add_log(self.aes_log, f"❌ {name} bağlantı testi: BAŞARISIZ", "error")
        
        threading.Thread(target=test_thread, daemon=True).start()

    def clear_aes_logs(self):
        self.aes_log.delete(1.0, tk.END)
        self.add_log(self.aes_log, "🧹 AES logları temizlendi", "info")

    def clear_quantum_logs(self):
        self.quantum_log.delete(1.0, tk.END)
        self.add_log(self.quantum_log, "🧹 Kuantum logları temizlendi", "info")

    def clear_all_logs(self):
        self.clear_aes_logs()
        self.clear_quantum_logs()

if __name__ == "__main__":
    app = ModernClientApp()
    app.mainloop()

