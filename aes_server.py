import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
import os
import hashlib

# Anahtar tanımı (client ve server aynı anahtarı kullanmalı)
AES_KEY = b'16-bytes-anahtar'

def handle_client(conn, addr):
    """
    AES, şifresiz (plain text) ve MD5 testlerini işler.
    Gelen verinin uzunluğuna ve içeriğine göre modu belirler.
    """
    print(f"\n🧠 AES istemcisinden bağlantı alındı: {addr}")
    try:
        # Öncelikle IV'i (16 bayt) almaya çalışırız.
        iv = conn.recv(16)
        
        # Eğer 16 baytlık IV geldiyse, bu AES ile şifrelenmiş bir mesajdır.
        if len(iv) == 16:
            encrypted_data = conn.recv(1024)
            if not encrypted_data: return
            
            print("🔐 AES ile şifrelenmiş veri tespit edildi.")
            print(f"Wireshark'ta şifreli veriyi görmelisiniz: {iv.hex() + encrypted_data.hex()[:24]}...")
            
            try:
                # AES şifre çözme işlemi
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                
                print(f"✅ Sunucuda şifre çözüldü: {decrypted_data.decode('utf-8')}")
                print("--- AES Testi Başarılı! ---\n")
            except Exception as e:
                print(f"❌ Şifre çözme hatası: {e}")
                print("❗ AES anahtarı, IV veya veri formatı yanlış olabilir.")
        else:
            # Gelen veri 16 bayttan kısa ise veya IV ile başlamıyorsa, şifresiz metindir veya hashtir.
            # İlk gelen veriyi de okuruz.
            incoming_data = iv + conn.recv(1024)
            plain_text_or_hash = incoming_data.decode('utf-8')
            
            # Eğer 32 karakter uzunluğundaysa, büyük olasılıkla MD5 hash'idir
            if len(plain_text_or_hash) == 32:
                print("🔑 MD5 Hash değeri tespit edildi.")
                print(f"Wireshark'ta HASH'i AÇIKÇA görmelisiniz: {plain_text_or_hash}")
                print("--- MD5 Testi Başarılı! ---\n")
            else:
                # Gelen veri 32 karakterden farklıysa, şifresiz metindir.
                print("📝 Şifresiz (Plain Text) veri tespit edildi.")
                print(f"Wireshark'ta mesajı AÇIKÇA görmelisiniz: {plain_text_or_hash}")
                print("--- Şifresiz Testi Başarılı! ---\n")

    except Exception as e:
        print(f"❌ Sunucu hatası: {e}")
    finally:
        conn.close()
        print("--- Bağlantı kapatıldı ---\n")

def main():
    HOST = '0.0.0.0'
    PORT = 65432
    print(f"Sunucu {HOST}:{PORT} adresine bağlanmaya çalışıyor...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, PORT))
            s.listen()
            print(f"*** ✅ Başarılı! Sunucu {HOST}:{PORT} adresinde dinliyor... ***\n")
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except Exception as e:
            print(f"❌ Sunucu başlatılamadı: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()