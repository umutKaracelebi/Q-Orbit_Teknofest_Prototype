import socket
import threading
import hashlib
import logging
import random
import json
from qiskit import QuantumCircuit, transpile
from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
from qiskit_aer import Aer
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
import time

# Loglamayı ayarla
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IBMQuantumServer:
    def __init__(self):
        self.quantum_key = None
        self.ibm_token = "3le2ogMfQHlZCXrtI7Z7bopNxADiC_0SjtNk9aoxP7O6"
        self.service = None
        self.num_qubits = 8
        self.check_bits_count = 2
        self.error_rate_threshold = 0.5
        self.setup_ibm_connection()

    def setup_ibm_connection(self):
        """IBM Quantum bağlantısını kur (q-orbit-prototype uyumlu)"""
        try:
            print("🔗 IBM Quantum hesabı ayarlanıyor...")
            QiskitRuntimeService.save_account(
                channel="ibm_quantum_platform",
                token=self.ibm_token,
                instance="q-orbit-prototype",
                overwrite=True
            )
            self.service = QiskitRuntimeService(
                channel="ibm_quantum_platform",
                instance="q-orbit-prototype"
            )
            print("✅ IBM Quantum hesabı başarıyla kaydedildi!")
            
            backends = self.service.backends()
            print("📋 Mevcut kuantum bilgisayarları:")
            for backend in backends:
                try:
                    status = backend.status()
                    cfg = backend.configuration()
                    tag = "(simulator)" if "simulator" in backend.name.lower() else ""
                    print(f"   - {backend.name} {tag} | {cfg.n_qubits} qubit | {status.status_msg}")
                except Exception:
                    print(f"   - {getattr(backend,'name','?')} (status/config okunamadı)")
                    
        except Exception as e:
            print(f"❌ IBM Quantum bağlantı hatası: {e}")
            self.service = None

    def get_quantum_backend(self):
        """Gerçek cihaz backend'ini seç (öncelikli olarak ibm_torino, sonra ibm_brisbane)"""
        try:
            if not self.service:
                return None
            
            print("🔗 Mevcut kuantum bilgisayarları aranıyor...")
            backends = self.service.backends()
            
            target_backend = None
            for backend in backends:
                if backend.name == "ibm_torino":
                    target_backend = backend
                    break
            
            if target_backend:
                status = target_backend.status()
                cfg = target_backend.configuration()
                if status.operational and getattr(cfg, "n_qubits", 0) >= self.num_qubits:
                    print(f"🎯 Seçilen backend: {target_backend.name}")
                    print(f"   - Qubit sayısı: {cfg.n_qubits}")
                    print(f"   - Bekleyen işler: {status.pending_jobs}")
                    print(f"   - Durum: {status.status_msg}")
                    return target_backend
                else:
                    print(f"⚠️ ibm_torino şu anda çalışır durumda değil: {status.status_msg}")

            target_backend = None
            for backend in backends:
                if backend.name == "ibm_brisbane":
                    target_backend = backend
                    break
            
            if target_backend:
                status = target_backend.status()
                cfg = target_backend.configuration()
                if status.operational and getattr(cfg, "n_qubits", 0) >= self.num_qubits:
                    print(f"🎯 Seçilen backend: {target_backend.name}")
                    print(f"   - Qubit sayısı: {cfg.n_qubits}")
                    print(f"   - Bekleyen işler: {status.pending_jobs}")
                    print(f"   - Durum: {status.status_msg}")
                    return target_backend
                else:
                    print(f"⚠️ ibm_brisbane şu anda çalışır durumda değil: {status.status_msg}")
            
            print("⚠️ Çalışır durumdaki öncelikli cihazlar bulunamadı, simülatör kullanılacak.")
            return None
                
        except Exception as e:
            print(f"❌ Backend seçim hatası: {e}")
            return None

    def create_bb84_circuit(self, alice_bits, alice_bases, bob_bases):
        """BB84 protokolüne göre devre oluştur"""
        n = len(alice_bits)
        qc = QuantumCircuit(n, n)
        for i in range(n):
            if alice_bits[i] == 1:
                qc.x(i)
            if alice_bases[i] == 'X':
                qc.h(i)
        qc.barrier()
        for i in range(n):
            if bob_bases[i] == 'X':
                qc.h(i)
            qc.measure(i, i)
        return qc

    def run_quantum_circuit(self, backend):
        """BB84 devresini çalıştır ve sonuçları işle"""
        print("⚡ Kuantum devresi BB84 protokolüne göre hazırlanıyor...")
        alice_bits = [random.randint(0, 1) for _ in range(self.num_qubits)]
        alice_bases = [random.choice(['Z', 'X']) for _ in range(self.num_qubits)]
        bob_bases = [random.choice(['Z', 'X']) for _ in range(self.num_qubits)]
        qc = self.create_bb84_circuit(alice_bits, alice_bases, bob_bases)
        print(f"🔗 Cihaz: {backend.name} (Sampler primitive)")
        try:
            transpiled_qc = transpile(qc, backend=backend, optimization_level=3)
            sampler = Sampler(mode=backend)
            job = sampler.run([transpiled_qc], shots=1024)
            print(f"⏳ Job ID: {job.job_id()}")
            result = job.result()
            result_data = result[0].data
            creg_names = list(result_data.keys())
            if not creg_names:
                raise ValueError("No classical registers found in the result data.")
            counts = result_data[creg_names[0]].get_counts()
            bob_raw_results = {int(k, 2): v for k, v in counts.items()}
            most_common_outcome = max(bob_raw_results, key=bob_raw_results.get)
            bob_measured_bits = [(most_common_outcome >> i) & 1 for i in range(self.num_qubits - 1, -1, -1)]
            print(f"Alice'in bitleri: {alice_bits}")
            print(f"Alice'in bazları: {alice_bases}")
            print(f"Bob'un bazları:   {bob_bases}")
            print(f"Bob'un ölçtüğü bitler: {bob_measured_bits}")
            secure_key = []
            for i in range(self.num_qubits):
                if alice_bases[i] == bob_bases[i]:
                    secure_key.append(alice_bits[i])
            final_key = []
            check_bits_alice = []
            check_bits_bob = []
            if len(secure_key) > self.check_bits_count:
                check_bits_indices = random.sample(range(len(secure_key)), self.check_bits_count)
                final_key = [bit for i, bit in enumerate(secure_key) if i not in check_bits_indices]
                check_bits_alice = [secure_key[i] for i in check_bits_indices]
                bob_temp_key = []
                for i in range(self.num_qubits):
                    if alice_bases[i] == bob_bases[i]:
                        bob_temp_key.append(bob_measured_bits[i])
                check_bits_bob = [bob_temp_key[i] for i in check_bits_indices]
            errors = sum(1 for a, b in zip(check_bits_alice, check_bits_bob) if a != b)
            error_rate = errors / self.check_bits_count if self.check_bits_count > 0 else 0
            print(f"\nHata kontrolü için seçilen bitler (Alice): {check_bits_alice}")
            print(f"Hata kontrolü için ölçülen bitler (Bob): {check_bits_bob}")
            print(f"Tespit edilen hata oranı: {error_rate:.2f}")
            if error_rate > self.error_rate_threshold:
                print("❌ Yüksek hata oranı tespit edildi! Olası bir dinleme girişimi var. Anahtar imha ediliyor.")
                return None
            else:
                print("✅ Hata oranı kabul edilebilir sınırlar içinde. Anahtar güvenli kabul ediliyor.")
                return final_key
        except Exception as e:
            print(f"❌ Cihazda çalışma hatası: {e}")
            return None

    def generate_quantum_key(self, secure_key):
        """Güvenli anahtardan SHA256 anahtarı üret"""
        if secure_key:
            key_string = ''.join(str(bit) for bit in secure_key)
            if not key_string:
                print("⚠️ Güvenli anahtar boş, anahtar oluşturulamadı.")
                return False
            key_bytes = key_string.encode('utf-8')
            self.quantum_key = hashlib.sha256(key_bytes).digest()
            print(f"🔑 Kuantum anahtar (SHA256): {self.quantum_key.hex()[:20]}...")
            return True
        return False

    def handle_client(self, conn, addr):
        print(f"\n🧠 Kuantum istemcisi bağlandı: {addr}")
        try:
            received_data = conn.recv(1024)
            if not received_data:
                print("❗ Boş veri alındı, bağlantı kapatılıyor.")
                return
            
            print("➡️ İstemciden gelen ham veri (Hex):")
            print(received_data.hex())
            print("Wireshark'ta sadece bu paket görünecek.")

            # Önce gerçek bir kuantum cihazı bulmaya çalış
            backend = self.get_quantum_backend()
            key_generated = None

            if backend:
                # Gerçek cihaz varsa, o cihazda çalıştır
                print("✔ Gerçek bir kuantum bilgisayarı bulundu. İşlem gerçek cihazda çalıştırılıyor...")
                key_generated = self.run_quantum_circuit(backend)
            else:
                # Cihaz yoksa veya kullanılamıyorsa simülasyon moduna geç
                print("⚠️ Gerçek cihaz kullanılamıyor, simülasyon moduna geçiliyor.")
                key_generated = self.run_simulation_mode()
            
            # Kuantum anahtarını oluştur
            self.generate_quantum_key(key_generated)

            if key_generated:
                conn.sendall(b"QUANTUM_SUCCESS")
                print("🎉 İşlem başarıyla tamamlandı, yanıt gönderildi.")
            else:
                conn.sendall(b"QUANTUM_ERROR")
                print("❌ İşlem başarısız oldu, hata yanıtı gönderildi.")
        
        except Exception as e:
            print(f"❌ Sunucu hatası: {e}")
            
        finally:
            conn.close()
            print("--- Bağlantı kapatıldı ---\n")

    def run_simulation_mode(self):
        """Simulasyon modunda BB84 calistir"""
        print("🔧 Yerel BB84 simulasyon modunda calistiriliyor...")
        
        alice_bits = [random.randint(0, 1) for _ in range(self.num_qubits)]
        alice_bases = [random.choice(['Z', 'X']) for _ in range(self.num_qubits)]
        bob_bases = [random.choice(['Z', 'X']) for _ in range(self.num_qubits)]
        
        for i in range(self.num_qubits):
            if i % 4 == 0:
                bob_bases[i] = 'X' if alice_bases[i] == 'Z' else 'Z'
        
        qc = self.create_bb84_circuit(alice_bits, alice_bases, bob_bases)
        
        simulator = Aer.get_backend("aer_simulator")
        tqc = transpile(qc, simulator)
        result = simulator.run(tqc, shots=1).result()
        counts = result.get_counts()
        
        most_common_outcome = max(counts, key=counts.get)
        bob_measured_bits = [int(bit) for bit in most_common_outcome.replace(" ", "")]

        secure_key = []
        for i in range(self.num_qubits):
            if alice_bases[i] == bob_bases[i]:
                secure_key.append(alice_bits[i])

        final_key = []
        check_bits_alice = []
        check_bits_bob = []
        
        if len(secure_key) > self.check_bits_count:
            check_bits_indices = random.sample(range(len(secure_key)), self.check_bits_count)
            final_key = [bit for i, bit in enumerate(secure_key) if i not in check_bits_indices]
            check_bits_alice = [secure_key[i] for i in check_bits_indices]
            
            bob_temp_key = []
            for i in range(self.num_qubits):
                if alice_bases[i] == bob_bases[i]:
                    bob_temp_key.append(bob_measured_bits[i])
            check_bits_bob = [bob_temp_key[i] for i in check_bits_indices]

        errors = sum(1 for a, b in zip(check_bits_alice, check_bits_bob) if a != b)
        error_rate = errors / self.check_bits_count if self.check_bits_count > 0 else 0

        print(f"Simulasyon sonuclari - Hata orani: {error_rate:.2f}")
        if error_rate > self.error_rate_threshold:
            print("❌ Simulasyonda yuksek hata orani tespit edildi. Anahtar imha ediliyor.")
            return None
        else:
            print("✅ Simulasyon guvenli anahtari olusturuldu.")
            self.generate_quantum_key(final_key)
            return final_key

def main():
    HOST = '0.0.0.0'
    PORT = 65433
    try:
        quantum_server = IBMQuantumServer()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            print(f"🧪 IBM KUANTUM SUNUCUSU BB84 PROTOKOLU ILE {HOST}:{PORT} dinleniyor...")
            print("📍 Guvenli kuantum anahtar dagitimi icin bekleniyor...")
            print("-" * 50)
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=quantum_server.handle_client, args=(conn, addr), daemon=True)
                thread.start()
    except Exception as e:
        print(f"❌ Sunucu baslatma hatasi: {e}")
        print("💡 Cozum: pip install 'qiskit>=1.0.0' 'qiskit-ibm-runtime>=0.22.0' 'qiskit-aer'")

if __name__ == "__main__":

    main()
