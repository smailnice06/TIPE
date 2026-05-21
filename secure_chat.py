# secure_chat.py
import time
import threading
import secrets
import random
from cypari2 import Pari
import ctypes
import os
import hashlib
import concurrent.futures
import multiprocessing
import platform

# --- 1. DÉFINITION DU PONT C/PYTHON ---
class RSAKeys_C(ctypes.Structure):
    _fields_ = [
        ("n", ctypes.c_char_p),
        ("d", ctypes.c_char_p),
        ("p", ctypes.c_char_p),
        ("q", ctypes.c_char_p),
        ("dp", ctypes.c_char_p),
        ("dq", ctypes.c_char_p),
        ("qinv", ctypes.c_char_p)
    ]

# --- 2. CHARGEMENT DE LA LIBRAIRIE ---
# Détection automatique de l'extension selon si on est sur Mac ou sur Raspberry
ext = ".dylib" if platform.system() == "Darwin" else ".so"
lib_path = os.path.abspath(f"librsa_bridge{ext}")

# On charge le code C compilé
try:
    c_rsa_lib = ctypes.CDLL(lib_path)
    c_rsa_lib.generate_rsa_keys_ctypes.restype = RSAKeys_C
    c_rsa_lib.generate_rsa_keys_ctypes.argtypes = [ctypes.c_int, ctypes.c_int]
    c_rsa_lib.free_rsa_keys_ctypes.argtypes = [RSAKeys_C]
except OSError:
    print(f"[ERREUR FATALE] Impossible de trouver la librairie compilée {lib_path}")
    print("Avez-vous bien exécuté la commande 'gcc -shared ...' ?")
    exit(1)

# --- 3. LA NOUVELLE FONCTION PYTHON ULTRA RAPIDE ---
def generer_cles_bavardes(taille_bits):
    nb_coeurs = os.cpu_count() or 4
    print(f" -> [CTYPES] Exécution native C sur {nb_coeurs} cœurs pour {taille_bits*2} bits...")
    
    # 1. On lance le calcul en C (ça va prendre quelques millisecondes/secondes)
    keys_struct = c_rsa_lib.generate_rsa_keys_ctypes(taille_bits, nb_coeurs)
    
    # 2. On convertit les chaînes de caractères (C) en vrais nombres (Python)
    e = 65537
    n = int(keys_struct.n.decode('utf-8'))
    d = int(keys_struct.d.decode('utf-8'))
    p = int(keys_struct.p.decode('utf-8'))
    q = int(keys_struct.q.decode('utf-8'))
    dp = int(keys_struct.dp.decode('utf-8'))
    dq = int(keys_struct.dq.decode('utf-8'))
    qinv = int(keys_struct.qinv.decode('utf-8'))
    
    # 3. ON ORDONNE AU C DE VIDER LA RAM (Critique !)
    c_rsa_lib.free_rsa_keys_ctypes(keys_struct)
    
    print(" -> [CTYPES] Clés RSA générées et mémoire libérée avec succès.")
    
    cle_publique = (e, n)
    cle_privee = (d, n, p, q, dp, dq, qinv)
    return (cle_publique, cle_privee)
    

def pad_message(message_str, n_bits):
    message_bytes = message_str.encode('utf-8')
    n_bytes = n_bits // 8
    max_msg_len = n_bytes - 11
    if len(message_bytes) > max_msg_len: raise ValueError(f"Message trop long ! (Max {max_msg_len} octets)")
        
    pad_len = n_bytes - len(message_bytes) - 3
    pad_bytes = bytearray()
    while len(pad_bytes) < pad_len:
        r = secrets.randbelow(255) + 1
        pad_bytes.append(r)
        
    padded_block = b'\x02' + bytes(pad_bytes) + b'\x00' + message_bytes
    return int.from_bytes(padded_block, 'big')

def unpad_message(padded_int, n_bits):
    n_bytes = n_bits // 8
    padded_bytes = padded_int.to_bytes(n_bytes - 1, 'big')
    if padded_bytes[0] != 2: raise ValueError("Padding invalide.")
    separator_index = padded_bytes.index(b'\x00', 1)
    return padded_bytes[separator_index + 1:].decode('utf-8')

def chiffrer(mot, n_bits, cle):
    cle_publique, _ = cle
    e, n = cle_publique
    m = pad_message(mot, n_bits)
    return pow(m, e, n) 

def dechiffrer(c, n_bits, cle):
    _, cle_privee = cle
    if len(cle_privee) == 7: 
        d, n, p, q, dp, dq, qinv = cle_privee
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q
    else:
        d, n = cle_privee[:2]
        m = pow(c, d, n)
    return unpad_message(m, n_bits)

# =========================================================
# -------- CLASSE NRF24 ET LOGIQUE RÉSEAU -----------------
# =========================================================

class SecureNRFChat:
    def __init__(self, pipe_write, pipe_read, ce_pin=17, spi_bus=0, spi_device=0):
        self.radio = None
        self.sim_mode = "hardware" 
        self.seq_send = 0
        
        # Séparation des buffers pour ne pas mélanger le texte et les clés
        self.msg_fragments = []
        self.key_fragments = []
        
        self.on_receive = None  
        self.on_key_received = None # Nouvel écouteur pour l'interface web

        # -------- INITIALISATION RADIO ----------
        try:
            import spidev
            import RPi.GPIO as GPIO
            from lib_nrf24 import NRF24

            GPIO.setmode(GPIO.BCM)
            GPIO.setwarnings(False)

            spi = spidev.SpiDev()
            spi.open(spi_bus, spi_device)
            spi.max_speed_hz = 4000000

            self.radio = NRF24(GPIO, spi) 
            self.radio.begin(spi_device, ce_pin)
            
            self.radio.setRetries(5, 15)
            self.radio.setPayloadSize(32)
            self.radio.setChannel(0x76)
            self.radio.setDataRate(NRF24.BR_1MBPS)
            self.radio.setPALevel(NRF24.PA_LOW)
            self.radio.openWritingPipe(pipe_write)
            self.radio.openReadingPipe(1, pipe_read)
            self.radio.startListening()
            
            print("[INFO] Matériel NRF24 détecté et initialisé.")

        except Exception as e:
            print("[AVERTISSEMENT] Pas d'antenne NRF24 (mode simulation activé).")
            self.radio = None
            self.sim_mode = "sim_crypto"

        print("[INFO] Génération des clés RSA pour le module de chat...")
        self.prime_bits = 512 # Correspond à RSA-1024
        cles = generer_cles_bavardes(self.prime_bits)
        self.public_key = cles[0]
        self.private_key = cles[1]
        
        # Au démarrage, on n'a plus de fausse clé, on la met à None
        self.remote_public_key = None 
        print("[INFO] Clés générées. Chat prêt.")

        if self.radio is not None:
            self.receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
            self.receiver_thread.start()

    def get_fingerprint(self, key):
        if not key: return "EN ATTENTE"
        import hashlib
        key_str = f"{key[0]}||{key[1]}"
        hash_complet = hashlib.sha256(key_str.encode('utf-8')).hexdigest()
        return hash_complet[:8].upper()

    def encrypt(self, message: str) -> bytes:
        if not self.remote_public_key:
            raise ValueError("Impossible de chiffrer : Aucune clé distante reçue !")
        cle_distante_tuple = (self.remote_public_key, None)
        c_int = chiffrer(message, self.prime_bits * 2, cle_distante_tuple)
        return c_int.to_bytes((self.prime_bits * 2) // 8, 'big')

    def decrypt(self, ciphertext: bytes) -> str:
        c_int = int.from_bytes(ciphertext, 'big')
        return dechiffrer(c_int, self.prime_bits * 2, (None, self.private_key))

    def _send_ack(self, seq):
        ack_packet = [seq, 0xFF] + [0] * 30
        self.radio.stopListening()
        self.radio.write(ack_packet)
        self.radio.startListening()

    def _receive_messages(self):
        while True:
            if self.radio.available():
                received = []
                self.radio.read(received, self.radio.getDynamicPayloadSize())
                seq, flags = received[0], received[1]

                if flags == 0xFF: continue
                self._send_ack(seq)

                # --- RECEPTION D'UN MESSAGE TEXTE ---
                if flags in (0x00, 0x01):
                    self.msg_fragments.append(received[2:])
                    if flags == 0x01:
                        total_bytes = b''.join(bytes(f).rstrip(b'\x00') for f in self.msg_fragments)
                        self.msg_fragments = []
                        try:
                            text_clair = self.decrypt(total_bytes)
                            if self.on_receive: self.on_receive(text_clair)
                        except Exception as e:
                            print(f"Erreur de déchiffrement radio: {e}")
                
                # --- RECEPTION D'UNE CLÉ RSA (HANDSHAKE) ---
                elif flags in (0x02, 0x03):
                    self.key_fragments.append(received[2:])
                    if flags == 0x03:
                        total_bytes = b''.join(bytes(f).rstrip(b'\x00') for f in self.key_fragments)
                        self.key_fragments = []
                        try:
                            key_str = total_bytes.decode('utf-8')
                            e_str, n_str = key_str.split("||")
                            self.remote_public_key = (int(e_str), int(n_str))
                            print(f"\n[HANDSHAKE] Clé publique reçue ! Empreinte : {self.get_fingerprint(self.remote_public_key)}")
                            if self.on_key_received: self.on_key_received()
                        except Exception as e:
                            print(f"Erreur Handshake: {e}")

            time.sleep(0.01)

    def send_public_key(self):
        """Diffuse la clé publique locale par ondes radio"""
        if self.radio is None: return
        print("\n[RADIO] Diffusion de la clé publique (Handshake)...")
        key_str = f"{self.public_key[0]}||{self.public_key[1]}"
        data_bytes = key_str.encode('utf-8')
        
        max_payload = 30
        packets = []
        for i in range(0, len(data_bytes), max_payload):
            chunk = data_bytes[i:i + max_payload]
            flags = 0x03 if i + max_payload >= len(data_bytes) else 0x02
            packet = [self.seq_send, flags] + list(chunk)
            while len(packet) < 32: packet.append(0)
            packets.append(packet)

        for pkt in packets:
            self.radio.stopListening()
            self.radio.write(pkt)
            self.radio.startListening()
            time.sleep(0.02)
        self.seq_send = (self.seq_send + 1) % 256
        print("[RADIO] Clé diffusée avec succès.")

    def send(self, message: str):
        if self.radio is None: return 0, 1
        if not self.remote_public_key:
            print("[ERREUR] Vous devez d'abord synchroniser les clés (Handshake) !")
            return 1, 1

        print(f"\n[RADIO] Préparation de l'envoi : '{message}'")
        data_bytes = self.encrypt(message)
        max_payload = 30
        packets = []
        
        for i in range(0, len(data_bytes), max_payload):
            chunk = data_bytes[i:i + max_payload]
            flags = 0x01 if i + max_payload >= len(data_bytes) else 0x00
            packet = [self.seq_send, flags] + list(chunk)
            while len(packet) < 32: packet.append(0)
            packets.append(packet)

        paquets_perdus = 0
        for pkt in packets:
            self.radio.stopListening()
            if not self.radio.write(pkt): paquets_perdus += 1
            self.radio.startListening()
            time.sleep(0.02) 

        self.seq_send = (self.seq_send + 1) % 256
        return paquets_perdus, len(packets)