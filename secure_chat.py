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

# =========================================================
# -------- IMPORT DE LA LIBRAIRIE C (GMP) -----------------
# =========================================================

chemin_lib = os.path.join(os.path.dirname(__file__), 'libmiller_custom_gmp.so')
lib_c = ctypes.CDLL(chemin_lib)

lib_c.miller_rabin_custom_gmp.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib_c.miller_rabin_custom_gmp.restype = ctypes.c_int

def test_miller_rabin(n, k=40):
    n_bytes = str(n).encode('utf-8')
    resultat = lib_c.miller_rabin_custom_gmp(n_bytes, k)
    return resultat == 1

# =========================================================
# -------- FONCTIONS DE CRYPTOGRAPHIE CUSTOM --------------
# =========================================================

def generer_grand_premier(bits=1024):
    tentatives = 0
    #pari_local = Pari() 
    #pari_local.allocatemem(64 * 10**6) 
    
    while True:
        candidat = secrets.randbits(bits)
        candidat |= (1 << (bits - 1)) 
        candidat |= 1 
        tentatives += 1

        if test_miller_rabin(candidat, k=40):
            print(f" -> [STATS] Miller-Rabin C a rejeté {tentatives - 1} nombres composés.")
            return candidat
            #if candidat.bit_length() == bits:
                #premier = str(candidat)
                #N = pari_local(premier)
                
                #if pari_local.isprime(N) == 1:
                    #print(" -> [STATS] PARI a confirmé ! C'est un vrai premier.\n")
                    #return candidat

def pgcd(a, b):
    while b: a, b = b, a % b
    return a

def inverse_modulaire(a, m):
    m0 = m
    y = 0
    x = 1
    if m == 1: return 0

    while a > 1:
        if m == 0: break 
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t

    if x < 0: x = x + m0
    return x

def worker_recherche_premier(taille_bits, queue):
    try:
        # On lance la recherche classique
        premier = generer_grand_premier(taille_bits)
        # On met le résultat dans le "tuyau" (Queue) partagé
        queue.put(premier)
    except Exception:
        pass


def generer_cles_bavardes(taille_bits):
    nb_coeurs = os.cpu_count() or 4
    print(f" -> [MULTICORE] Lancement agressif : {nb_coeurs} cœurs sur la ligne de départ...")
    
    # Un "tuyau" de communication thread-safe pour récupérer les résultats
    queue = multiprocessing.Queue()
    processus_actifs = []
    
    # 1. On lâche les loups
    for _ in range(nb_coeurs):
        p = multiprocessing.Process(target=worker_recherche_premier, args=(taille_bits, queue))
        p.start()
        processus_actifs.append(p)
        
    primes_found = []
    
    # 2. On attend sagement à la sortie du tuyau
    while len(primes_found) < 2:
        # L'exécution bloque ici jusqu'à ce qu'un coeur pousse un nombre dans le tuyau
        candidat = queue.get() 
        if candidat not in primes_found:
            primes_found.append(candidat)
            print(f"    [+] Victoire d'un cœur ! ({len(primes_found)}/2)")

    # 3. L'EXECUTION SYSTÈME (On tire la prise des retardataires)
    for p in processus_actifs:
        p.terminate() # Envoie un SIGTERM brutal au système d'exploitation
        p.join()      # Attend la confirmation de la mort du processus
        
    print(" -> [MULTICORE] Les retardataires ont été coupés. Calcul de la clé RSA...")
    
    # On assigne p et q avec nos deux gagnants
    p = primes_found[0]
    q = primes_found[1]
    
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    
    while pgcd(e, phi) != 1: e = secrets.randbelow(3, phi, 2)

    d = inverse_modulaire(e, phi)
    
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = inverse_modulaire(q, p)
    
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