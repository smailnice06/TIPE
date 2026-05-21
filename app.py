# app.py
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import time
import random
from secure_chat import SecureNRFChat, generer_cles_bavardes, chiffrer, dechiffrer

# --- Initialisation ---
app = Flask(__name__)
socketio = SocketIO(app)

# =======================================================
# ⚠️ POUR LE RASPBERRY PI N°2, INVERSEZ CES DEUX LIGNES :
pipe_write = [0xE1, 0xF0, 0xF0, 0xF0, 0xF0] 
pipe_read  = [0xD2, 0xF0, 0xF0, 0xF0, 0xF0]
# =======================================================

# 1. PRÉPARATION DE LA VARIABLE GLOBALE À VIDE (Bouclier macOS)
chat = None

# --- Routes Web ---
@app.route("/")
def index():
    return render_template("index.html")

@socketio.on("connect")
def handle_connect():
    # Sécurité pour les processus enfants qui n'ont pas de chat initialisé
    if chat is None: 
        return 
        
    etat_materiel = {
        "nrf24_connected": chat.radio is not None,
        "mode": chat.sim_mode,
        "empreinte_locale": chat.get_fingerprint(chat.public_key),
        "empreinte_distante": chat.get_fingerprint(chat.remote_public_key)
    }
    emit("system_status", etat_materiel)

@app.route("/api/run_benchmark")
def run_benchmark():
    tailles_a_tester = [128, 256, 512, 1024, 2048, 4096]
    message_test = "TIPE 2026 - Test!"
    resultats = []
    
    print("\n=== DÉMARRAGE DU BENCHMARK ===")
    for taille in tailles_a_tester:
        print(f"--- Calcul pour {taille} bits ---")
        
        debut = time.perf_counter()
        cles = generer_cles_bavardes(taille)
        t_gen = time.perf_counter() - debut
        
        debut = time.perf_counter()
        msg_c = chiffrer(message_test, taille * 2, (cles[0], None))
        t_chiff = time.perf_counter() - debut
        
        debut = time.perf_counter()
        msg_d = dechiffrer(msg_c, taille * 2, (None, cles[1]))
        t_dechiff = time.perf_counter() - debut

        taille_octets = (taille * 2) // 8
        nb_paquets_nrf24 = (taille_octets // 30) + 1
        
        resultats.append({
            "taille": f"{taille} bits",
            "modulo": f"{taille*2} bits",
            "t_gen": round(t_gen, 4),
            "t_chiff": round(t_chiff, 5),
            "t_dechiff": round(t_dechiff, 5),
            "octets": taille_octets,
            "paquets": nb_paquets_nrf24
        })
    print("=== BENCHMARK TERMINÉ ===")
    return jsonify(resultats)

# --- Routes WebSocket (Chat) ---
@socketio.on("send_message")
def handle_send_message(data):
    # Sécurité supplémentaire
    if chat is None:
        return

    text = data.get("message")
    pseudo = data.get("pseudo", "Anonyme")

    if text:
        try:
            emit("new_message", {"pseudo": pseudo, "message": text}, broadcast=True)

            chiffre_bytes = chat.encrypt(text)
            chiffre_hex = chiffre_bytes.hex() 
            emit("radio_waves", {"pseudo": pseudo, "cipher": chiffre_hex}, broadcast=True)

            # On récupère la VRAIE réalité de l'antenne
            perdus, total = chat.send(text)

            # Calcul du vrai pourcentage de perte
            if total > 0:
                loss_percent = int((perdus / total) * 100)
            else:
                loss_percent = 0
                
            # Si un paquet est perdu, la puce a forcément fait ses 15 retentatives max
            retries_max = 15 if perdus > 0 else 0

            # On envoie les vraies données au tableau de bord
            emit('signal_health', {'loss': loss_percent, 'retry': retries_max}, broadcast=True)

        except Exception as e:
            print(f"Erreur transmission : {e}")

# 2. LE BOUCLIER MULTICŒUR EST ICI
if __name__ == "__main__":
    # Ce bloc n'est lu que par le lancement initial de l'utilisateur.
    # Les processus enfants de macOS s'arrêteront de lire avant d'entrer ici.
    
    chat = SecureNRFChat(pipe_write, pipe_read)

    def quand_message_radio_recu(texte_clair):
        print(f"\n[RÉCEPTION RADIO] Message validé et déchiffré : {texte_clair}")
        socketio.emit("new_message", {"pseudo": "Correspondant distant", "message": texte_clair})

    chat.on_receive = quand_message_radio_recu

    # -- NOUVEAU : Gestion du Handshake Web <-> Radio --
    def quand_cle_recue():
        empreinte = chat.get_fingerprint(chat.remote_public_key)
        socketio.emit("update_fingerprint", {"empreinte_distante": empreinte})

    chat.on_key_received = quand_cle_recue

    @socketio.on("trigger_handshake")
    def handle_handshake():
        if chat is not None:
            chat.send_public_key()

    # Lancement du serveur Web
    socketio.run(app, host="0.0.0.0", port=5001, allow_unsafe_werkzeug=True)