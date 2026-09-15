# SPEC — `chat` : messagerie terminal P2P chiffrée en C

## 1. Objectif

Construire une messagerie terminal multiplateforme **Fedora ↔ macOS** écrite en **C**.

UX principale :

```bash
chat nathan
```

Si `nathan` est en ligne :

```text
Connecting to nathan...
Connected to nathan [direct P2P]
Encrypted session established.

nathan > salut
you    > _
```

S'il est hors ligne :

```text
nathan is offline.
```

Le système doit :

- utiliser une connexion **P2P directe** dès que possible ;
- fonctionner derrière les NAT/box classiques grâce à **ICE/STUN** ;
- utiliser **TURN comme fallback** uniquement si une connexion directe est impossible ;
- chiffrer les messages **de bout en bout** ;
- ne conserver **aucun historique de messages côté serveur** ;
- fonctionner sous Fedora et macOS ;
- fournir un binaire CLI `chat` et un daemon utilisateur `chatd`.

Le serveur central ne sert qu'à :

- gérer les pseudos ;
- annoncer présence/absence ;
- transmettre les informations nécessaires au rendez-vous ICE ;
- authentifier les identités ;
- éventuellement fournir les paramètres TURN.

Le serveur ne doit jamais avoir accès au texte en clair des conversations.

---

# 2. Contraintes de la V1

Implémenter uniquement :

- conversation 1-à-1 ;
- texte UTF-8 ;
- une seule conversation active à la fois ;
- Fedora ;
- macOS ;
- IPv4 + IPv6 si disponibles ;
- pas de fichiers ;
- pas de groupes ;
- pas de messages hors ligne ;
- pas d'historique serveur ;
- pas de synchronisation multi-appareils ;
- pas d'interface ncurses au début.

La priorité est d'obtenir rapidement :

```bash
chat nathan
```

avec connexion + chiffrement + échange de texte.

---

# 3. Stack technique

## Langage

C17.

Compiler avec au minimum :

```text
-Wall -Wextra -Wpedantic
```

En développement, prévoir également une configuration :

```text
-fsanitize=address,undefined
```

## Build

CMake.

## Bibliothèques

### Réseau P2P / NAT traversal

**libnice**

Utiliser :

- ICE ;
- STUN ;
- TURN ;
- IPv4/IPv6.

libnice implémente ICE et fournit notamment `NiceAgent`, la collecte de candidats, STUN et TURN.

### Canal de contrôle

**libwebsockets**

Utilisé entre :

```text
chatd <-> chat-server
```

Le canal de contrôle doit utiliser :

```text
wss://
```

en production.

### Cryptographie

**libsodium**

Ne pas implémenter soi-même de primitive cryptographique.

Utiliser :

- `sodium_init()`
- `crypto_kx_*` pour dériver des clés de session TX/RX ;
- `crypto_secretstream_xchacha20poly1305_*` pour chiffrer les messages de la session ;
- `sodium_memzero()` pour effacer les clés temporaires.

### Runtime

libnice dépend de GLib.

Utiliser la boucle d'événements GLib pour le daemon si cela simplifie l'intégration avec libnice.

---

# 4. Arborescence cible

```text
chat/
├── CMakeLists.txt
├── README.md
├── docs/
│   └── protocol.md
├── common/
│   ├── protocol.h
│   ├── protocol.c
│   ├── crypto.h
│   ├── crypto.c
│   ├── log.h
│   └── log.c
├── client/
│   ├── main.c
│   ├── ipc_client.c
│   └── ipc_client.h
├── daemon/
│   ├── main.c
│   ├── daemon.h
│   ├── presence.c
│   ├── presence.h
│   ├── ice.c
│   ├── ice.h
│   ├── session.c
│   ├── session.h
│   ├── ipc_server.c
│   ├── ipc_server.h
│   ├── identity.c
│   └── identity.h
├── server/
│   ├── main.c
│   ├── users.c
│   ├── users.h
│   ├── websocket.c
│   └── websocket.h
├── packaging/
│   ├── systemd/
│   │   └── chatd.service
│   ├── launchd/
│   │   └── chatd.plist
│   ├── fedora/
│   └── homebrew/
└── tests/
    ├── test_crypto.c
    ├── test_protocol.c
    └── test_identity.c
```

Produire trois exécutables :

```text
chat
chatd
chat-server
```

---

# 5. Responsabilité des exécutables

## `chat`

CLI utilisée directement par l'utilisateur.

Exemples :

```bash
chat init alex
chat status
chat nathan
chat fingerprint nathan
```

Le CLI ne doit pas gérer lui-même la présence Internet permanente.

Il communique localement avec `chatd`.

## `chatd`

Daemon utilisateur.

Responsabilités :

- charger l'identité ;
- se connecter à `chat-server` ;
- maintenir la présence ;
- recevoir les demandes entrantes ;
- gérer libnice ;
- établir les connexions P2P ;
- établir les sessions cryptographiques ;
- transmettre les données entre `chat` et le peer distant.

## `chat-server`

Serveur de contrôle.

Responsabilités :

```text
username -> public key
username -> online/offline
username -> websocket actuellement connecté
```

Il transmet également :

- offre de conversation ;
- paramètres ICE ;
- candidats ICE ;
- informations TURN temporaires si nécessaire.

Il ne reçoit jamais les messages applicatifs après établissement de la session P2P/TURN.

---

# 6. Installation des dépendances

## Fedora

Prévoir dans la documentation :

```bash
sudo dnf install \
    gcc \
    cmake \
    pkgconf-pkg-config \
    glib2-devel \
    libnice-devel \
    libsodium-devel \
    libwebsockets-devel
```

## macOS

Via Homebrew :

```bash
brew install \
    cmake \
    pkg-config \
    glib \
    libnice \
    libsodium \
    libwebsockets
```

Le CMake doit privilégier `pkg-config` pour trouver les bibliothèques.

---

# 7. Configuration locale

Linux :

```text
~/.config/chat/
```

macOS :

```text
~/Library/Application Support/chat/
```

Au minimum :

```text
config.toml
identity.key
identity.pub
contacts.db
chatd.sock
```

`identity.key` doit avoir des permissions strictes :

```text
0600
```

Ne jamais logger :

- clé privée ;
- clé de session ;
- plaintext d'un message en mode normal.

---

# 8. Création d'identité

Commande :

```bash
chat init alex
```

Actions :

1. appeler `sodium_init()` ;
2. vérifier que l'identité n'existe pas déjà ;
3. générer une paire de clés avec `crypto_kx_keypair()` ;
4. écrire la clé privée localement avec permission `0600` ;
5. inscrire auprès du serveur :
   - `username = alex`
   - clé publique ;
6. sauvegarder l'URL du serveur dans `config.toml`.

Exemple :

```text
Created identity: alex
Fingerprint: 7f:12:92:ac:42:...
```

Le serveur doit refuser deux inscriptions concurrentes du même pseudo.

Pour une vraie mise en production, prévoir ensuite un mécanisme de récupération/changement de pseudo. Ce n'est pas nécessaire dans la V1.

---

# 9. Fingerprint et pinning des contacts

La première fois que `alex` contacte `nathan`, afficher l'empreinte de la clé publique :

```text
New contact: nathan
Fingerprint:
7F:12:92:AC:42:13:...

Trust this identity? [Y/n]
```

Après confirmation :

```text
nathan -> public_key
```

est enregistré localement.

Lors d'une connexion suivante :

- comparer la clé reçue du serveur avec celle enregistrée ;
- si elle change, bloquer la connexion par défaut.

Message :

```text
SECURITY ERROR:
Nathan's identity key changed.
Connection refused.
```

Ne jamais mettre automatiquement à jour une clé déjà approuvée.

---

# 10. Présence

Au démarrage de `chatd` :

```text
chatd -> WSS -> chat-server
```

Envoyer :

```json
{
  "type": "hello",
  "username": "alex",
  "public_key": "...",
  "protocol_version": 1
}
```

Le serveur répond :

```json
{
  "type": "hello_ok"
}
```

Maintenir la connexion WebSocket ouverte.

Le statut en ligne correspond à une connexion de contrôle authentifiée actuellement active.

Si la WebSocket disparaît :

```text
alex = offline
```

Le daemon doit se reconnecter automatiquement avec backoff.

---

# 11. Authentification du canal de présence

Ne pas considérer un simple champ `username` comme une authentification.

Le serveur doit envoyer un challenge aléatoire.

Le client doit prouver qu'il possède sa clé privée.

Si `crypto_kx` n'est pas adapté à cette preuve d'identité, utiliser une paire de signatures Ed25519 dédiée via libsodium :

```text
crypto_sign_keypair()
crypto_sign_detached()
crypto_sign_verify_detached()
```

Architecture recommandée :

```text
Identity de compte = Ed25519
Clés éphémères de session = crypto_kx
```

Le serveur stocke la clé publique Ed25519 du compte.

Flow :

```text
client -> username
server -> random challenge
client -> signature(challenge)
server -> verify(public_key)
```

La clé privée reste locale.

---

# 12. Commande `chat nathan`

Le flow cible est exactement :

```text
chat nathan
    |
    v
chatd
    |
    v
chat-server
    |
    +-- nathan offline -> erreur
    |
    `-- nathan online
          |
          v
      négociation ICE
          |
          v
      session sécurisée
          |
          v
        chat
```

## Si Nathan est offline

Afficher :

```text
nathan is offline.
```

et retourner un code d'erreur non nul.

## Si Nathan est online

Afficher :

```text
Connecting to nathan...
```

Puis commencer le rendez-vous ICE.

---

# 13. Signalisation ICE

Le serveur WebSocket est utilisé comme canal de signalisation.

Messages nécessaires :

```text
CHAT_REQUEST
CHAT_ACCEPT
CHAT_REJECT
ICE_CREDENTIALS
ICE_CANDIDATE
ICE_GATHERING_DONE
CHAT_CANCEL
```

Exemple logique :

```json
{
  "type": "chat_request",
  "from": "alex",
  "to": "nathan",
  "session_id": "random-id"
}
```

Nathan accepte automatiquement dans la V1 si le contact n'est pas bloqué.

Le serveur retransmet les informations, mais ne participe pas au flux de messages une fois ICE établi.

---

# 14. ICE avec libnice

Créer un `NiceAgent`.

Flow :

1. `nice_agent_new()` ou variante appropriée ;
2. `nice_agent_add_stream()` ;
3. configurer un serveur STUN ;
4. configurer TURN si disponible ;
5. `nice_agent_gather_candidates()` ;
6. récupérer :
   - credentials ICE locales ;
   - candidats locaux ;
7. transmettre au peer via `chat-server` ;
8. recevoir ses credentials/candidats ;
9. utiliser :
   - `nice_agent_set_remote_credentials()`
   - `nice_agent_set_remote_candidates()`
10. attendre l'état connecté/ready.

Le daemon doit écouter les changements d'état ICE.

---

# 15. STUN

En développement, autoriser un serveur STUN configurable :

```toml
[network]
stun_host = "..."
stun_port = 3478
```

Ne pas hardcoder une dépendance permanente à un STUN public dans le code.

En production, déployer son propre service STUN/TURN.

---

# 16. TURN fallback

Pour respecter au mieux l'UX :

```text
si Nathan est online -> la conversation doit normalement fonctionner
```

TURN doit être disponible en fallback.

Flow :

```text
ICE candidates
   |
   +--> host candidate
   |
   +--> server reflexive via STUN
   |
   `--> relay candidate via TURN
```

ICE sélectionne la meilleure paire.

Ordre souhaité :

1. direct LAN si possible ;
2. direct Internet/hole punching ;
3. TURN relay.

Même avec TURN :

```text
Alex ===== encrypted bytes ===== TURN ===== encrypted bytes ===== Nathan
```

Le serveur TURN ne doit pas posséder les clés E2EE.

Pour le déploiement, utiliser **coturn** plutôt que réimplémenter un serveur TURN.

Le serveur de présence peut fournir des credentials TURN temporaires.

---

# 17. Établissement de la session cryptographique

Une connexion ICE n'est pas considérée comme une session de chat sécurisée à elle seule.

Après ICE :

1. échanger une clé publique de session éphémère ;
2. authentifier cet échange avec l'identité longue durée ;
3. vérifier la signature distante ;
4. dériver des clés RX/TX indépendantes ;
5. initialiser un flux cryptographique par direction ;
6. effacer les secrets temporaires inutiles.

Utiliser `crypto_kx_*`.

Exemple conceptuel :

```text
Alex                                Nathan

ephemeral KX pk_A                   ephemeral KX pk_B
       |                                   |
       |-------- pk_A + signature -------->|
       |<------- pk_B + signature ---------|
       |                                   |
       +----- derive tx/rx session keys ---+
```

Ne jamais utiliser une clé longue durée directement comme clé de chiffrement de tous les messages.

---

# 18. Chiffrement des messages

Après le key exchange, utiliser :

```text
crypto_secretstream_xchacha20poly1305
```

Créer un secretstream indépendant dans chaque direction.

Pourquoi :

- chiffrement authentifié ;
- ordre de flux ;
- nonces gérés par libsodium ;
- rekey possible ;
- détection d'altération ;
- adapté à une suite de messages.

Échange initial :

```text
Alice -> secretstream header TX -> Bob
Bob   -> secretstream header TX -> Alice
```

Puis chaque message applicatif est passé à :

```text
crypto_secretstream_xchacha20poly1305_push()
```

À la réception :

```text
crypto_secretstream_xchacha20poly1305_pull()
```

Si `pull()` échoue :

- considérer le paquet comme invalide ;
- fermer la session.

À la fin :

```text
TAG_FINAL
```

Effacer les clés via `sodium_memzero()`.

---

# 19. Transport applicatif au-dessus d'ICE

Définir un framing explicite.

Ne jamais supposer qu'un appel réseau correspond exactement à un message.

Format binaire V1 :

```text
+----------+----------+-------------+----------------+
| version  | type     | length      | payload        |
| uint8    | uint8    | uint32 BE   | length bytes   |
+----------+----------+-------------+----------------+
```

Types :

```c
enum chat_packet_type {
    CHAT_PKT_HANDSHAKE = 1,
    CHAT_PKT_STREAM_HEADER = 2,
    CHAT_PKT_MESSAGE = 3,
    CHAT_PKT_CLOSE = 4,
    CHAT_PKT_PING = 5,
    CHAT_PKT_PONG = 6
};
```

Limiter strictement `length`.

Exemple :

```c
#define CHAT_MAX_MESSAGE_SIZE (64 * 1024)
```

Toute taille supérieure doit provoquer le rejet du paquet.

---

# 20. Messages texte

Payload plaintext avant chiffrement :

```text
UTF-8 bytes
```

Pas besoin de JSON pour les messages utilisateur.

Pour les messages du serveur de contrôle, JSON est acceptable en V1.

Maximum recommandé :

```text
64 KiB
```

par message.

---

# 21. IPC local entre `chat` et `chatd`

Le CLI et le daemon doivent communiquer en local.

Fedora/macOS :

```text
Unix domain socket
```

Exemple Linux :

```text
$XDG_RUNTIME_DIR/chatd.sock
```

Fallback :

```text
~/.config/chat/chatd.sock
```

Le socket doit être accessible uniquement par l'utilisateur.

Commandes IPC :

```text
STATUS
LOOKUP
OPEN_CHAT
SEND_MESSAGE
CLOSE_CHAT
```

Le flux des messages reçus est renvoyé au CLI via ce socket.

---

# 22. Interface CLI V1

Ne pas utiliser ncurses pour la première implémentation.

L'objectif est :

```text
$ chat nathan

Connecting to nathan...
Connected to nathan [P2P]
Encrypted session established.

nathan > salut
you    > bonjour
nathan > ça marche
you    > _
```

Le CLI doit surveiller simultanément :

- stdin ;
- socket IPC vers `chatd`.

Utiliser :

```text
poll()
```

ou une approche équivalente.

`Ctrl+C` ferme proprement la conversation.

---

# 23. Connexion entrante

Dans la V1, si Nathan exécute :

```bash
chat alex
```

et Alex est en ligne :

- `chatd` d'Alex reçoit `CHAT_REQUEST` ;
- si Nathan est un contact connu et non bloqué, accepter automatiquement ;
- sinon le CLI peut demander confirmation.

Pour aller vite, implémenter d'abord l'acceptation automatique.

---

# 24. Affichage du mode réseau

Après établissement ICE, afficher :

```text
Connected to nathan [direct P2P]
```

ou :

```text
Connected to nathan [TURN relay]
```

Le mode relay ne change pas le statut du chiffrement.

Toujours afficher ensuite :

```text
Encrypted session established.
```

uniquement après réussite du handshake cryptographique.

---

# 25. Timeout

Ne jamais attendre indéfiniment.

Exemple :

```text
presence lookup: 5 s
ICE negotiation: 15 s
crypto handshake: 5 s
```

Si Nathan est annoncé online mais que la connexion échoue :

```text
nathan is online, but the connection could not be established.
```

Ne pas afficher `offline` dans ce cas.

---

# 26. Codes de sortie du CLI

Exemple :

```text
0  success
1  generic error
2  user offline
3  connection failed
4  identity mismatch
5  daemon unavailable
6  authentication failed
```

---

# 27. Serveur de présence — modèle minimal

Structure logique :

```c
typedef struct {
    char username[33];
    unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES];
    struct lws *wsi;
    int online;
} user_t;
```

En production, persister uniquement :

```text
username
identity public key
created_at
```

Ne pas persister :

```text
messages
session keys
conversation content
ICE candidates après fin de session
```

Les candidats ICE sont temporaires et doivent être supprimés après la session.

---

# 28. Protocole serveur

Messages JSON minimum :

```text
HELLO
AUTH_CHALLENGE
AUTH_RESPONSE
AUTH_OK
USER_LOOKUP
USER_STATUS
CHAT_REQUEST
CHAT_ACCEPT
CHAT_REJECT
ICE_CREDENTIALS
ICE_CANDIDATE
ICE_DONE
CHAT_END
```

Chaque message lié à une conversation possède :

```text
session_id
from
to
```

Le serveur vérifie que le `from` correspond réellement à la WebSocket authentifiée.

Ne jamais faire confiance à `from` fourni par le client sans vérification.

---

# 29. Sécurité réseau

Production :

```text
wss://
```

avec certificat TLS valide pour le serveur de contrôle.

Même si les messages P2P sont E2EE, TLS reste nécessaire pour protéger :

- présence ;
- metadata de rendez-vous ;
- authentification ;
- candidats ICE ;
- credentials TURN.

---

# 30. Sécurité mémoire

Pour les clés secrètes :

- limiter les copies ;
- appeler `sodium_memzero()` après usage ;
- ne jamais imprimer les buffers secrets ;
- vérifier tous les codes de retour libsodium ;
- utiliser des tailles provenant des constantes libsodium.

Si utile ensuite :

```text
sodium_mlock()
sodium_munlock()
```

peuvent être ajoutés.

---

# 31. Validation des entrées

Valider strictement :

## Username

Exemple :

```text
[a-zA-Z0-9_-]
```

Longueur :

```text
3..32
```

## Messages réseau

Toujours vérifier :

- version ;
- type ;
- longueur ;
- état actuel de la machine à états ;
- provenance/session_id.

Ne jamais caster aveuglément un buffer reçu en struct C sans vérifier les tailles et l'endianness.

---

# 32. Pas d'historique

V1 :

- les messages ne sont pas écrits sur disque ;
- ils existent uniquement en mémoire ;
- aucune file d'attente offline.

Si le peer disparaît :

```text
Connection lost.
```

Le message suivant n'est pas stocké pour livraison ultérieure.

---

# 33. Daemon Fedora

Créer :

```text
packaging/systemd/chatd.service
```

Service utilisateur, pas root.

Objectif :

```bash
systemctl --user enable --now chatd
```

Le package peut l'activer/documenter.

Le daemon ne doit jamais nécessiter les privilèges root.

---

# 34. Daemon macOS

Créer un LaunchAgent utilisateur :

```text
~/Library/LaunchAgents/...
```

Le packaging installe un plist permettant à `chatd` de démarrer à l'ouverture de session.

Pas de daemon système root.

---

# 35. Packaging Fedora

Cible finale :

```bash
sudo dnf install chat
```

Le RPM contient :

```text
/usr/bin/chat
/usr/bin/chatd
```

Le serveur n'est pas nécessaire dans le package client.

Préparer un `.spec` RPM après stabilisation.

---

# 36. Packaging macOS

Cible finale :

```bash
brew install <tap>/chat
```

Créer une Formula Homebrew après stabilisation.

Ne pas bloquer le développement initial sur le packaging.

---

# 37. Serveur TURN

Ne pas développer TURN soi-même.

Déployer `coturn`.

Prévoir :

```text
turn.example.com:3478
```

et TLS TURN ultérieurement si nécessaire.

Le serveur de présence peut distribuer des credentials TURN temporaires à la demande.

Ne jamais mettre un mot de passe TURN permanent public en dur dans le client.

---

# 38. Ordre d'implémentation demandé à Codex

Codex doit avancer dans cet ordre, mais produire directement le produit final sans créer plusieurs projets jetables.

## Étape 1 — squelette

Créer :

- CMake ;
- `chat` ;
- `chatd` ;
- `chat-server` ;
- bibliothèque `common`.

Tous doivent compiler sur Fedora.

## Étape 2 — identité

Implémenter :

```bash
chat init <username>
```

avec :

- identité Ed25519 longue durée ;
- stockage local sécurisé ;
- fingerprint.

## Étape 3 — serveur

Implémenter :

- WebSocket ;
- inscription ;
- challenge d'authentification ;
- présence ;
- lookup username.

## Étape 4 — daemon

Implémenter :

- lancement ;
- chargement identité ;
- authentification serveur ;
- heartbeat / présence ;
- reconnexion.

## Étape 5 — IPC

Implémenter :

```text
chat <-> Unix socket <-> chatd
```

et :

```bash
chat status
```

## Étape 6 — `chat nathan`

Implémenter le lookup :

```bash
chat nathan
```

Si offline :

```text
nathan is offline.
```

## Étape 7 — signalisation

Ajouter :

```text
CHAT_REQUEST
CHAT_ACCEPT
ICE credentials
ICE candidates
```

## Étape 8 — libnice

Établir une connexion ICE réelle entre deux machines.

Tester :

1. même LAN ;
2. deux réseaux différents.

## Étape 9 — TURN

Ajouter coturn et vérifier que le relay fonctionne lorsque le direct est bloqué.

## Étape 10 — handshake crypto

Ajouter :

- clé KX éphémère ;
- signature avec identité Ed25519 ;
- vérification ;
- dérivation RX/TX.

## Étape 11 — secretstream

Créer deux flux :

```text
Alex -> Nathan
Nathan -> Alex
```

et chiffrer chaque message.

## Étape 12 — terminal interactif

Implémenter :

```text
nathan > ...
you    > ...
```

avec `poll()`.

## Étape 13 — fermeture propre

Gérer :

- Ctrl+C ;
- peer disconnect ;
- daemon disconnect ;
- serveur disconnect ;
- timeout ;
- TAG_FINAL ;
- nettoyage mémoire.

## Étape 14 — macOS

Faire compiler et fonctionner :

```text
chat
chatd
```

sur macOS.

## Étape 15 — services utilisateur

Ajouter :

- systemd user Fedora ;
- launchd macOS.

## Étape 16 — packaging

Créer :

- RPM ;
- Homebrew Formula.

---

# 39. Tests obligatoires

## Tests unitaires

### crypto

Tester :

- signature correcte ;
- signature invalide ;
- dérivation KX ;
- secretstream encrypt/decrypt ;
- modification d'un ciphertext ;
- clé distante incorrecte.

### protocol

Tester :

- paquet valide ;
- longueur excessive ;
- paquet tronqué ;
- type inconnu ;
- mauvaise version.

### identity

Tester :

- création ;
- chargement ;
- permissions ;
- fingerprint ;
- mismatch d'un contact.

---

# 40. Tests d'intégration

## Test 1 — localhost

Deux identités :

```text
alex
nathan
```

sur la même machine avec configs séparées.

Objectif :

```bash
chat nathan
```

et échange de messages.

## Test 2 — LAN

Fedora et Mac sur le même réseau.

Vérifier :

```text
[direct P2P]
```

## Test 3 — Internet

Fedora et Mac sur deux accès Internet différents.

Vérifier ICE/STUN.

## Test 4 — TURN forcé

Bloquer/éviter les candidats directs.

Vérifier :

```text
[TURN relay]
```

et que le chat reste chiffré.

## Test 5 — mauvais serveur

Modifier la clé publique de Nathan côté serveur.

Le client doit refuser si une clé différente a déjà été pinée.

## Test 6 — corruption réseau

Modifier un ciphertext.

`crypto_secretstream_*_pull()` doit échouer et la session doit être fermée.

---

# 41. Logging

Prévoir :

```text
ERROR
WARN
INFO
DEBUG
TRACE
```

Par défaut :

```text
INFO
```

Ne jamais logger le plaintext d'un message.

En DEBUG :

autorisé :

```text
ICE state
candidate type
peer username
session id
packet type/size
```

interdit :

```text
private key
session key
message plaintext
TURN password permanent
```

---

# 42. États d'une session

Implémenter explicitement une machine à états :

```text
IDLE
LOOKUP
REQUESTING
ICE_NEGOTIATING
ICE_CONNECTED
CRYPTO_HANDSHAKE
SECURE
CLOSING
CLOSED
FAILED
```

Rejeter tout message incompatible avec l'état actuel.

Exemple :

un `CHAT_PKT_MESSAGE` reçu avant `SECURE` doit être rejeté.

---

# 43. Definition of Done V1

La V1 est terminée lorsque :

1. Fedora et macOS peuvent installer/compiler le client.
2. Alex et Nathan possèdent chacun une identité persistante.
3. Les deux `chatd` annoncent leur présence.
4. `chat nathan` retourne immédiatement une erreur si Nathan est offline.
5. Si Nathan est online, ICE établit une route.
6. Une connexion P2P directe est utilisée lorsqu'elle est disponible.
7. TURN fonctionne en fallback.
8. Une session cryptographique authentifiée est établie.
9. Les messages texte sont chiffrés de bout en bout.
10. Le serveur de présence et TURN ne peuvent pas lire les messages.
11. Un changement inattendu de clé d'identité est détecté.
12. Aucun message n'est stocké côté serveur.
13. `Ctrl+C` ferme proprement la session.
14. Les secrets de session sont effacés de la mémoire après usage.

---

# 44. Ce qu'il ne faut PAS faire

Codex ne doit pas :

- créer son propre algorithme cryptographique ;
- utiliser XOR comme chiffrement ;
- utiliser AES/ChaCha directement sans API AEAD éprouvée ;
- réutiliser des nonces manuellement ;
- envoyer les messages texte via le serveur de présence ;
- stocker les messages côté serveur ;
- désactiver la vérification TLS ;
- accepter automatiquement une nouvelle clé pour un contact déjà connu ;
- exposer la clé privée ;
- nécessiter root pour `chatd` ;
- réimplémenter STUN/TURN ;
- supposer que UDP/TCP conserve les limites des messages applicatifs ;
- utiliser `strcpy`, `sprintf`, `gets` ou fonctions dangereuses sans bornage.

---

# 45. Choix à privilégier en cas d'ambiguïté

Si Codex doit choisir sans demander :

```text
simplicité > fonctionnalités supplémentaires
sécurité > optimisation
API libsodium haut niveau > primitive maison
connexion directe > TURN
TURN > échec si le direct est impossible
formats explicites > cast de structures réseau
configuration > valeurs réseau hardcodées
```

Ne pas ajouter de fonctionnalités hors scope avant que la V1 fonctionne.

---

# 46. Commandes finales attendues

Initialisation :

```bash
chat init alex
```

Statut :

```bash
chat status
```

Conversation :

```bash
chat nathan
```

Exemple :

```text
$ chat nathan
Connecting to nathan...
Connected to nathan [direct P2P]
Encrypted session established.

nathan > Salut
you    > Salut
nathan > Ça marche.
you    > _
```

Offline :

```text
$ chat nathan
nathan is offline.
```

Relay :

```text
$ chat nathan
Connecting to nathan...
Connected to nathan [TURN relay]
Encrypted session established.
```

---

# 47. Références techniques

Documentation officielle à utiliser avant d'implémenter les APIs :

- libnice — ICE / STUN / TURN :
  https://libnice.freedesktop.org/
- libnice NiceAgent :
  https://libnice.freedesktop.org/libnice/NiceAgent.html
- libsodium — Key exchange :
  https://doc.libsodium.org/key_exchange
- libsodium — Secretstream :
  https://doc.libsodium.org/secret-key_cryptography/secretstream
- libsodium — Authenticated public-key encryption :
  https://doc.libsodium.org/public-key_cryptography/authenticated_encryption
- libwebsockets :
  https://libwebsockets.org/

Toujours vérifier les signatures exactes des fonctions contre la documentation correspondant à la version installée.

---

# 48. Instruction globale pour Codex

Implémente ce projet en C en privilégiant un résultat fonctionnel de bout en bout.

Ne crée pas une série de prototypes indépendants. Construis directement l'architecture cible dans un seul repository.

À chaque étape :

1. compiler ;
2. corriger tous les warnings pertinents ;
3. lancer les tests disponibles ;
4. conserver les fonctionnalités précédemment fonctionnelles ;
5. documenter toute décision d'architecture non évidente dans `docs/protocol.md`.

Si une décision mineure manque, choisis l'option la plus simple respectant cette spécification au lieu de bloquer.

Pour toute décision concernant la cryptographie ou ICE, suivre les APIs et recommandations officielles des bibliothèques plutôt que d'inventer un protocole ad hoc.
