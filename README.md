# qlik-embed-0auth-impersonalisation

Application Flask de démonstration pour l'**impersonation OAuth M2M** avec **qlik-embed** sur Qlik Cloud.

## Architecture

```
Client (navigateur)                    Serveur Flask (Python)              Qlik Cloud
┌─────────────────┐     ┌──────────────────────────────────┐     ┌──────────────────┐
│  qlik-embed      │     │  /oauth/token (client_credentials) │───▶│  GET /oauth/token │
│  (Oauth2)        │     │  /oauth/token (user-impersonation) │───▶│  GET /api/v1/users│
│  getQlikToken()  │◀────│  /api/qlik-token                   │     └──────────────────┘
└─────────────────┘     └──────────────────────────────────┘
                                ▲
                                │ cache (dict + TTL)
```

## Fonctionnement

1. **Login** — l'utilisateur se connecte à l'application Flask (email/mot de passe)
2. **Token admin** — le serveur obtient un token OAuth avec le scope `admin.users` via `client_credentials`
3. **Résolution userId** — le serveur cherche l'utilisateur par email via `GET /api/v1/users` et récupère son `userId` interne Qlik
4. **Impersonation** — le serveur échange le token admin contre un token utilisateur via `grant_type=urn:qlik:oauth:user-impersonation` avec `user_lookup.field=userId`
5. **qlik-embed** — le token est injecté dans la page HTML et passé à qlik-embed via `getAccessToken()`

## Configuration OAuth dans Qlik Cloud

| Étape | Détail |
|-------|--------|
| Client OAuth | M2M (machine-to-machine) avec **User Impersonation** activé |
| Scopes requis | `user_default` (lecture analytics) + `admin.users` (recherche d'utilisateurs) |
| Grant type | `urn:qlik:oauth:user-impersonation` |
| User lookup | `field: "userId"`, `value: <qlik_user_id>` (pas `subject`) |

## Déploiement local

```bash
git clone git@github.com:QlikFrancePlatform/qlik-embed-0auth-impersonalisation.git
cd qlik-embed-0auth-impersonalisation
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Puis ouvrir `http://localhost:5051`.

## Variables d'environnement

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Clé secrète Flask (optionnelle, générée automatiquement si absente) |

## Optimisations

- Cache backend (dict + TTL 5h55) → évite 2 appels API Qlik par requête
- Cache client JS (Promise.resolve) → zéro fetch /api/qlik-token si token valide
- `preconnect` CDN + tenant Qlik → connexions TCP/TLS anticipées
- `preload` du script qlik-embed → téléchargement prioritaire
- `defer` sur le script → ne bloque pas le rendu HTML
- Lazy loading (IntersectionObserver) → chart chargé seulement si visible
- Version CDN figée (`@1.3.0`) → cache navigateur optimal
