import yaml
import os
import jwt
import threading
import logging
import datetime
from jwt import PyJWKClient
from jwt.exceptions import ExpiredSignatureError, PyJWKClientError
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

# Configuration basique des logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PanApiSession(OAuth2Session):
    """PanApi extension to :class:`requests_oauthlib.OAuth2Session` for Strata Cloud Manager (SCM)."""

    _configfile = "~/.panapi/config.yml"
    _token_url = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
    # URL JWKS officielle et correcte pour le CSP de Palo Alto
    _jwks_uri = "https://auth.apps.paloaltonetworks.com/oauth2/v1/keys" 

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = threading.Lock()
        self.token_expiry = None
        self.signing_key = None

    def authenticate(self, token_url=None, **kwargs):
        self.token_url = token_url or self._token_url
        
        # 1. Récupération des identifiants (kwargs ou fichier YAML)
        keys = ("client_id", "client_secret", "tsg_id")
        if set(keys).issubset(kwargs):
            self.client_id = kwargs.get("client_id")
            self.client_secret = kwargs.get("client_secret")
            self.tsg_id = kwargs.get("tsg_id")
        else:
            config_path = kwargs.get("configfile", self._configfile)
            f = os.path.abspath(os.path.expanduser(os.path.expandvars(config_path)))
            if not os.path.exists(f):
                raise FileNotFoundError(f"Fichier de configuration introuvable : {f}")
                
            with open(f, "r", encoding="utf-8-sig") as c:
                config = yaml.safe_load(c.read())
                
            self.client_id = config["client_id"]
            self.client_secret = config["client_secret"]
            self.tsg_id = config["tsg_id"]

        # 2. CORRECTION MAJEURE : Scope pour Machine-to-Machine (Service Account)
        # On retire "email profile" qui fait planter les comptes de service.
        self.scope = f"tsg_id:{self.tsg_id}"
        
        # 3. Demande du token d'accès
        oauth2_client = BackendApplicationClient(client_id=self.client_id)
        self._client = oauth2_client
        
        logging.info(f"Demande du token OAuth2 pour le TSG ID: {self.tsg_id}...")
        self.fetch_token(
            token_url=self.token_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=self.scope
        )
        
        # 4. Calcul de l'expiration (Timezone-aware pour Python 3.12+)
        expires_in = self.token.get('expires_in', 900) # Défaut 15 min si non spécifié
        self.token_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expires_in)
        logging.info(f"Token récupéré avec succès. Expirera à {self.token_expiry.isoformat()}")
        
        # 5. Récupération de la clé de signature (Optionnel, pour debug)
        try:
            jwks_client = PyJWKClient(self._jwks_uri)
            self.signing_key = jwks_client.get_signing_key_from_jwt(self.token['access_token'])
        except Exception as e:
            logging.warning(f"Impossible de récupérer le JWKS pour décoder le token : {e}. Le décodage local sera ignoré.")
            self.signing_key = None

    def reauthenticate(self):
        logging.info("Réauthentification de la session (Token expiré ou proche de l'expiration)...")
        self.fetch_token(
            token_url=self.token_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=self.scope
        )
        expires_in = self.token.get('expires_in', 900)
        self.token_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expires_in)
        logging.info(f"Nouveau token récupéré. Expirera à {self.token_expiry.isoformat()}")

    def decode_token(self):
        if not self.signing_key:
            logging.warning("Aucune clé de signature disponible. Impossible de décoder le token.")
            return None
            
        payload = jwt.decode(
            self.token['access_token'],
            self.signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            options={"verify_exp": False, "verify_iat": False},
        )
        return payload

    def ensure_valid_token(self):
        with self._lock:
            if self.is_expired:
                self.reauthenticate()
    
    @property
    def is_expired(self):
        if not self.token_expiry:
            return True
            
        # Vérifie si le temps actuel est à moins de 60 secondes de l'expiration
        buffer_time = datetime.timedelta(seconds=60)
        now = datetime.datetime.now(datetime.timezone.utc)
        
        if now >= (self.token_expiry - buffer_time):
            logging.debug("Le token est sur le point d'expirer ou a déjà expiré.")
            return True
        return False
