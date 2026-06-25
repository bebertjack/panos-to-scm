import requests
import xml.etree.ElementTree as ET
import logging
import urllib3
from requests.exceptions import SSLError, RequestException

class PaloConfigManager:
    """
    Gère la récupération de la configuration complète (running-config) 
    depuis un pare-feu PAN-OS via l'API XML.
    """
    def __init__(self, token: str, base_url: str, verify_ssl: bool = True):
        self.token = token
        
        # S'assure que l'URL est bien formée (doit se terminer par /api)
        self.base_url = base_url.rstrip('/')
        if not self.base_url.endswith('/api'):
            self.base_url += '/api'
            
        self.verify_ssl = verify_ssl
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
        # Utilisation d'une session pour réutiliser les connexions TCP (plus rapide)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update({'X-PAN-KEY': self.token})

    def get_running_config(self) -> str:
        """
        Récupère la configuration XML complète du pare-feu.
        Retourne la chaîne XML brute.
        """
        logging.info(f"Téléchargement de la configuration XML depuis {self.base_url}...")
        
        # L'API PAN-OS utilise 'show' pour la config courante (running-config)
        payload = {
            'type': 'config', 
            'action': 'show', 
            'xpath': '/config/'
        }
        
        try:
            response = self.session.get(self.base_url, params=payload)
            response.raise_for_status()
        except SSLError as e:
            raise SSLError(
                f"Erreur SSL lors de la connexion à {self.base_url}. "
                f"Si le certificat est auto-signé, assurez-vous de configurer "
                f"verify_ssl=False dans votre fichier config.yml ou via les variables d'environnement."
            ) from e
        except RequestException as e:
            raise ConnectionError(f"Impossible de joindre le pare-feu PAN-OS : {e}") from e

        # Parsing de la réponse pour vérifier le statut PAN-OS
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as e:
            raise ValueError(f"Réponse non-XML reçue du pare-feu : {response.text[:200]}") from e

        status = root.get('status')
        if status == 'success':
            config_element = root.find('.//config')
            if config_element is not None:
                logging.info('Configuration XML téléchargée avec succès.')
                # Retourne le XML sous forme de chaîne de caractères (unicode)
                return ET.tostring(config_element, encoding='unicode')
            else:
                raise ValueError("Succès reçu, mais aucune balise <config> trouvée dans la réponse XML.")
        else:
            # Extraction du message d'erreur précis renvoyé par PAN-OS
            msg_element = root.find('.//msg')
            error_msg = msg_element.text if msg_element is not None else "Erreur inconnue"
            raise PermissionError(f"Échec de la récupération de la config PAN-OS : {error_msg}")

    def make_request(self, payload: dict) -> requests.Response:
        """Méthode générique pour faire d'autres requêtes API PAN-OS si besoin."""
        try:
            response = self.session.get(self.base_url, params=payload)
            response.raise_for_status()
            return response
        except RequestException as e:
            logging.error(f"Erreur lors de la requête API PAN-OS : {e}")
            raise
