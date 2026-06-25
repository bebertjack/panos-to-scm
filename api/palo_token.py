import os
import logging
import xml.etree.ElementTree as ET
import urllib3
import requests
from requests.exceptions import SSLError, RequestException
import yaml

class PanosSession:
    """
    Gère l'authentification et les requêtes vers un pare-feu PAN-OS local (Source).
    """
    def __init__(self, config_path='~/.panapi/config.yml', verify_ssl=None):
        self.config_path = os.path.expanduser(config_path)
        self.config = self._load_config()
        
        self.ngfw_url = self._format_url(self.config.get('palo_alto_ngfw_url', ''))
        self.username = self.config.get('palo_alto_username')
        self.password = self.config.get('palo_alto_password')
        self.token = self.config.get('palo_api_token')
        
        # Gère la vérification SSL (priorité : argument > env var > config > True)
        if verify_ssl is not None:
            self.verify_ssl = verify_ssl
        else:
            env_verify = os.getenv('PANOS_VERIFY_SSL', str(self.config.get('verify_ssl', True))).lower()
            self.verify_ssl = env_verify not in ['false', '0', 'no']

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Initialisation de la session requests (réutilise les connexions TCP)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        
        # Si on a déjà un token, on l'injecte dans les headers
        if self.token:
            self.session.headers.update({'X-PAN-KEY': self.token})

    def _format_url(self, url):
        """S'assure que l'URL se termine bien par /api/"""
        url = url.rstrip('/')
        if not url.endswith('/api'):
            url += '/api'
        return url

    def _load_config(self):
        """Charge la config depuis le YAML ou les variables d'environnement."""
        config = {}
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file) or {}
        
        # Fallback sur les variables d'environnement (meilleure pratique pour la sécu)
        config['palo_alto_ngfw_url'] = os.getenv('PANOS_URL', config.get('palo_alto_ngfw_url'))
        config['palo_alto_username'] = os.getenv('PANOS_USER', config.get('palo_alto_username'))
        config['palo_alto_password'] = os.getenv('PANOS_PASS', config.get('palo_alto_password'))
        config['palo_api_token'] = os.getenv('PANOS_TOKEN', config.get('palo_api_token'))
        
        return config

    def _save_config(self):
        """Sauvegarde le token dans le fichier YAML."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'w', encoding='utf-8') as file:
                yaml.dump(self.config, file)
            logging.info("Token PAN-OS sauvegardé dans le fichier de configuration.")

    def authenticate(self):
        """Récupère ou valide le token API PAN-OS."""
        if not self.token:
            logging.info("Aucun token PAN-OS existant. Génération d'un nouveau token API...")
            if not self.username or not self.password:
                raise ValueError("Username et Password requis pour générer un token PAN-OS.")
                
            payload = {'type': 'keygen', 'user': self.username, 'password': self.password}
            
            try:
                response = self.session.post(f"{self.ngfw_url}/?type=keygen", data=payload)
                response.raise_for_status()
            except SSLError as e:
                raise SSLError(f"Erreur SSL lors de la connexion à {self.ngfw_url}. "
                               f"Si le certificat est auto-signé, définissez verify_ssl=False "
                               f"dans le config.yml ou via PANOS_VERIFY_SSL=False.")
            except RequestException as e:
                raise ConnectionError(f"Impossible de joindre le pare-feu PAN-OS : {e}")

            # Parsing sécurisé de la réponse XML
            root = ET.fromstring(response.content)
            status = root.get('status')
            
            if status == 'success':
                key_element = root.find('.//key')
                if key_element is not None and key_element.text:
                    self.token = key_element.text
                    self.config['palo_api_token'] = self.token
                    self.session.headers.update({'X-PAN-KEY': self.token})
                    self._save_config()
                    logging.info("Token PAN-OS récupéré avec succès.")
                else:
                    raise ValueError("Réponse XML invalide : balise <key> introuvable.")
            else:
                # Extraction du message d'erreur PAN-OS
                msg_element = root.find('.//msg')
                error_msg = msg_element.text if msg_element is not None else "Erreur inconnue"
                raise PermissionError(f"Échec de l'authentification PAN-OS : {error_msg}")
        else:
            logging.info("Utilisation du token PAN-OS existant.")
            
        return self.token

    def get_config(self, xpath: str):
        """Fait une requête GET (configuration) vers l'API XML de PAN-OS."""
        self.authenticate()
        params = {'type': 'config', 'action': 'get', 'xpath': xpath}
        response = self.session.get(f"{self.ngfw_url}/", params=params)
        return response

    def show_operational(self, cmd: str):
        """Fait une requête SHOW (operational) vers l'API XML de PAN-OS."""
        self.authenticate()
        params = {'type': 'op', 'cmd': cmd}
        response = self.session.get(f"{self.ngfw_url}/", params=params)
        return response
