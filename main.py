import logging
from logging.handlers import TimedRotatingFileHandler
import time
import os
import argparse
import sys

# Imports de ton projet
from config import ConfigurationManager
from parse.parse_panos import XMLParser
from parse.parse_cisco import CiscoParser
from api import PanApiSession
from scm import PanApiHandler
from scm.process import Processor, SCMObjectManager
from api.palo_token import PaloToken # (Ou PanosSession si tu as remplacé le fichier)
from panos import PaloConfigManager
import scm.obj as obj

def setup_logging():
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    
    # Fichier de log
    handler = TimedRotatingFileHandler('debug-log.txt', utc=True, when="midnight", interval=1, backupCount=3)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    # Console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)
    return logger

def parse_arguments():
    """Parse les arguments CLI pour éviter les input() bloquants."""
    parser = argparse.ArgumentParser(description="Migration PAN-OS / Cisco vers Strata Cloud Manager (SCM)")
    
    parser.add_argument('--source', choices=['panos', 'cisco'], help="Source de la configuration")
    parser.add_argument('--fetch-live', action='store_true', help="Récupérer la config live du PAN-OS (sinon utilise le XML local)")
    parser.add_argument('--xml-file', type=str, help="Chemin vers le fichier XML local (si --fetch-live n'est pas utilisé)")
    
    parser.add_argument('--scope-type', choices=['folder', 'snippet', 'device_group'], help="Type de scope SCM")
    parser.add_argument('--scope-value', type=str, help="Nom du scope (ex: Shared, Global, DG-Name)")
    
    parser.add_argument('--objects', type=str, help="Liste d'objets spécifiques à migrer (séparés par des virgules)")
    parser.add_argument('--all', action='store_true', help="Migrer tous les objets et règles")
    parser.add_argument('--security', action='store_true', help="Migrer les règles de sécurité")
    parser.add_argument('--nat', action='store_true', help="Migrer les règles NAT")
    
    # Paramètres de performance (Ajustés pour l'API SCM)
    parser.add_argument('--workers', type=int, default=3, help="Nombre de workers parallèles (Défaut: 3, Max recommandé: 5 pour SCM)")
    parser.add_argument('--limit', type=int, default=1000, help="Limite d'objets par requête API")
    
    return parser.parse_args()

def get_file_path_and_type(args, config, logger):
    """Détermine la source et le fichier à parser."""
    # Fallback sur les prompts interactifs si les arguments CLI manquent
    source = args.source
    if not source:
        if os.path.exists('cisco_config.txt'):
            source = input("Do you want to parse Cisco or PANOS configuration? (cisco/panos): ").strip().lower()
        else:
            source = 'panos'

    if source == 'panos':
        fetch_live = args.fetch_live
        if not fetch_live and not args.xml_file:
            user_choice = input("Do you want to retrieve new config from Palo Alto NGFW? (yes/no): ").strip().lower()
            fetch_live = (user_choice == 'yes')

        if fetch_live:
            # Utilisation de la classe PaloToken (ou PanosSession)
            palo_token_manager = PaloToken() 
            token = palo_token_manager.retrieve_token()
            palo_config_manager = PaloConfigManager(token, palo_token_manager.ngfw_url)
            running_config = palo_config_manager.get_running_config()

            file_path = "running_config.xml"
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(running_config)
            logger.info("New running configuration retrieved and saved.")
        else:
            file_path = args.xml_file or config.xml_file_path
            logger.info(f"Using local XML file: {file_path}")
    else:
        file_path = config.cisco_file_path
        logger.info(f"Using Cisco configuration file: {file_path}")

    return file_path, source

def initialize_api_session(logger):
    """Initialise la session OAuth2 vers SCM."""
    logger.info("Initialisation de la session OAuth2 vers Strata Cloud Manager...")
    session = PanApiSession()
    session.authenticate()
    return session

def main():
    logger = setup_logging()
    args = parse_arguments()
    
    try:
        start_time = time.time()
        logger.info(f"Script started at {time.ctime(start_time)}")

        # Chargement de la config globale du projet
        config = ConfigurationManager()
        
        # 1. Connexion à SCM (Cible)
        api_session = initialize_api_session(logger)
        api_handler = PanApiHandler(api_session)

        # 2. Récupération de la config (Source)
        file_path, config_type = get_file_path_and_type(args, config, logger)
        logger.info(f"File path: {file_path}, Config type: {config_type}")

        # 3. Parsing et définition du Scope SCM
        if config_type == 'panos':
            parser = XMLParser(file_path, config_type)
            scope_param_raw, config_type, device_group_name = parser.parse_config_and_set_scope(file_path)
            
            # NETTOYAGE DU SCOPE : L'ancienne API renvoyait "&folder=Shared". 
            # On nettoie pour avoir un format propre "folder=Shared"
            scope_param = scope_param_raw.lstrip('&')
            scope_type, scope_value = scope_param.split('=')
            
            logger.info(f'Current SCM {scope_type}: {scope_value}, PANOS: {config_type}, Device Group: {device_group_name}')
            parser.config_type = config_type
            parser.device_group_name = device_group_name

            if args.objects:
                run_objects_list = args.objects.split(',')
                logger.info(f'Running specific objects: {run_objects_list}')
                parsed_data = parser.parse_specific_types(run_objects_list)
            else:
                run_objects_list = []
                parsed_data = parser.parse_all()
                
        else: # Cisco
            parser = CiscoParser(file_path)
            parser.parse()
            parsed_data = parser.get_parsed_data()
            
            # Gestion du scope pour Cisco
            scope_type = args.scope_type or input("Enter scope type for Cisco (folder/snippet): ").strip().lower()
            scope_value = args.scope_value or input(f"Enter {scope_type} name (Case Sensitive): ").strip()
            scope_param = f"{scope_type}={scope_value}" # Plus de '&' au début
            device_group_name = None
            run_objects_list = args.objects.split(',') if args.objects else []

        logger.debug(f"Parsed data keys: {list(parsed_data.keys())}")

        # 4. Configuration du SCM Object Manager
        selected_obj_types = [o for o in config.obj_types if o.__name__ in run_objects_list] if run_objects_list else config.obj_types
        
        # ATTENTION : max_workers réduit pour éviter les HTTP 429 (Rate Limit) de SCM
        workers = args.workers
        if workers > 5:
            logger.warning("SCM API a des rate-limits stricts. Réduction des workers à 5 pour éviter les erreurs 429.")
            workers = 5

        scm_obj_manager = setup_scm_object_manager(api_handler, selected_obj_types, config.sec_obj, config.nat_obj, scope_param)

        # 5. Exécution de la migration
        if args.all or args.objects:
            logger.info(f"Démarrage du push des OBJETS vers SCM avec {workers} workers...")
            scm_obj_manager.process_objects(parsed_data, scope_param, device_group_name, max_workers=workers, limit=args.limit)
            
        if args.all or args.security:
            logger.info("Push des règles de SÉCURITÉ...")
            scm_obj_manager.process_rules(config.sec_obj, parsed_data, file_path, limit=args.limit, rule_type='security')
            
        if args.all or args.nat:
            logger.info("Push des règles NAT (Séquentiel)...")
            scm_obj_manager.configure.set_max_workers(1)  # NAT doit souvent être séquentiel
            scm_obj_manager.process_rules(config.nat_obj, parsed_data, file_path, limit=args.limit, rule_type='nat')

        logger.info(f"Migration terminée avec succès en {time.time() - start_time:.2f} secondes.")

    except Exception as e:
        logger.exception(f"Erreur fatale pendant la migration : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
