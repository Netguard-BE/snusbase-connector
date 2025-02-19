#!/usr/bin/env python3
import os
import json
import yaml
import logging
import requests
import sqlite3
import schedule
import time
from typing import Any, Dict, List, Union
from pycti import OpenCTIApiClient, get_config_variable
from stix2 import TLP_RED
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class SnusbaseConnector:
    def __init__(self) -> None:
        self.setup_logging()

        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        self.config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["SnusbaseConnector", "opencti_url"], self.config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["SnusbaseConnector", "opencti_token"], self.config
        )
        self.snusbase_api_key = get_config_variable(
            "SNUSBASE_API_KEY", ["SnusbaseConnector", "snusbase_api_key"], self.config
        )
        self.interval = get_config_variable(
            "CONNECTOR_INTERVAL", ["SnusbaseConnector", "connector_interval"], self.config
        )

        # self.load_config()
        self.initialize_opencti()
        self.initialize_requests_session()
        self.initialize_db() # Set up our SQLite database

        # Caching to avoid reprocessing the same hash repeatedly
        self.dehash_cache: Dict[str, Any] = {}

        # Snusbase configuration
        self.snusbase_url: str = "https://api.snusbase.com/data/search"
        self.snusbase_url_dehash: str = "https://api.snusbase.com/tools/hash-lookup"

        self.identity = self.opencti.identity.create(
            type="Organization",
            name="Snusbase",
            description="Snusbase makes it easy to stay on top of the latest database breaches and makes sure you and your closest stay safe online.",
        )

    def setup_logging(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yml')
        try:
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
                self.validate_config()
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found at {config_path}")
            raise
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing configuration file: {e}")
            raise

    def validate_config(self) -> None:
        required_keys = ['snusbase', 'opencti', 'connector']
        for key in required_keys:
            if key not in self.config:
                self.logger.error(f"Missing required configuration key: {key}")
                raise ValueError(f"Missing required configuration key: {key}")

    def initialize_opencti(self) -> None:
        try:
            self.opencti = OpenCTIApiClient(
                url=self.opencti_url,
                token=self.opencti_token,
                ssl_verify=False
            )
        except Exception as e:
            self.logger.error(f"Error initializing OpenCTI client: {e}")
            raise

    def initialize_requests_session(self) -> None:
        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def initialize_db(self) -> None:
        """
        Initialize an SQLite database (leaks.db) which stores the leak_count per observable.
        """
        db_path = os.path.join(os.path.dirname(__file__), "leaks.db")
        try:
            self.db_conn = sqlite3.connect(db_path)
            self.db_cursor = self.db_conn.cursor()

            # Create the table if it doesn't already exist.
            self.db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS leak_counts (
                    observable_value TEXT PRIMARY KEY,
                    leak_count INTEGER,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.db_conn.commit()
            self.logger.info("Database initialized.")
        except sqlite3.Error as e:
            self.logger.error(f"Error initializing database: {e}")
            raise

    def dehash(self, hashes: dict) -> Any:
        self.logger.info("Retrieving password from hash...")
        payload = json.dumps({
            "terms": hashes,
            "types": ["hash"]
        })
        headers = {
            'Content-Type': 'application/json',
            'Auth': self.snusbase_api_key
        }

        try:
            response = self.session.post(
                self.snusbase_url_dehash,
                headers=headers,
                data=payload,
                timeout=10
            )

            response.raise_for_status()
            result = response.json()

            return result
        except requests.RequestException as e:
            self.logger.exception("Exception occurred during dehash API call:")
            return hashes

    def retrieve_password_from_hash(self, data: Union[Dict, List, Any]) -> Union[Dict, List, Any]:
        """
        Recursively search for keys named 'hash' in the provided JSON data and collect
        all hash values found.
        
        :param data: A dictionary, list, or any other type containing JSON data.
        :return: A list of hash values (strings).
        """
        hashes = []

        if isinstance(data, dict):
            for key, value in data.items():
                if key == "hash" and isinstance(value, str):
                    hashes.append(value)
                else:
                    hashes.extend(self.retrieve_password_from_hash(value))
        elif isinstance(data, list):
            for item in data:
                hashes.extend(self.retrieve_password_from_hash(item))

        return hashes

    def combine_json_objects(self, data: Dict, decoded_hashes: Dict) -> Dict:
        """
        Recursively search for any dictionary within `data` that contains a "hash" key.
        If a matching hash is found in the decoded_hashes, add a new key "decoded" to
        the dictionary containing the decoded information.
        
        :param data: The original JSON data (as a dict).
        :param decoded_hashes: The decoded hash data from dehash() (dict).
        :return: The modified data with merged decoded hash information.
        """
        # Create a mapping for quick lookup of decoded hashes
        mapping = {}
        for source, results in decoded_hashes.get("results", {}).items():
            for item in results:
                if "hash" in item and "password" in item:
                    mapping[item["hash"]] = item["password"]
        
        def recursive_combine(obj):
            if isinstance(obj, dict):
                if "hash" in obj and obj["hash"] in mapping:
                    obj["decoded_password"] = mapping[obj["hash"]]
                for key, value in obj.items():
                    obj[key] = recursive_combine(value)
            elif isinstance(obj, list):
                return [recursive_combine(item) for item in obj]
            return obj
        
        return recursive_combine(data)

    def fetch_leaks(self, term: str) -> Any:
        """
        Query Snusbase for leaks based on a term (e.g. domain or email)
        and return the results, with decoded hash information merged in.
        """
        self.logger.info(f"Fetching leaks for {term}...")
        payload = json.dumps({
            "terms": [term],
            "types": [
                "username", "email", "lastip", "hash", "password", "name", "_domain"
            ],
            "wildcard": True
        })
        headers = {
            'Content-Type': 'application/json',
            'Auth': self.snusbase_api_key
        }
        try:
            response = self.session.post(
                self.snusbase_url,
                headers=headers,
                data=payload,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            # Retrieve all hash (string) values from the incoming data.
            hashes = self.retrieve_password_from_hash(data)
            # Get decoded hash details from Snusbase.
            decoded_hashes = self.dehash(hashes)
            
            # Merge the decoded hash info into the original data.
            combined_data = self.combine_json_objects(data, decoded_hashes)

            return combined_data
        
        except requests.RequestException as e:
            self.logger.exception("Exception during leak fetching API call:")
            return None

    def update_database(self, observable_value: str, new_count: int) -> bool:
        """
        Check the database to see if a record exists for the observable.
        If it exists, compare and update the leak_count if needed.
        Print an alert if there is any change in size.
        """
        try:
            self.db_cursor.execute("SELECT leak_count FROM leak_counts WHERE observable_value=?", (observable_value,))
            row = self.db_cursor.fetchone()
            if row is None:
                # No previous data – insert a new record.
                self.db_cursor.execute(
                    "INSERT INTO leak_counts (observable_value, leak_count) VALUES (?, ?)",
                    (observable_value, new_count)
                )
                self.db_conn.commit()
                self.logger.info(f"Inserted new record for {observable_value} with leak count = {new_count}.")

                return True
            else:
                old_count = row[0]
                if new_count != old_count:
                    self.db_cursor.execute(
                        "UPDATE leak_counts SET leak_count = ?, last_updated = CURRENT_TIMESTAMP WHERE observable_value=?",
                        (new_count, observable_value)
                    )
                    self.db_conn.commit()
                    self.logger.info(f"Updated record for {observable_value} from {old_count} to {new_count}.")

                    return True
                else:
                    self.logger.info(f"No change in leak count for {observable_value} (remains {old_count}).")

                    return False
        except sqlite3.Error as e:
            self.logger.error(f"Error updating database: {e}")

            return False

    def save_to_file(self, data: Dict, name: str) -> Any:
        filename = f"{name}.md"

        md_content = f"# Leaked Data for {name}\n\n"
        md_content += "```json\n"
        md_content += json.dumps(data, indent=4)
        md_content += "\n```"

        try:
            with open(f"./{filename}", 'w', encoding='utf-8') as md_file:
                md_file.write(md_content)
            self.logger.info(f"Markdown file created successfully at {filename}")
        except Exception as e:
            self.logger.error(f"An error occurred while creating the Markdown file: {e}")

        return filename

    def process_observables(self) -> None:
        """
        Retrieve observables from OpenCTI and for each observable, query Snusbase for leaks.
        Also, compare the number of leaks with a stored value in the database.
        """
        observable_filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "objectLabel",
                    "values": ["946062f4-2d60-44c7-8a45-67a34f1cd4a8"],
                    "operator": "eq",
                    "mode": "or"
                }
            ],
            "filterGroups": []
        }
        try:
            observables = self.opencti.stix_cyber_observable.list(filters=observable_filters)
            if not observables:
                self.logger.info("No observables found for the given filters.")
                return

            for observable in observables:
                observable_value = observable.get("observable_value")
                if observable_value:
                    leaks = self.fetch_leaks(observable_value)
                    
                    # Determine leak_count from the fetched data.
                    if leaks:
                        if isinstance(leaks, list):
                            leak_count = len(leaks)
                        elif isinstance(leaks, dict):
                            leak_count = leaks.get("size", 0)
                        else:
                            leak_count = 0

                        if leak_count > 0:
                            hasChanged = self.update_database(observable_value, leak_count)
                            if hasChanged:
                                filename = self.save_to_file(leaks, observable_value)
                                self.create_incident(observable_value, filename)
                            
                            self.logger.info("-" * 40)
                    else:
                        self.logger.warning(f"No leaks found for {observable_value}.")
                else:
                    self.logger.warning("Observable does not have 'observable_value'.")
        except Exception as e:
            self.logger.exception("Error processing observables from OpenCTI:")

    def create_incident(self, name: str, filename: str) -> Any:
        """Create an incident in OpenCTI when leaks are detected."""
        try:
            incident = self.opencti.incident.create(
                name=f"Leaked data detected for {name}",
                description=f"Leaked data found on Snusbase:\n{name}",
                objectLabel="snusbase",
                objective="Credential Leaks",
                confidence=75,
                severity="High",
                incident_type="data-leak",
                objectMarking=TLP_RED["id"],
                created_by_ref=self.identity["standard_id"]
            )

            file = self.opencti.stix_domain_object.add_file(
                id=incident["id"],
                file_name=f"./{filename}",
                file_markings=[TLP_RED["id"]]
            )

            file_path = f"./{filename}"
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    self.logger.info(f"File '{file_path}' removed successfully.")
                except Exception as e:
                    self.logger.error(f"Error removing file '{file_path}': {e}")
            else:
                self.logger.warning(f"File '{file_path}' does not exist.")
        except Exception as e:
            self.logger.error(f"Error creating incident in OpenCTI: {e}")

    def run(self) -> None:
        try:
            self.process_observables()

        except Exception as e:
            self.logger.exception("Error running SnusbaseConnector:")


    def timer(self) -> None:
        try:
            # Schedule the run method to run every x hours
            schedule.every(int(self.interval)).hours.do(self.run)

            while True:
                schedule.run_pending()
                time.sleep(1)

        except Exception as e:
            self.logger.exception("Error running SnusbaseConnector:")

    def __del__(self):
        if hasattr(self, 'db_conn'):
            self.db_conn.close()
            self.logger.info("Database connection closed.")

if __name__ == "__main__":
    connector = SnusbaseConnector()
    connector.timer()
    # connector.run()