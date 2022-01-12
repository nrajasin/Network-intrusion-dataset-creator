import logging
import logging.config
import yaml

# TODO add error handling or debug output
def load_logging():
    with open("logging_config.yaml", "r") as f:
        config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
