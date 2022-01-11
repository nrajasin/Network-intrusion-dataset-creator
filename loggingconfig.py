import logging
import logging.config
import yaml


def load_logging():
    with open("logging_config.yaml", "r") as f:
        config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    logger = logging.getLogger(__name__)
    logger.debug("handlers: %s", logger.handlers)
    if len(logger.handlers) == 0:
        logger.warn("no handlers found for this logger")
