import os

import logging
from logging.handlers import TimedRotatingFileHandler


class LoggerService:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)

    def _configure_success_logger(self, logger_name, log_level=logging.INFO):
        # Create logger
        logger = logging.getLogger(logger_name)
        logger.setLevel(log_level)

        # Handler for success logs
        success_handler = TimedRotatingFileHandler(
            filename=os.path.join(self.log_dir, 'success.log'),
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        success_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(success_handler)

        return logger

    def _configure_error_logger(self, logger_name, log_level=logging.ERROR):
        # Create logger
        logger = logging.getLogger(logger_name)
        logger.setLevel(log_level)

        # Handler for error logs
        error_handler = TimedRotatingFileHandler(
            filename=os.path.join(self.log_dir, 'error.log'),
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        error_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(error_handler)

        return logger

    def configure_loggers(self, success_logger_name, error_logger_name):
        success_logger = self._configure_success_logger(success_logger_name)
        error_logger = self._configure_error_logger(error_logger_name)
        return success_logger, error_logger