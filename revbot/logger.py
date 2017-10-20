import logging

class Logger:
    def __init__(self, log_level, log_file):
        self.logger = logging.getLogger()
        self.logger.setLevel(log_level)

        fh = logging.FileHandler(log_file)
        fh.setLevel(log_level)

        ch = logging.StreamHandler()
        ch.setLevel(log_level)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def info(self, txt):
        self.logger.info(txt)
    def warning(self, txt):
        self.logger.warning(txt)
    def debug(self, txt):
        self.logger.debug(txt)
    def error(self, txt):
        self.logger.error(txt)
    def critical(self, txt):
        self.logger.critical(txt)