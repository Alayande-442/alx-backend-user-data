#!/usr/bin/env python3
"""
Personal Data Filtering Module
"""

import os
import re
import logging
from typing import List
import mysql.connector


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Obfuscates specified fields in a log message.
    """
    pattern = f"({separator.join([f'{field}=[^;]*' for field in fields])})"
    return re.sub(pattern, lambda x: f"{x.group(0).split('=')[0]}={redaction}", message)


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class for obfuscating sensitive information.
    """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Filters sensitive information in the log record message.
        """
        original_message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, original_message, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger for sensitive information.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Connects to a MySQL database using environment variables.
    """
    return mysql.connector.connect(
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        database=os.getenv("PERSONAL_DATA_DB_NAME"),
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    )


def main() -> None:
    """
    Main function to read and filter data from the database.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()

    for row in cursor:
        record = "; ".join(f"{PII_FIELDS[i]}={row[i]}" for i in range(len(PII_FIELDS)))
        logger.info(record)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()

