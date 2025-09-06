import imaplib
import email
import logging
import os
from typing import Optional, Set
from datetime import datetime, timedelta
import time
from email.utils import parsedate_to_datetime
import threading
import signal
import sys

from dotenv import load_dotenv
import json
from custom_logger import setup_logger
from dataclasses import dataclass, field


@dataclass
class MailboxConfig:
    email: str
    password: str
    imap_server: str
    imap_port: int


@dataclass
class EmailCache:
    """Cache to track processed emails"""
    processed_ids: Set[bytes] = field(default_factory=set)  # IDs that are >20min old and won't be deleted
    pending_deletion: dict = field(default_factory=dict)  # {email_id: scheduled_deletion_time}


load_dotenv()
logger = setup_logger(
    "email_cleaner",
    level=logging.DEBUG,
)

try:
    CLEANING_KEYWORDS = json.loads(os.environ["CLEANING_KEYWORDS"])
    WHITELIST_KEYWORDS = json.loads(os.environ["WHITELIST_KEYWORDS"])
    logger.info("Cleaning Keywords: " + ", ".join([kw for kw in CLEANING_KEYWORDS if kw]))
    logger.info("Whitelist Keywords: " + ", ".join([kw for kw in WHITELIST_KEYWORDS if kw]))
except Exception as e:
    logger.error(f"Error loading keywords from environment variables: {e}")
    os._exit(1)

# Global flag for graceful shutdown
shutdown_event = threading.Event()


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Shutdown signal received. Stopping all threads...")
    shutdown_event.set()


def get_mailboxes() -> list:
    def parse_mailbox(mailbox_string) -> Optional[MailboxConfig]:
        split_mailbox = mailbox_string.split(":")
        if len(split_mailbox) < 3:
            logger.error(f"Invalid mailbox format: {mailbox_string}")
            logger.error("Expected format: email:password:imap_server:imap_port (imap_port is optional)")
            return None
        email_addr = split_mailbox[0]
        password = split_mailbox[1]
        imap_server = split_mailbox[2]
        imap_port = int(split_mailbox[3]) if len(split_mailbox) > 3 else 993
        return MailboxConfig(email=email_addr, password=password, imap_server=imap_server, imap_port=imap_port)

    mailboxes_string = os.environ.get("MAILBOXES")
    if not mailboxes_string:
        logger.error("No MAILBOXES environment variable")
        return []
    try:
        mailboxes = json.loads(mailboxes_string)
        if not isinstance(mailboxes, list):
            logger.error("MAILBOXES environment variable is not a list")
            return []
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing MAILBOXES environment variable: {e}")
        return []

    mailboxes = [parse_mailbox(mb) for mb in mailboxes if parse_mailbox(mb) is not None]
    return mailboxes


class Mailbox():
    def __init__(self, mailbox_config: MailboxConfig):
        self.SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 60))  # Scan every 60 seconds by default
        self.DELETION_DELAY_MINUTES = int(os.environ.get("DELETION_DELAY_MINUTES", 20))  # 20 minutes delay
        self.config = mailbox_config
        self.connection = None
        self.cache = EmailCache()
        self.lock = threading.Lock()  # Thread lock for connection operations

        if not self._setup_session():
            raise Exception(f"Failed to set up session for {self.config.email}")

        self.initial_cleanup()

    @staticmethod
    def _should_delete_email(subject: str, from_: str, body: str) -> bool:
        subject_lower = subject.lower()
        from_lower = from_.lower()
        body_lower = body.lower()

        # Check whitelist first - if whitelisted, don't delete
        for keyword in WHITELIST_KEYWORDS:
            if not keyword:
                continue
            if keyword.lower() in subject_lower or keyword.lower() in from_lower or keyword.lower() in body_lower:
                return False

        # Check if email matches deletion keywords
        for keyword in CLEANING_KEYWORDS:
            if not keyword:
                continue

            keyword_lower = keyword.lower()

            if keyword_lower in subject_lower or keyword_lower in from_lower or keyword_lower in body_lower:
                return True

        return False

    def _get_email_body(self, msg) -> str:
        """Extract email body from message"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(msg.get_payload())
        return body

    def _get_email_date(self, msg) -> Optional[datetime]:
        """Extract and parse email date"""
        date_str = msg.get("Date")
        if date_str:
            try:
                return parsedate_to_datetime(date_str)
            except:
                logger.warning(f"Could not parse date: {date_str}")
                return None
        return None

    def initial_cleanup(self):
        """Initial cleanup - process all existing emails"""
        logger.info(f"Starting initial cleanup for {self.config.email}")
        current_time = datetime.now(tz=None)
        deletion_threshold = current_time - timedelta(minutes=self.DELETION_DELAY_MINUTES)

        with self.lock:
            # Fetch all emails
            status, messages = self.connection.search(None, "ALL")
            if status != "OK":
                logger.error(f"Failed to fetch emails for {self.config.email}")
                return

            email_ids = messages[0].split()
            logger.info(f"Found {len(email_ids)} emails in {self.config.email}")
            logger.info("Processing emails... this may take a while depending on the number of emails.")

            deleted_count = 0
            flagged_count = 0
            cached_count = 0

            for email_id in reversed(email_ids):
                try:
                    status, msg_data = self.connection.fetch(email_id, "(BODY.PEEK[])")
                    if status != "OK":
                        logger.error(f"Failed to fetch email ID {email_id} for {self.config.email}")
                        continue

                    msg = email.message_from_bytes(msg_data[0][1])
                    subject = msg.get("subject", "")
                    from_ = msg.get("from", "")
                    body = self._get_email_body(msg)
                    email_date = self._get_email_date(msg)

                    if not email_date:
                        # If we can't determine the date, skip this email
                        logger.warning(f"Skipping email ID {int(email_id)} - no date found")
                        continue

                    # Make email_date timezone-naive for comparison
                    if email_date.tzinfo is not None:
                        email_date = email_date.replace(tzinfo=None)

                    if self._should_delete_email(subject, from_, body):
                        if email_date < deletion_threshold:
                            # Email is older than 20 minutes and matches keywords - delete immediately
                            self.connection.store(email_id, "+FLAGS", "\\Deleted")
                            logger.info(
                                f"Deleted email ID {int(email_id)} with subject '{subject}' from '{from_}' (received at {email_date})")
                            deleted_count += 1
                        else:
                            # Email matches keywords but is too recent - schedule for deletion
                            deletion_time = email_date + timedelta(minutes=self.DELETION_DELAY_MINUTES)
                            self.cache.pending_deletion[email_id] = deletion_time
                            logger.info(
                                f"Flagged email ID {int(email_id)} for deletion at {deletion_time} - subject: '{subject}'")
                            flagged_count += 1
                    else:
                        # Email doesn't match deletion criteria
                        self.cache.processed_ids.add(email_id)
                        cached_count += 1

                except Exception as e:
                    logger.error(f"Error processing email ID {email_id}: {e}")
                    continue

            # Expunge deleted emails
            if deleted_count > 0:
                self.connection.expunge()

        logger.info(
            f"Initial cleanup completed for {self.config.email}: {deleted_count} deleted, {flagged_count} flagged, {cached_count} cached")

    def scan_and_clean(self):
        """Periodic scan to check for new emails and process pending deletions"""
        logger.info(f"Starting periodic scan for {self.config.email}")
        current_time = datetime.now(tz=None)
        deletion_threshold = current_time - timedelta(minutes=self.DELETION_DELAY_MINUTES)

        with self.lock:
            # First, get current email IDs to validate against
            status, messages = self.connection.search(None, "ALL")
            if status != "OK":
                logger.error(f"Failed to fetch emails for {self.config.email}")
                return

            current_email_ids = set(messages[0].split())

            # Process pending deletions with validation
            emails_to_delete = []
            invalid_ids = []

            for email_id, deletion_time in list(self.cache.pending_deletion.items()):
                if current_time >= deletion_time:
                    if email_id in current_email_ids:
                        emails_to_delete.append(email_id)
                    else:
                        # Email no longer exists, remove from pending
                        invalid_ids.append(email_id)
                        logger.warning(f"Email ID {int(email_id)} no longer exists, removing from pending deletion")

            # Clean up invalid IDs
            for email_id in invalid_ids:
                del self.cache.pending_deletion[email_id]

            # Delete valid emails
            if emails_to_delete:
                for email_id in emails_to_delete:
                    try:
                        self.connection.store(email_id, "+FLAGS", "\\Deleted")
                        logger.info(f"Deleted pending email ID {int(email_id)}")
                        del self.cache.pending_deletion[email_id]
                    except Exception as e:
                        logger.error(f"Error deleting pending email ID {email_id}: {e}")
                        # Remove from pending if it failed
                        if email_id in self.cache.pending_deletion:
                            del self.cache.pending_deletion[email_id]

                self.connection.expunge()

            # Now check for new emails
            status, messages = self.connection.search(None, "ALL")
            if status != "OK":
                logger.error(f"Failed to fetch emails for {self.config.email}")
                return

            email_ids = messages[0].split()
            new_emails_processed = 0

            for email_id in email_ids:
                # Skip if already processed or pending deletion
                if email_id in self.cache.processed_ids or email_id in self.cache.pending_deletion:
                    continue

                try:
                    status, msg_data = self.connection.fetch(email_id, "(BODY.PEEK[])")
                    if status != "OK":
                        continue

                    msg = email.message_from_bytes(msg_data[0][1])
                    subject = msg.get("subject", "")
                    from_ = msg.get("from", "")
                    body = self._get_email_body(msg)
                    email_date = self._get_email_date(msg)

                    if not email_date:
                        continue

                    # Make email_date timezone-naive for comparison
                    if email_date.tzinfo is not None:
                        email_date = email_date.replace(tzinfo=None)

                    new_emails_processed += 1

                    if self._should_delete_email(subject, from_, body):
                        if email_date < deletion_threshold:
                            # Old email that matches keywords - delete immediately
                            self.connection.store(email_id, "+FLAGS", "\\Deleted")
                            logger.info(f"Deleted new email ID {int(email_id)} with subject '{subject}'")
                            self.connection.expunge()
                        else:
                            # Recent email that matches keywords - schedule for deletion
                            deletion_time = email_date + timedelta(minutes=self.DELETION_DELAY_MINUTES)
                            self.cache.pending_deletion[email_id] = deletion_time
                            logger.info(f"Flagged new email ID {int(email_id)} for deletion at {deletion_time}")
                    else:
                        # Email doesn't match deletion criteria
                        self.cache.processed_ids.add(email_id)
                        logger.debug(f"Cached email ID {int(email_id)} - won't be deleted")

                except Exception as e:
                    logger.error(f"Error processing email ID {email_id}: {e}")
                    continue

            if new_emails_processed > 0:
                logger.info(f"Processed {new_emails_processed} new emails for {self.config.email}")

    def run_continuous_cleaning(self):
        """Run the cleaning process continuously"""
        logger.info(
            f"Starting continuous cleaning for {self.config.email} (scanning every {self.SCAN_INTERVAL} seconds)")

        while not shutdown_event.is_set():
            try:
                self.scan_and_clean()
                # Use wait instead of sleep to be responsive to shutdown
                if shutdown_event.wait(timeout=self.SCAN_INTERVAL):
                    break
            except Exception as e:
                logger.error(f"Error during scan for {self.config.email}: {e}")
                # Try to reconnect
                logger.info(f"Attempting to reconnect to {self.config.email}")
                if self._setup_session():
                    logger.info(f"Reconnected successfully to {self.config.email}")
                else:
                    logger.error(
                        f"Failed to reconnect to {self.config.email}. Retrying in {self.SCAN_INTERVAL} seconds")
                if shutdown_event.wait(timeout=self.SCAN_INTERVAL):
                    break

        logger.info(f"Stopping continuous cleaning for {self.config.email}")
        self._cleanup()

    def _setup_session(self) -> bool:
        try:
            with self.lock:
                if self.connection:
                    try:
                        self.connection.logout()
                    except Exception as e:
                        logger.error(f"Failed to logout from {self.config.email} properly: {e}")
                        pass

                self.connection = imaplib.IMAP4_SSL(self.config.imap_server, self.config.imap_port)
                self.connection.login(self.config.email, self.config.password)
                self.connection.select("INBOX")
                logger.info(f"Logged in to {self.config.email} successfully")
                return True
        except imaplib.IMAP4.error as e:
            logger.error(f"IMAP login failed for {self.config.email}: {e}")
            return False

    def _cleanup(self):
        """Clean up resources when shutting down"""
        try:
            with self.lock:
                if self.connection:
                    self.connection.logout()
                    logger.info(f"Logged out from {self.config.email}")
        except Exception as e:
            logger.error(f"Error during cleanup for {self.config.email}: {e}")


def mailbox_worker(mailbox_config: MailboxConfig):
    """Worker function for each mailbox thread"""
    try:
        logger.info(f"Starting worker thread for {mailbox_config.email}")
        mailbox = Mailbox(mailbox_config)
        mailbox.run_continuous_cleaning()
    except Exception as e:
        logger.error(f"Fatal error in worker thread for {mailbox_config.email}: {e}")


# Main execution
if __name__ == "__main__":
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    mailboxes = get_mailboxes()

    if not mailboxes:
        logger.error("No valid mailboxes configured")
        os._exit(1)

    logger.info(f"Starting email cleaner with {len(mailboxes)} mailbox(es)")

    # Create and start a thread for each mailbox
    threads = []
    for i, mailbox_config in enumerate(mailboxes):
        thread = threading.Thread(
            target=mailbox_worker,
            args=(mailbox_config,),
            name=f"Mailbox-{mailbox_config.email}",
            daemon=False
        )
        threads.append(thread)
        thread.start()
        logger.info(f"Started thread for mailbox: {mailbox_config.email}")

    # Wait for all threads to complete (they will run until shutdown signal)
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        logger.info("Main thread interrupted, waiting for worker threads to finish...")
        shutdown_event.set()
        for thread in threads:
            thread.join(timeout=5)

    logger.info("All threads have stopped. Email cleaner shutting down.")