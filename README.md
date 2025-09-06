# 📧 Email Cleaner Bot

An automated IMAP email cleaner 🧹 built for sneaker/resell/botting setups where inboxes often get flooded with OTP codes, promo spam, or useless mails.  
It keeps your inbox clean by **flagging and deleting unwanted emails** — while respecting whitelisted senders/keywords.

## ✨ Features

- 📨 **Multi-mailbox support** (manage multiple inboxes at once).  
- 🧹 **Keyword cleaning**: delete emails containing certain words.  
- 🛡️ **Whitelist protection**: never delete important mails.  
- 🔄 **Continuous scanning** at a configurable interval.  
- ⏳ **Smart delay deletion** (wait X minutes before deletion).  
- 🔌 **Auto-reconnects** if the IMAP session drops.  
- 🗂️ **Caching**: avoids re-processing safe emails.  

## ⚙️ Installation

```bash
git clone https://github.com/Tentoxa/email-cleaner.git
cd email-cleaner
pip install -r requirements.txt
```

## 🔧 Configuration

Use a `.env` file or environment variables:

```env
MAILBOXES=["user1@example.com:password:imap.server.com:993","user2@example.com:password:imap.server.com:993"]
CLEANING_KEYWORDS=["otp","promo","advertisement","spam", "Einmalcode"]
WHITELIST_KEYWORDS=["order","invoice"]
SCAN_INTERVAL=60
DELETION_DELAY_MINUTES=20
```

- **MAILBOXES** → list of mailboxes in format: `email:password:imap_server:imap_port`.  
- **CLEANING_KEYWORDS** → any mail containing these words will be deleted.  
- **WHITELIST_KEYWORDS** → words that protect emails from deletion.  
- **SCAN_INTERVAL** → scan interval in seconds (default: `60`).  
- **DELETION_DELAY_MINUTES** → minimum delay before flagged mails are deleted.  

## ▶️ Usage

```bash
python main.py
```

Runs continuously until stopped (Ctrl+C / SIGTERM).  

## 📦 Dependencies

- `imaplib`, `email`, `threading`, `logging`, `dotenv`, `json`