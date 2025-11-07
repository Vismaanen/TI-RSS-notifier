"""
Configure available settings depending on a customization of currently available features or as an effect
of further script development.
"""


# ----------------------------------------------------------------------------------------------------------------------
# SMTP report mailing server settings
# ----------------------------------------------------------------------------------------------------------------------
SMTP_SERVER = "192.168.0.1"
SMTP_PORT = 25
SENT_FROM = "sender@domain.com"
REPORT_TO = 'mail_to@domain.com'
REPORT_CC = 'mail_cc_1@domain.com, mail_cc_2@domain.com'
REPORT_DEBUG_TO = 'mail_debug_to@domain.com'
REPORT_DEBUG_CC = 'mail_debug_cc@domain.com'


# ----------------------------------------------------------------------------------------------------------------------
# Custom e-mail signature string placeholder
# ----------------------------------------------------------------------------------------------------------------------
SIGNATURE = f'<p>---</p><p>' \
            f'<span style="color: #808080; font-family: \'Segoe UI\', Tahoma, Geneva, Verdana, sans-serif; ' \
            f'font-size: 12;"><br />This is an automated message, do not reply.<br />' \
            f'In case of any inquiry please contact:<br />' \
            f'> <a href="mailto:recipient@domain.com">recipient@domain.com</a></span></p>'


# ----------------------------------------------------------------------------------------------------------------------
# RSS content headers string, configure to mimic real web browser. If a source is hidden behind a CloudFlare: script
# will provide only article headers instead of iterating all articles for a full text.
# ----------------------------------------------------------------------------------------------------------------------
RSS_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/127.0.0.1 Safari/537.36"
    ),
    "Accept": "application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ----------------------------------------------------------------------------------------------------------------------
# RSS feeds and keywords customization
# ----------------------------------------------------------------------------------------------------------------------
FEEDS = {
    'Dark Reading': 'https://www.darkreading.com/rss.xml',
    'Security Week': 'https://www.securityweek.com/feed/',
    'The Hacker News': 'https://hnrss.org/newest',
    'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
    'Infosecurity Magazine': 'https://www.infosecurity-magazine.com/rss/news/'}
URL_EXCLUSIONS = ['https://www.youtube.com/']
CUSTOMERS = [
    'customer 1', 'customer 2'
]
LOOKUP = [
    "0-day", "0day", "zero-day", "zero day", "unpatched", "privilege escalation", "remote code execution",
    "rce", "vulnerability", "exploit", "proof-of-concept", "PoC", "remote exploit", "critical vulnerability",
    "critical flaw", "CVE-"]


# ----------------------------------------------------------------------------------------------------------------------
# Article content lookup regex settings, used to pinpoint article fragments containing monitored keywords.
# ----------------------------------------------------------------------------------------------------------------------
RE_CVE = r"\bCVE-\d{4}-\d{4,7}\b"
RE_SENTENCES = r"(?<=[.!?])\s+"
REPORT_CVES_SEVERITY = ['MEDIUM', 'HIGH', 'CRITICAL']


# ----------------------------------------------------------------------------------------------------------------------
# Misc settings: including SQL data volume limits and message score (to be implemented on demand)
# ----------------------------------------------------------------------------------------------------------------------
SCORE_LIMIT = 70
REPORT_CVES_DAYS = 7
REPORT_PRIO_DAYS = 30
DB_NAME = 'YOUR DATABASE NAME'
LOGS_DIR = 'C:\\Temp\\TI_RSS\\Logs'
