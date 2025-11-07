"""
Description:    Threat Intelligence RSS reporting solution. Working on popular IT security TI source feeds, it scans
                for new articles, uploading to local database only those which mach configured interests. Details:

                - scanning article contents for specific keywords or customer names,
                - extracting contexts: parts of article that contain found keywords or customer names,
                - obtaining CVE IDs from text, requesting CVSSv3 and severity from NIST, uploading to a local database,
                - creating three kind of reports: for CVE details and for matched priority keywords / customers

Dependencies:   Script requires preparation before running:

                - NIST API key
                - external libraries to be imported, see command below:
                - pip install beautifulsoup4 feedparser rapidfuzz readability-lxml pyodbc requests
                - MSSQL database with tables: data_ti_articles and data_ti_cves, structure attached in a document

Major updates:

                - 17.10.2025: core articles scanner finalized, code documentation and cleanup
                - 23.10.2025: added reports functionality, code cleanup and documentation
                - 24.10.2025: logging and exception tracking polishing
"""

# default imports
import re
import sys
import time
import socket
import certifi
import smtplib
import logging
import argparse
import config as c
import pandas as pd
from typing import Any
from dateutil import tz
from itertools import groupby
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from email.mime.multipart import MIMEMultipart

# non-default library imports
import pyodbc
import requests
import feedparser
from pathlib import Path
from rapidfuzz import fuzz
from bs4 import BeautifulSoup
from readability import Document


class MyUtils:
    """
    Utility methods for general script use.
    """

    def __init__(self):
        """
        Initialize class instance
        """
        self.set_directories()

    # region SQL connectivity ------------------------------------------------------------------------------------------
    @staticmethod
    def db_connect(log: logging.Logger) -> tuple[bool, pyodbc.Connection] | tuple[bool, str]:
        """
        Create db_conn object for a given app.

        :param log: log.object
        :type log: logging.Logger
        :return: db connection bool state and object / description if failed
        :rtype: tuple(bool, pyodbc.Connection) or tuple[bool, str]
        :raise Exception: ``exc`` general database connection error
        """
        # default connection string setting
        # based on a current machine hostname
        _server = socket.gethostname()
        _driver_string = "Driver={SQL Server};"
        _conn_string = f"{_driver_string};Server={_server}\\SQLEXPRESS;Database={c.DB_NAME};Trusted_Connection=yes;"
        # attempt establishing a connection
        try:
            return True, pyodbc.connect(_conn_string)
        # anticipate any possible exception
        except Exception as exc:
            log.warning(f'> exception with SQL connection: {str(exc)}')
            return False, str(exc)

    @staticmethod
    def upload_data(db_conn: pyodbc.Connection, query: str, log: logging.Logger) -> bool:
        """
        Default function to upload data to db based on a simple query.

        :param db_conn: database connection object
        :param str query: query string
        :param log: log object
        :type db_conn: pyodbc.Connection
        :type log: logging.Logger
        :return: True or False depending on a query execution state
        :rtype: bool
        :raise Exception: ``e`` query execution error, returning False
        """
        try:
            cursor = db_conn.cursor()
            cursor.execute(query)
            db_conn.commit()
            cursor.close()
            log.info(f'  > SQL query OK')
            return True
        except Exception as exc:
            log.warning(f'  > SQL query ERROR: {str(exc)}')
            time.sleep(5)
            return False

    @staticmethod
    def get_data(db_conn: pyodbc.Connection, query: str, log: logging.Logger) -> list[Any] | None:
        """
        Default function to obtain raw data from db based on a provided query.

        :param db_conn: database connection object
        :param str query: query string
        :param log: log object
        :type db_conn: pyodbc.Connection
        :type log: logging.Logger
        :return: list of records - result of query, optional
        :rtype: list[Any] or None
        :raise Exception: ``exc`` query execution error, returning None
        """
        result_list = []
        try:
            cursor = db_conn.cursor()
            cursor.execute(query)
            for record in cursor.fetchall():
                result_list.append(list(record))
            log.info(f'  > SQL query OK, [{len(result_list)}] records')
            return result_list
        except Exception as exc:
            log.warning(f'  > SQL query ERROR: {str(exc)}')
            time.sleep(15)
            return None
    # endregion

    # region files and directories -------------------------------------------------------------------------------------
    @staticmethod
    def create_log(app_name: str) -> logging.Logger:
        """
        Create and return app log file object.

        :param str app_name: application name string
        :return: log object
        :rtype: logging.Logger
        """
        # log parameters
        log_name = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{app_name}.log"

        try:
            # adjust target logs directory as needed - by default: subdirectory in a script location
            log_directory = Path(f"C:\\ECS\\Logs\\{app_name}")
            log_directory.mkdir(parents=True, exist_ok=True)
            log_path = log_directory / log_name
            # create logger
            logger = logging.getLogger(log_name)
            logger.setLevel(logging.INFO)
            # file handler setting
            if not logger.handlers:
                file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                logger.addHandler(file_handler)
                # console output handler setting
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                logger.addHandler(console_handler)
            return logger
        except Exception as exc:
            print(f"Cannot create local log object: {str(exc)}; script will now exit.")
            exit()

    @staticmethod
    def set_directories() -> bool:
        """
        Create logs directory to store logs for analysis.

        :return: directories configuration state: True or False
        :rtype: bool
        :raise Exception: ``exc`` general error: check permissions and directory path / status manually
        """
        try:
            path = Path(f"{c.LOGS_DIR}\\TI scanner")
            path.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as exc:
            print(f'Exception while setting up script directories. Verify script permissions. {str(exc)}')
            return False
    # endregion

    @staticmethod
    def send_simple_mail(html_body: str, subject: str, log: logging.Logger) -> None:
        """
        Attempt to send an email message, containing provided html body and attachments dictionary, via SMTP relay.
        Upload processed message details into ``log_sent_messages`` table with potential exception details.

        :param str html_body: message html body string (without a greeting or signature)
        :param str subject: message subject
        :param log: log object
        :type log: logging.Logger
        :raise Exception: ``exc`` general message processing exception
        """
        try:
            server = smtplib.SMTP(c.SMTP_SERVER, c.SMTP_PORT)
            message_object = MIMEMultipart()
            # attach email body
            message_body = f'Hello, <br /><br />{html_body}{c.SIGNATURE}'
            message_object.attach(MIMEText(message_body, "html", "utf-8"))
            # attach signature
            signature_image = MIMEImage(open('C:\\ECS\\Resources\\signature.png', 'rb').read())
            signature_image.add_header('Content-ID', '<signature>')
            message_object.attach(signature_image)
            # assign other properties
            message_object["From"] = c.SENT_FROM
            message_object["To"] = c.REPORT_TO
            message_object["Cc"] = c.REPORT_CC
            message_object["Subject"] = subject
            # send message, notify if failed
            server.send_message(message_object)
            log.info(f'> email sent')
        except Exception as exc:
            log.warning(f'> message sending ERROR: [{str(exc)}]')
        return


class MyReceiver:
    """
    Perform RSS articles retrieval from configured feeds
    """

    def __init__(self, log: logging.Logger, db_conn: pyodbc.Connection, utils: MyUtils):
        """
        Initialize class instance.
        """
        self.log = log
        self.db_conn = db_conn
        self.utils = utils
        self.feeds = c.FEEDS
        self.headers = c.RSS_HEADERS
        # initialize text content scanner class
        self.scanner = MyScanner(self.log, db_conn, utils)

    def perform_request(self, url: str) -> requests.models.Response or None:
        """
        Function to perform https requests.

        :param str url: feed / article URL address string
        :return: https:// response, optional
        :rtype: requests.models.Response() or None
        :raise requests.exceptions.SSLError: invalid certificate on a server side
        :raise requests.exceptions.ProxyError: proxy connection error
        :raise requests.exceptions.ReadTimeout: connection timeout
        :raise Exception: ``exc`` unspecified code exception
        """
        # exclusions check
        if any(excl in url for excl in c.URL_EXCLUSIONS):
            self.log.info('> skipping excluded video URL: ')
            return None
        # attempt to execute a request
        try:
            response = requests.get(url, headers=self.headers, timeout=25, verify=False)  # USE THIS INTERNALLY
            if response.status_code == 200:
                self.log.info(f'> ok: {url}')
                return response
            elif response.status_code in (301, 302):
                self.log.warning(f'> redirect! >> {response.headers.get('Location')}')
            elif response.status_code == 304:
                self.log.info('> no updates')
            elif response.status_code == 403:
                self.log.warning(f'> forbidden: {url}')
            elif response.status_code == 404:
                self.log.warning('> not found')
            elif response.status_code == 429:
                self.log.warning(f'> download rate limited, skipping')
            elif response.status_code >= 500:
                self.log.warning(f'> server-side error, skipping')
        except requests.exceptions.SSLError:
            self.log.critical(f'> SSL source certificate exception')
        except requests.exceptions.ProxyError:
            self.log.warning(f'> proxy warning: {url}')
        except requests.exceptions.ReadTimeout:
            self.log.warning(f'> timeout warning: {url}')
        except Exception as exc:
            self.log.critical(f'> general code exception, debug manually: {str(exc)}')
        return None

    def process_feeds(self) -> dict[str, any] or None:
        """
        Scan configured feeds for new articles. Cache those not already noted.
        Additionally, scan for a specific keywords related to threat type / severity and customer names.
        Provide notification if found.

        :return: feeds-separated article content and analysis results, optional
        :rtype: dict[str, any] or None
        """
        all_messages = {}
        # loop sources
        self.log.info('scanning feeds')
        for source, feed in self.feeds.items():
            feed_messages = {}
            self.log.info('-------------------')
            self.log.info(feed)
            # data check-in
            response = self.perform_request(feed)
            if not response:
                self.log.warning('> skipping feed - no valid response')
                continue
            # data volume lookup
            # check if article is in database
            # if not - scan for content and provide email feedback if necessary
            response_parsed = feedparser.parse(response.text)
            self.log.info('> looping obtained article entries')
            for entry in response_parsed.entries:
                self.log.info('-------------------')
                # obtain article details
                details = self.scanner.parse_article_details(entry)
                if details:
                    self.log.info(f'> title: {details["title"]}')
                    # check if already observed
                    if self.scanner.check_if_cached(source, details):
                        continue
                    else:
                        # perform source assessment to ensure minimum data provision
                        # some sources use CloudFlare which disables even Selenium
                        # in such case provide only article headers, without downloading a whole content
                        # for other sources - proceed with obtaining whole articles
                        if source in ['Dark Reading']:
                            article_text = 'Unavailable'
                        else:
                            # if there is a new article, not logged in database - obtain whole text
                            article = self.perform_request(details['link'])
                            if not article:
                                self.log.warning('> cannot receive article, skipping')
                                continue
                            # attempt text parsing
                            article_text = self.scanner.parse_article_text(article)
                        # analyze if eligible for alert
                        valid, findings, scores = self.scanner.analyze_text(details['title'],
                                                                            details['summary'],
                                                                            article_text)
                        # assessment for upload and alerting
                        if valid:
                            # add details to a report message dict
                            feed_messages[details['title']] = {'details': details,
                                                               'text': article_text,
                                                               'findings': findings,
                                                               'scores': scores}
                else:
                    self.log.warning('> cannot read article details: {str(entry)}')
                    continue
                # slow down a bit
                time.sleep(1)
            # append feed summary to general messages dict
            if feed_messages:
                all_messages[source] = feed_messages
        #  final content validation
        if all_messages:
            self.log.info(f'found {sum(len(articles) for articles in all_messages.values())} '
                          f'from {len(all_messages)} sources')
            return all_messages
        self.log.info('no messages matching content of interest published, exiting...')
        return None

    def upload_articles(self, articles: dict[str, any]) -> None:
        """
        Attempt uploading the newest articles to local database.

        :param articles: dictionary of recently obtained articles
        :type articles: dict[str, any]
        :raise Exception: ``exc`` general articles upload exception
        """
        try:
            in_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # loop sources collection
            for source in articles:
                for article in articles[source]:
                    article_content = articles[source][article]
                    # build SQL query for article
                    query = (f'INSERT INTO [Neo_DB].[dbo].[data_ti_articles] ([in_timestamp], [source], [url], [title],'
                             f' [summary], [article], [score_keywords], [score_customers], [cves], [found_keywords],'
                             f' [found_customers], [context_keywords], [context_customers]) '
                             f'VALUES ('
                             f"'{in_timestamp}', "
                             f"'{source}', "
                             f"'{article_content['details'].get('link')}', "
                             f"'{article_content['details'].get('title')}', "
                             f"'{article_content['details'].get('summary')}', "
                             f"'{article_content.get('text')[:4092]}', "
                             f"'{article_content['scores'].get('keywords')}', "
                             f"'{article_content['scores'].get('customers')}', "
                             f"'{article_content['findings'].get('cves')}', "
                             f"'{article_content['findings'].get('keywords')}', "
                             f"'{article_content['findings'].get('customers')}', "
                             f"'{article_content['findings'].get('keywords context')}', "
                             f"'{article_content['findings'].get('customers context')}'"
                             f')')
                    # perform upload
                    # send exception detail via email on error
                    self.utils.upload_data(self.db_conn, query, self.log)
        except Exception as exc:
            self.log.critical(f'cannot upload new articles: {str(exc)}')
            # x.errorize('TI scanner', 'app', exc, 'Cannot perform new articles upload', 2)


class MyScanner:
    """
    Data parsing and cleanup utilities class.
    """

    def __init__(self, log: logging.getLogger(), db_conn: pyodbc.Connection, utils: MyUtils):
        self.log = log
        self.db_conn = db_conn
        self.utils = utils

    def parse_article_details(self, entry: feedparser.FeedParserDict) -> dict[str, any] or None:
        """
        Attempt to parse article details from obtained content.

        :param entry: web resource article object
        :type entry: feedparser.FeedParserDict
        :return: article details dictionary, optional
        :rtype: dict[str, any] or None
        :raise Exception: ``exc`` unspecified code exception
        """
        results = {}
        try:
            # obtain details
            results['link'] = entry.get("link")
            results['title'] = entry.get("title", "").replace("'", "`")
            results['summary'] = (BeautifulSoup(entry.get("summary", "").replace("'", "`"), "html.parser")
                                  .get_text(" ", strip=True))
            results['published'] = self.parse_article_datetime(entry)
        except Exception as exc:
            self.log.warning(f'> cannot read article details: {str(exc)}')
            return None
        return results

    def parse_article_datetime(self, entry: feedparser.FeedParserDict) -> str:
        """
        Attempt to parse article publish timestamp into unified format with TZ UTC included.

        :param entry: web resource article object
        :type entry: feedparser.FeedParserDict
        :return: parsed timestamp string or 'No date' status
        :rtype: str
        :raise Exception: ``exc`` unspecified datetime parsing exception
        """
        try:
            # check default parsing method first
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                timestamp = datetime.fromtimestamp(time.mktime(entry.published_parsed))
            # fallback method
            else:
                published_raw = entry.get("published") or entry.get("updated")
                if not published_raw:
                    return 'No date'
                timestamp = dateparser.parse(published_raw)
            if not timestamp:
                return 'No date'
            timestamp = timestamp.astimezone(tz.UTC)
            self.log.info(f'> article datetime: {timestamp}')
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as exc:
            self.log.warning(f'> timestamp parsing exception: {str(exc)}')
            return 'No date'

    def parse_article_text(self, response: requests.models.Response) -> str:
        """
        Attempt to parse full article text. It will be scanned for keywords related to threats or customers later.

        :param response: https response string
        :type response: requests.models.Response
        :return: parsed article or empty string
        :rtype: str
        :raise Exception: ``exc`` text parsing general exception
        """
        # obtain raw text
        try:
            content_doc = Document(response.text)
            content_sum = content_doc.summary()
            content_soup = BeautifulSoup(content_sum, "html.parser")
            content_text = content_soup.get_text(separator="\n").strip()
            if len(content_text) < 200:
                # NOTE: 23.10.2025 added encoding enforcement to avoid wrongful decoding
                soup_full = BeautifulSoup(response.text, "html.parser", from_encoding="windows-1252")
                for soup in soup_full(["script", "style", "noscript"]):
                    soup.decompose()
                content_text = soup_full.get_text(separator="\n").strip()
            self.log.info('> article text parsed')
        except Exception as exc:
            self.log.warning(f'> article text parsing error: {str(exc)}')
            content_text = ""
        # additional cleanup if required
        # meta characters and unnecessary newlines
        content_text = content_text.replace('\xa0', '').replace("'", "`")
        content_text = re.sub(r'\n+', '\n', content_text).strip()
        self.log.info('> article text cleaned')
        return content_text

    def check_if_cached(self, source, details: dict[str, str]) -> bool:
        """
        Utility to search local database for a marching record to check, if article is new or has been already
        processed earlier.

        :param str source: RSS source title
        :param details: article details dictionary
        :type details: dict(str, str)
        :return: True or False
        :rtype: bool
        """
        # attempt to ask database if an article is already cached
        query = (f"SELECT * "
                 f"FROM [Neo_DB].[dbo].[data_ti_articles] "
                 f"WHERE [source] = '{source}'"
                 f"AND [url] = '{details["link"]}' "
                 f"AND [title] = '{details["title"]}' "
                 f"AND [summary] = '{details["summary"]}' ")
        response = self.utils.get_data(self.db_conn, query, self.log)
        if not response:
            self.log.info('> new article!')
            return False
        self.log.info('>  article cached, skipping...')
        return True

    def analyze_text(self, title: str, summary: str, content: str) -> (bool, dict, dict) or (bool, None, None):
        """
        Attempt to analyze provided text for specific indicators or customer names. Append not only match info but also
        context info - parts of text with matching phrases. Attempt to calculate accuracy score.

        :param str title: article title
        :param str summary: article summary text
        :param str content: article content text
        :return: results: bool state, details dict and scores dict or bool state, None, None
        :rtype: bool, dict[str, any], dict[str, any] or bool, None, None
        """
        article_details = {'keywords': [], 'customers': [], 'cves': []}
        article_scores = {'keywords': 0, 'customer name': 0}
        text = " ".join([title or "", summary or "", content or ""]).lower()
        # attempt to check each item individually
        text = text.lower()
        for scope, phrases in {'keywords': c.LOOKUP, 'customers': c.CUSTOMERS}.items():
            article_details[scope] = self.quick_phrase_search(text, phrases)
            article_details[f'{scope} context'] = self.phrase_context_search(text, article_details[scope])
            article_scores[scope] = self.calculate_article_score(text, phrases, article_details[scope], scope)
        # quick CVE search
        article_details['cves'] = self.quick_cve_search(text)
        # decision related to collected info
        if any(article_details.values()) or any(v > c.SCORE_LIMIT for v in article_scores.values()):
            self.log.info('> article content valid')
            return True, article_details, article_scores
        self.log.info('> skipping, article not matching interest')
        return False, None, None

    @staticmethod
    def quick_phrase_search(text: str, phrases: list[str]) -> str or None:
        """
        Search text for *whole-word* matches of given phrases, case-sensitive.

        :param text: article text string
        :param phrases: list of phrases to search for
        :return: comma-separated string of unique found phrases, or None if no match
        """
        seen = set()
        matches = []

        for phrase in phrases:
            pattern = r'\b' + re.escape(phrase) + r'\b'
            if re.search(pattern, text) and phrase not in seen:
                seen.add(phrase)
                matches.append(phrase)

        return ', '.join(matches) if matches else None

    @staticmethod
    def phrase_context_search(text: str, matches: str | None) -> list[str] | None:
        """
        Scan text for provided phrases and return properly formatted sentences containing them. Strip text parts of
        leading / trailing whitespaces, capitalize it, ends with a period (.).

        :param str text: searched article text
        :param str matches: matching phrases string - found in previous step
        :return:
        """
        # if no hits for any phrase - skip this action
        if not matches:
            return None
        # create a phrases watch list
        phrase_hits = [match.strip() for match in matches.split(',') if match.strip()]
        sentences = re.split(c.RE_SENTENCES, text)
        found_sentences = []
        # for each phrase get one matching sentence
        for phrase in phrase_hits:
            for sentence in sentences:
                if re.search(rf'\b{re.escape(phrase)}\b', sentence, re.IGNORECASE):
                    context = sentence.strip().replace('\n', ' ')
                    if context and not context[0].isupper():
                        context = context[0].upper() + context[1:]
                    if not re.search(r'[.!?]$', context):
                        context += '.'
                    found_sentences.append(context)
                    break
        # volume and duplicate check
        # added to ensure no duplicate findings
        if not found_sentences:
            return None
        else:
            unique_items = list(set(found_sentences))
            return " | ".join(unique_items) if unique_items else None

    def quick_cve_search(self, text: str) -> str | None:
        """
        Attempt to search given text for provided phrases presence.
        For each found CVE perform a quick NIST lookup.
        If CVE is not cached locally - upload obtained info to database.

        :param str text: article text string
        :return: matching CVE IDs string or a no match description
        :rtype: str
        """
        matches = ''
        cves = re.findall(c.RE_CVE, text, flags=re.IGNORECASE)
        if not cves:
            return None
        # if any CVE found - proceed
        for cve in cves:
            # perform quick check if CVE is  already recognized in db
            # if not - call API NIST for details
            # then perform upload
            self.process_local_cves(cves)
            if matches == '':
                matches = cve.upper()
            elif matches != '':
                matches = f'{matches}, {cve.upper()}'
            return matches

    def process_local_cves(self, cves: list[str]) -> None:
        """
        Perform local CVE database check-in for CVEs not yet inventoried. This will be used on a report when CVE
        score and severity will take role.

        :param cves: CVE matches list
        :type cves: list[str]
        """
        # attempt to split content
        in_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # attempt to ask NIST API for CVE details
        for match in cves:
            cve = match.upper()
            # call API
            details = self.get_cve_cvss_and_severity(cve)
            # parse details, check i CVE is present with exact scores
            # upload if not
            if details:
                cvss = details['cvss']
                severity = details['severity']
                # check if cvss is already cached with exact parameters
                query = (f"SELECT * FROM [Neo_DB].[dbo].[data_ti_cves] "
                         f"WHERE [CVE_ID] = '{cve}' AND [CVSS] = '{cvss}' AND [severity] = '{severity}'")
                present = self.utils.get_data(self.db_conn, query, self.log)
                if not present:
                    self.log.info(f'> {cve} upload: score {cvss}, severity {severity}')
                    query = (f"INSERT INTO [Neo_DB].[dbo].[data_ti_cves] "
                             f"([in_timestamp], [CVE_ID], [CVSS], [severity]) "
                             f"VALUES "
                             f"('{in_timestamp}', '{cve}', '{cvss}', '{severity}')")
                    state = self.utils.upload_data(self.db_conn, query, self.log)
                    if state:
                        self.log.info(f'> {cve} added')
                    else:
                        self.log.warning(f'> {cve} not added')
                    continue

    def get_cve_cvss_and_severity(self, cve_id: str) -> dict[str, any] | None:
        """
        Attempt to call NIST API for CVE details. Process response, return cvss and severity.

        :param str cve_id: CVE ID string
        :return: cve score details, optional
        :rtype: dict[str, any] or None
        :raise requests.exceptions.RequestException: ``exc`` generic requests exception
        :raise Exception: ``exd`` generic requests code exception for manual debug
        """
        # set URL
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.strip()}"
        # attempt a request
        try:
            response = requests.get(url, timeout=10)
            time.sleep(5)
            # response successful
            if response.status_code == 200:
                data = response.json()
                items = data.get("vulnerabilities", [])
                if not items:
                    return {"cvss": 'n/a', "severity": "n/a"}
                metrics = items[0].get("cve", {}).get("metrics", {})
                return self.get_cve_scores(metrics)
            else:
                self.log.warning(f'> CVE check request unsuccessful: {response.status_code}')
                return None
        except requests.exceptions.RequestException as exc:
            self.log.warning(f'> CVE request exception: {str(exc)}')
            return None
        except Exception as exd:
            self.log.warning(f'> CVE check generic code exception: {str(exd)}')
            return None

    @staticmethod
    def get_cve_scores(metrics) -> dict[str, any] | None:
        """
        Read CVE scores from obtained response data.

        :param metrics: response dictionary
        :type metrics: dict[str, any]
        :return: CVE cvss and severity scores dict, optional
        :rtype: dict[str, any] or None
        """
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                # get scores data for matching key
                cvss_data = metrics[key][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                # return details if found
                if score and severity:
                    return {"cvss": score, "severity": severity.upper()}
        return None

    def calculate_article_score(self, text: str, phrases: list[str], matches: str, subject: str) -> int:
        """
        Attempt to calculate keywords score for a given text for more context.

        :param str text: article text string
        :param phrases: keywords list
        :param str matches: keyword matches string
        :param str subject: score subject description: keywords or customer names
        :type phrases: list(str)
        :return: matching keywords string or a no match description
        :rtype: str
        """
        max_score = 0
        # proceed only if keyword matches found
        if not matches:
            return 0
        # attempt to calculate ratio
        try:
            for phrase in phrases:
                score = fuzz.partial_ratio(phrase, text)
                if score > max_score:
                    max_score = score
        except Exception as exc:
            self.log.warning(f'> cannot calculate score for article: {str(exc)}')
            return 0
        self.log.info(f'> score - {subject}: {max_score}')
        return max_score


class MyReporter:
    """
    SQL data upload handling and report building class.
    """

    def __init__(self, log: logging.Logger, db_conn: pyodbc.Connection, utils: MyUtils):
        """
        Initialize class instance

        :param log: log object
        :param db_conn: database connection object
        :type log: logging.Logger
        :type db_conn: pyodbc.Connection
        """
        self.log = log
        self.db_conn = db_conn
        self.utils = utils
        # initialize local HTML code utilities class
        self.html = MyHTML()

    def create_report(self, mode: str) -> None:
        """
        Attempt to prepare and deliver a report containing articles related too CVEs.

        :param str mode: script mode arg
        """
        # first - det up list of articles with CVE hits
        # it has to include CVE details, article details
        article_list = self.get_articles(mode)
        cve_list = self.get_cves_list()
        # format data for a report
        # sort per source, then publish date
        # create a dict structure for easier *.html report creation
        if article_list and cve_list:
            self.log.info('--------------------')
            self.log.info('CVEs and articles collected, formatting data')
            report_data = self.format_report(mode, article_list, cve_list)
            # attempt to build a report code
            report_code = self.build_report(report_data)
            # call email sending method
            if report_code:
                self.deliver_report(mode, report_code)
                # mark articles as delivered
                self.mark_as_delivered(article_list)

    def get_articles(self, mode: str) -> list[list[any]] | None:
        """
        Attempt to obtain CVE articles from database.

        :return: list of articles, optional
        :rtype: list[list[any]] or None
        """
        self.log.info(f'executing query to obtain CVE-related articles data')
        # set timestamp - last X days as configured
        if mode == 'cves':
            date_from = ((datetime.now() - timedelta(days=c.REPORT_CVES_DAYS))
                         .replace(hour=0, minute=0, second=0, microsecond=0)
                         .strftime('%Y-%m-%d %H:%M:%S'))
            query = (f"SELECT "
                     f"[source], "
                     f"[url], "
                     f"[title], "
                     f"[summary], "
                     f"[cves], "
                     f"[found_keywords], "
                     f"[found_customers], "
                     f"[context_keywords], "
                     f"[context_customers] "
                     f"FROM [Neo_DB].[dbo].[data_ti_articles] "
                     f"WHERE [in_timestamp] >= '{date_from}' "
                     f"AND [delivery_timestamp] IS NULL "
                     f"AND [cves] NOT LIKE 'None' "
                     f"ORDER BY [in_timestamp] desc")
        elif mode == 'prio':
            date_from = ((datetime.now() - timedelta(days=c.REPORT_PRIO_DAYS))
                         .replace(hour=0, minute=0, second=0, microsecond=0)
                         .strftime('%Y-%m-%d %H:%M:%S'))
            query = (f"SELECT "
                     f"[source], "
                     f"[url], "
                     f"[title], "
                     f"[summary], "
                     f"[cves], "
                     f"[found_keywords], "
                     f"[found_customers], "
                     f"[context_keywords], "
                     f"[context_customers] "
                     f"FROM [Neo_DB].[dbo].[data_ti_articles] "
                     f"WHERE [in_timestamp] >= '{date_from}' "
                     f"AND [delivery_timestamp] IS NULL "
                     f"AND [found_customers] NOT LIKE 'None' "
                     f"ORDER BY [in_timestamp] desc")
        else:
            date_from = ((datetime.now() - timedelta(days=c.REPORT_PRIO_DAYS))
                         .replace(hour=0, minute=0, second=0, microsecond=0)
                         .strftime('%Y-%m-%d %H:%M:%S'))
            query = (f"SELECT "
                     f"[source], "
                     f"[url], "
                     f"[title], "
                     f"[summary], "
                     f"[cves], "
                     f"[found_keywords], "
                     f"[found_customers], "
                     f"[context_keywords], "
                     f"[context_customers] "
                     f"FROM [Neo_DB].[dbo].[data_ti_articles] "
                     f"WHERE [in_timestamp] >= '{date_from}' "
                     f"AND [delivery_timestamp] IS NULL "
                     f"AND [found_customers] LIKE 'None' "
                     f"AND [cves] LIKE 'None' "
                     f"ORDER BY [in_timestamp] desc")
        # get data
        data = self.utils.get_data(self.db_conn, query, self.log)
        # validate data volume
        if data:
            self.log.info(f'article data obtained: [{len(data)}] item(s)')
            return data
        self.log.info(f'no article data obtained')
        return None

    def get_cves_list(self) -> list[list[any]] | None:
        """
        Attempt to obtain CVE articles from database.

        :return: list of articles, optional
        :rtype: list[list[any]] or None
        """
        self.log.info(f'executing query to obtain CVE details')
        # execute query as provided below
        query = "SELECT * FROM [Neo_DB].[dbo].[data_ti_cves]"
        data = self.utils.get_data(self.db_conn, query, self.log)
        # validate data volume
        if data:
            self.log.info(f'cve local data obtained, [{len(data)}] indicators')
            return data
        self.log.info('cve data not obtained, check database table content')
        return None

    def format_report(self, mode: str, article_list: list[Any], cve_list: list[Any]) -> dict[str, Any] | None:
        """
        Format obtained data into a structure easier for *.html report creation.

        :param str mode: script mode arg
        :param article_list: list of articles eligible for a report
        :param cve_list: list of CVE details
        :type article_list: list[Any]
        :type cve_list: list[Any]
        :return: dictionary of articles matching report scope, optional
        :rtype: dict[str, Any] or None
        :raise Exception: generic code exception
        """
        try:
            self.log.info('--------------------')
            self.log.info('formatting articles data')
            # group by source
            article_dict = {key: list(val) for key, val in groupby(sorted(article_list, key=lambda item: item[0]),
                                                                   key=lambda item: item[0])}
            # loop per  source
            results = {}
            for source, articles in article_dict.items():
                self.log.info(f'> {source}: [{len(articles)} articles]')
                source_filtered = []
                for article in articles:
                    self.log.info(f'  > {article[2]}')
                    # adjust report scope depending on a report mode
                    # for CVE report - cves are mandatory
                    # for customers report - cve info is optional
                    if mode == 'cves':
                        eligible = self.check_priority_cves(article, cve_list)
                    else:
                        eligible = None
                    # skip article if operating on cves mode and no cve info found
                    if mode == 'cves' and not eligible:
                        self.log.info(f'    > no eligible CVEs, skipping...')
                        continue
                    # create data structure
                    article_parsed = {
                        'title': article[2],
                        'link': article[1],
                        'summary': article[3],
                        'cves': eligible,
                        'keywords': article[5] if article[5] != 'None' else None,
                        'customers': article[6] if article[6] != 'None' else None,
                        'keywords_context': article[7] if article[7] != 'None' else None,
                        'customers_context': article[8] if article[8] != 'None' else None,
                    }
                    source_filtered.append(article_parsed)
                # append articles detail if any qualified
                if source_filtered:
                    results[source] = source_filtered
            # data volume validation
            if results:
                self.log.info(f'articles data sorted and filtered, [{len(results)}] sources included')
                return results
            self.log.info(f'no articles matching [{mode}] report scope, skipping...')
            return None
        except Exception as exc:
            self.log.warning(f'issue with articles sorting: {str(exc)}')
            return None

    def check_priority_cves(self, article: list[Any], cve_list: list[Any]) -> list[Any] | None:
        """
        Check article CVEs  against cached details, filter out unwanted ones based on a severity.

        :param article: article details list
        :param cve_list: cached CVEs details list
        :type article: list[Any]
        :type cve_list: list[Any]
        :return: list of matching CVEs, optional
        :rtype: list[Any] or None
        """
        try:
            # obtain list of cves mentioned within article
            cves = [cve.strip() for cve in article[4].split(",")]
            # match each cve with cached details
            pd_cves = pd.DataFrame(cve_list, columns=['index', 'timestamp', 'cve_id', 'cvss', 'severity'])
            details = pd_cves[
                (pd_cves['cve_id'].isin(cves)) &
                (pd_cves['severity'].isin(c.REPORT_CVES_SEVERITY))
                ][['cve_id', 'severity', 'cvss']]
            results = details.values.tolist()
            if results:
                self.log.info(f'    > filtered [{len(results)}] CVEs')
                return results
            self.log.info('    > no CVES matching criteria')
            return None
        except Exception as exc:
            self.log.warning(f'    > CVEs priority check exception: {str(exc)}')
            return None

    def build_report(self, report_data: dict[str, Any]) -> str | None:
        """
        Main method to combine report data into a *.html code. This will be attached to an email.

        :param report_data: report data dictionary containing per-source article details.
        :type report_data: dict[str, Any]
        :return: html code string, optional
        :rtype: str or None
        :raise Exception: ``exc`` generic code exception for manual debug
        """
        self.log.info('--------------------')
        self.log.info('building report code')
        try:
            # set overall table
            html_string = self.html.set_theader(1000)
            # per source - build separate table
            for source in report_data:
                html_string += self.html.set_theader(1000)
                # append a clear source name row
                html_string += f'<tr>{self.html.source_row_cell(source)}</tr>'
                # append a row for new table per-article
                html_string += f'<tr><td>'
                # per article table input
                for article in report_data[source]:
                    # create article table
                    html_string += self.html.set_theader(1000)
                    # append quick detail summary table
                    html_string += f'<tr>{self.html.article_title_row_cell(article["title"])}</tr>'
                    # append link record
                    html_string += f'<tr>{self.html.link_row_cell(article["link"])}</tr>'
                    # append details
                    html_string += f'<tr>{self.html.customers_row_cell(article["customers"])}</tr>'
                    html_string += f'<tr><td><strong>Keywords : </strong>{article["keywords"]}</td></tr>'
                    # append CVEs
                    if article["cves"]:
                        html_string += f'<tr><td><strong>CVE found:</strong></td></tr>'
                        for cve in article["cves"]:
                            html_string += f'<tr><td>  > <strong>{cve[0]}</strong>: CVSS {cve[2]} ({cve[1]})</td></tr>'
                    # append summary
                    html_string += f'<tr>{self.html.article_summary_row_cell(article["summary"])}</tr>'
                    # append contexts
                    for context in ("keywords", "customers"):
                        if article[f'{context}_context']:
                            html_string += f'<tr><td><strong>{context.capitalize()} mentions<strong></td></tr>'
                            for entry in article[f'{context}_context'].split("|"):
                                html_string += f'<tr>{self.html.context_row_cell(entry, article[context])}</tr>'
                    # close article table
                    html_string += self.html.close_theader()
                    # add article separator
                    html_string += '<tr><td>&nbsp;</td></tr>'
                # close article tables row
                html_string += f'</td></tr>'
                # close source table
                html_string += self.html.close_theader()
                html_string += '<tr><td>&nbsp;</td></tr>'
            # close overall table
            html_string += self.html.close_theader()
            self.log.info('*.html report ready')
            return html_string
        except Exception as exc:
            self.log.warning(f'*.html report failed: {str(exc)}')
            return None

    def deliver_report(self, mode: str, report_code: str) -> None:
        """
        Execute email delivery method for a  given report.

        :param str mode: report mode arg
        :param str report_code: report ``*.html`` code string
        """
        self.log.info('--------------------')
        self.log.info('report delivery')
        # depending on a report prepare matching subject and email greeting
        if mode == 'cves':
            subject = f'[TI] 🔶 CVE-related news'
            body = f'please find recent articles related to CVEs attached below: </ br>{report_code}'
        elif mode == 'prio':
            subject = f'[TI] 🔴 PRIO!: customer-related news'
            body = f'please find recent articles related to serviced customers attached below: </ br>{report_code}'
        else:
            subject = f'[TI] 🟩 RSS news matching interests'
            body = f'please find recent articles related to monitored interests attached below: </ br>{report_code}'
        # call sender class, execute sending
        self.log.info('calling email sender module')
        self.utils.send_simple_mail(body, subject, self.log)
        return

    def mark_as_delivered(self, article_list: list[Any]) -> None:
        """
        If email report delivery passed successfully - mark articles as delivered to avoid duplicated deliveries.

        :param article_list: list of articles matching report scope
        :type article_list: list[Any]
        """
        self.log.info('marking articles as delivered')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for article in article_list:
            query = (f"UPDATE [Neo_DB].[dbo].[data_ti_articles]"
                     f"SET [delivery_timestamp] = '{timestamp}' "
                     f"WHERE [source] = '{article[0]}' "
                     f"AND [title] = '{article[2]}' "
                     f"AND [summary] = '{article[3]}' "
                     f"AND [delivery_timestamp] IS NULL")
            updated = self.utils.upload_data(self.db_conn, query, self.log)
            if updated:
                self.log.info(f'> [ok] {article[2]}')
            else:
                self.log.info(f'> [fail] {article[2]}')
        return


class MyHTML:
    """
    HTML formatting placeholder class.
    """

    def __init__(self):
        """
        Initialize class instance.
        """

    @staticmethod
    def set_theader(width):
        """
        Return code of a new table with default settings related to cell spacing and padding.
        :param int width: table width in px
        :return: ``html`` table header
        :rtype: str
        """
        html_string = (
            f'<table style="width: {width}px; '
            f'border-collapse: collapse; '
            f'border-spacing: 0cm; '
            f'font-family: \'Courier New\', monospace; '
            f'font-size: 12;" '
            f'cellpadding="5">'
            f'<tbody>'
        )
        return html_string

    @staticmethod
    def close_theader():
        """
        Return table closing string.
        :return: ``</tbody></table>``
        :rtype: str
        """
        return "</tbody></table>"

    @staticmethod
    def source_row_cell(source: str) -> str:
        """
        Provide format for a source name table cell.

        :param str source: article source name string
        :return: html code string
        :rtype: str
        """
        style_border = 'border-bottom: 2px solid black; '
        style_font = 'font-size: 20; color:#003780; '
        style_cell = f"text-align: left; height: 24px; "
        return f'<td style="{style_cell}{style_border}{style_font}"><strong>From {source}</strong></td>'

    @staticmethod
    def article_title_row_cell(title: str) -> str:
        """
        Provide format for article title table cell

        :param str title: article title string
        :return: html code string
        :rtype: str
        """
        style_border = 'border-bottom: 1px solid silver; '
        style_font = 'font-size: 14; color:#000000; '
        style_cell = f"text-align: left; height: 14px; "
        return f'<td style="{style_cell}{style_border}{style_font}"><strong>⏩ {title}</strong></td>'

    @staticmethod
    def customers_row_cell(customers: str | None) -> str:
        """
        Provide format for mentioned customers table cell.

        :param customers: customer names string, optional
        :type customers: str or None
        :return: html code string
        :rtype: str
        """
        if customers:
            style_border = 'border: 1px solid red; '
            style_font = 'font-size: 12; color:#8c0000; '
            style_cell = f"text-align: left; background-color: #fcc5c5;"
            return f'<td style="{style_cell}{style_border}{style_font}"><strong>Customers: </strong>{customers}</td>'
        # in case of no mentioned customer names - return feedback info in raw format
        else:
            return f'<td style="text-align: left;"><strong>Customers: </strong>not related</td>'

    @staticmethod
    def article_summary_row_cell(summary: str) -> str:
        """
        Provide format for article summary table cell.

        :param str summary: article summary string
        :return: html code string
        :rtype: str
        """
        style_border = 'border: 1px solid gray; '
        style_font = 'font-size: 12; color:#000000; '
        style_cell = f"text-align: left; background-color: #dbdbdb;"
        return f'<td style="{style_cell}{style_border}{style_font}"><strong>Summary: </strong>{summary}</td>'

    def context_row_cell(self, context: str, keywords: str) -> str:
        """
        Provide format for keyword context article pieces table cell.

        :param str context: fragment of an article matching detected keyword
        :param str keywords: detected  priority keywords for a given articleF
        :return: html code string
        :rtype: str
        """
        style_border = ''
        style_font = 'font-size: 12; color:#000000; '
        style_cell = f"text-align: left; background-color: #c5dcfc;"
        # prepare text by adding bold near findings
        keywords_list = keywords.split(",")
        prepared_context = self.emphasize_keywords(context, keywords_list)
        # return
        return f'<td style="{style_cell}{style_border}{style_font}">{prepared_context}</td>'

    @staticmethod
    def link_row_cell(link: str) -> str:
        """
        Provide format for article link table cell.

        :param str link: original article url link string
        :return: html code string
        :rtype: str
        """
        style_border = ''
        style_font = 'font-size: 12; color:#000000; '
        style_cell = f"text-align: left; "
        return (f'<td style="{style_cell}{style_border}{style_font}">'
                f'🌐 <strong>Link :</strong> <a href="{link}">{link}</a></td>')

    @staticmethod
    def emphasize_keywords(text: str, keywords: list[str]) -> str:
        """
        Add distinct style near each priority keywords in a given article piece.

        :param str text: article piece string
        :param keywords: priority keywords found in an article
        :type keywords: list[str]
        :return: modified htmls string with visually highlighted keywords
        :rtype: str
        """
        # if no keywords for some reason - return original text
        if not keywords:
            return text
        # style: background highlight
        style = "font-weight:bold; background-color:rgb(255,255,0);"
        # attempt to pin-pint matching phrases in details, avoiding parts of words
        escaped = sorted((re.escape(k) for k in keywords), key=len, reverse=True)
        pattern = re.compile(r'\b(?:' + '|'.join(escaped) + r')\b', flags=re.IGNORECASE)
        # return modified code
        return pattern.sub(lambda val: f"<strong><span style='{style}'>{val.group(0)}</span></strong>", text)


def main(**kwargs: dict) -> None:
    """
    Perform script startup, then proceed with actions for a selected mode:

    - scan: obtain recent RSS articles, perform quick content analysis
    - cves: prepare a report with articles containing CVE-related content
    - prio: prepare a report with articles containing customer name

    Before any execution validate mode arg. If running without args: ask for user input.
    """
    # initialize log, exit on failure
    utils = MyUtils()
    log = utils.create_log('TI scanner')
    if not log:
        exit()

    # initialize utilities class
    # connect with database
    log.info('connecting with database')
    db_state, db_conn = utils.db_connect(log)
    if not db_state:
        log.critical('cannot connect with SQL database, exiting...')
        exit()

    # app task selection
    # process manual mode input when executed without arguments
    if kwargs['mode'] is not None:
        log.info(f'automated execution -> proceeding with {kwargs['mode']}')
        mode = str(kwargs['mode'])
    else:
        log.info('manual execution -> asking for user input')
        mode = select_mode(log)

    # mode [scan] - obtain and process recent RSS headers
    if mode == 'scan':
        # init RSS receiver class
        # lookup and analyze feeds
        receiver = MyReceiver(log, db_conn, utils)
        articles = receiver.process_feeds()
        if articles:
            receiver.upload_articles(articles)

    # mode [cves / prio]
    elif mode in ('cves', 'prio', 'news'):
        # obtain data
        # build report table containing details per source > article
        reporter = MyReporter(log, db_conn, utils)
        reporter.create_report(mode)

    # end of actions
    log.info('-------------------')
    log.info('all actions completed')


def select_mode(log: logging.Logger) -> str or exit:
    """
    Enabled manual input of application mode, providing a list of possible options. Exit on improper mode value.

    :param log: log object
    :type log: logging.Logger
    :return: chosen mode string
    :rtype: str
    """
    log.info('select task to perform')
    log.info('scan - round up recent articles from RSS sources')
    log.info('cves - CVE report content')
    log.info('prio - customer news report')
    log.info('news - all other (non-customer and non-cve related) articles')
    # get user input
    mode = input(f"Chosen task [scan / cves / prio / news]: ")
    # verify input - if in range, return proper mode string
    if mode in ['scan', 'cves', 'prio', 'news']:
        log.info(f'proceeding with {mode}')
        return mode
    else:
        log.critical(f'Option [{mode}] not recognized, exiting...')
        exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TI scanner')
    parser.add_argument('-m', '--mode', metavar='mode', help='Choose task to perform', type=str)
    args = parser.parse_args()
    main(**vars(args))
