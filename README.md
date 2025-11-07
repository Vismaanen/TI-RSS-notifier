# 📃 TI RSS scanner

Welcome to the manual of a TI scanner script - automated tool to obtain, analyze and forward TI articles of interest 
from popular web sources writing about IT security. Script can be run manually from an IDE or configured within a task
scheduler for a timed runs.

## Main functionalities
___
Script perform four separate actions:

- check-up of configured web sources for new articles, scrapping and uploading parsed content into local SQL database,
- creation of a report focused on configured ``customer names`` of interest,
- creation of a report with articles containing specific configured ``keywords``,
- creation of a report containing details about articles related to ``CVEs``.

These functionalities are described in detail in the following sections of this instruction.

## Dependencies
___
To run, script requires an SQL database with two tables:

- data_ti_articles: main table to store articles data,
- data_ti_cves: table to store details of CVEs mentioned in articles

Additional libraries are also required; use provided link to obtain those:

``pip install beautifulsoup4 feedparser rapidfuzz readability-lxml pyodbc requests``

Script logs all actions locally in a ``LOGS_DIR`` configurable location - set in a ``config`` file.

## External resources
___
Script operates on accessing various sources through ``https://``. Default supported TI sources as follows:

- BleepingComputer
- Dark Reading
- Security Week
- The Hacker News
- Infosecurity Magazine

Additionally, to provide a full coverage on a CVEs topic, queries to ``NIST`` are performed to obtain severity 
details for CVEs mentioned within articles. These details are then being uploaded into database CVEs table for later
use as a reference.

## Running script
___
Script can be run by providing --mode argument. Available modes:

- ``scan`` perform a lookup on RSS articles:
  - obtain current RSS content,
  - parse content, if applicable iterate per article to obtain full details,
  - search keywords related to CVEs, query ``NIST`` for CVE severity and cvss score, upload info to database,
  - check if each article meets monitoring criteria (keywords) before uploading,
  - collect each matching keyword as well as sentences from article which contain monitored keyword(s) for context,
  - upload articles of interest into database.
- ``prio`` create a report containing articles with mentioned customer name keywords,
- ``cves`` create a report containing articles related to CVEs,
- ``news`` create a report containing all other articles, not related to customer keywords or CVEs.

## Annotations
___
- No duplicate article deliveries: each article forwarded within a report is being marked in a database table with a delivery timestamp,
- Logging: each issue with a script is being logged for a review,
- SQL table queries are available within ``sql`` directory.,
- No API key is required for a communication with NIST, unless there are larger volume of queries expected.