# pc-exposed-hosts-report-generator
This project creates HTML or PDF reports for Vulnerability and Compliance data pulled from a Prisma Cloud tenant. 
The report is generated only for Hosts exposed to the Internet.

Full credits go to Jason Donahue (timekillerj) who originally created this project and whose code I've almost enterily reused. 
 

## Setup
First clone this repo:

```
git clone https://github.com/pasqua1e/pc-exposed-hosts-report-generator.git
```

It is recommended you create a virtual environment to keep installed python packages isolated from the rest of your system:

```
cd pc-exposed-hosts-report-generator
python3 -m venv venv
```
Activate it:

```
source venv/bin/activate
```

Next you will need to install the required python packages:

```
pip install -r requirements.txt
```

Finally, you will need to install [wkhtmltopdf](https://wkhtmltopdf.org/downloads.html) for your platform.

## Environment Variables
To run reports with this script you will need 4 environment variables:

| Environment Variable     | Description                               |
|----------------------    |-------------------------------------------|
| CONSOLE_ADDRESS          | Prisma Cloud Console address              |
| COMPUTE_CONSOLE_ADDRESS  | Compute Console address                   |
| COMPUTE_ACCESS_KEY       | Your username for the instance            |
| COMPUTE_SECRET_KEY       | Your password                             |

## Usage
```
usage: create_report.py [-h] [-t {deployed,registry,ci}] [-f {pdf,html}] [-d] [-s] [-vo] [-co]

Create Compute Reports

optional arguments:
  -h, --help                                                show this help message and exit
  -T {hosts,containers}                                     Scan type (default: hosts)
  -t {deployed,registry,ci}, --type {deployed,registry,ci}  Containers only: Used to select the type of report to run.
  -f {pdf,html}, --format {pdf,html}                        Selects the file format of the generated report.
  -d, --debug                                               Prints debug output during report creation
  -s, --summary                                             Summary only, do not include vulnerability or compliance details
  -vo, --vulnerabilities-only                               Exclude Compliance data from report
  -co, --compliance-only                                    Exclude Vulnerabilities data from report
```
