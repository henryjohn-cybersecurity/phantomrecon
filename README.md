**PhantomRecon**

Advanced OSINT & Attack Surface Mapping Framework

PhantomRecon is an ethical reconnaissance and OSINT framework designed to help security researchers, students, and penetration testers analyze an organization’s public attack surface.

It aggregates intelligence from DNS, IP infrastructure, emails, social platforms, cloud services, JavaScript assets, and maps findings to MITRE ATT&CK techniques for clear risk understanding.

**Features**

Domain WHOIS & DNS intelligence

IP reputation, geolocation & evidence collection

Subdomain enumeration & takeover detection

Technology stack & security header fingerprinting

Cloud infrastructure & storage exposure detection

Email & social media OSINT

JavaScript secret & token discovery

Public exposure analysis

MITRE ATT&CK exposure mapping

Risk scoring & executive summary

JSON, HTML & PDF report generation

**Installation**

Clone the Repository

git clone https://github.com/henryjohn-cybersecurity/PhantomRecon.git

cd PhantomRecon

Create a Virtual Environment

python -m venv venv

Activate the Virtual Environment

Windows

venv\Scripts\activate

Linux / macOS

source venv/bin/activate

Install Dependencies

pip install -r requirements.txt

**Usage**

Inside PhantomRecon.py, go to target = "example.com"

replace "example.com" with any target domain (e.g amazon.com)

run:

python phantomrecon.py

When prompted:

Review findings in the terminal

Generate JSON & HTML reports automatically

Choose whether to export the HTML report as a PDF


**Output**

All reports are saved in the output/ directory:

JSON Report – structured machine-readable intelligence

HTML Report – interactive, human-friendly report

PDF Report – shareable executive document

Example:

output/

 ├── example.com_report_20260101.json
 
 ├── example.com_report_20260101.html
 
 └── example.com_report_20260101.pdf

**MITRE ATT&CK Mapping**

PhantomRecon maps discovered exposures to relevant MITRE ATT&CK tactics and techniques, helping defenders understand how attackers may exploit publicly available information.

Mapped stages include:

Reconnaissance (TA0043)

Resource Development (TA0042)

Initial Access (TA0001)

Discovery (TA0007)

Each technique includes severity, evidence, and contextual explanation.

**Example Use Cases**

Ethical hacking & penetration testing prep

Blue team attack surface monitoring

Cybersecurity internship portfolios

Security awareness & research

OSINT investigations (authorized only)

**Legal Disclaimer**

PhantomRecon is intended for educational and authorized security testing purposes only.
You must have explicit permission before scanning any target you do not own.
The author assumes no responsibility for misuse or illegal activity conducted using this tool.

**Author**

Effiong Henry John

Cybersecurity Analyst | Ethical Hacker | OSINT Researcher

LinkedIn: https://www.linkedin.com/in/-johenryhn-395707270

Email: intergrity660@gmail.com

**Contributing**

Contributions are welcome!

Fork the repository

Create a feature branch

Commit your changes

Submit a pull request

Ideas, bug reports, and improvements are encouraged.

⭐ If you find PhantomRecon useful, please consider starring the repository!

⭐ If you find PhantomRecon useful, please consider starring the repository!

