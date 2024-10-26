# LdapDomainDump
LdapDomainDump with channel binding
![image](https://github.com/user-attachments/assets/abc29a69-89b7-4fed-a120-0632f0ee26a4)

## Getting Started

**Clone the repository:**
```bash
git clone https://github.com/k4ls3c/LdapDomainDump.git
```
## Usage
```
python3 ldapdomaindump.py -u usename -p 'pass@123' -d domain.com -s dc_ip --dump --html
```
![image](https://github.com/user-attachments/assets/9e1a08bf-ddb9-4b7b-8b4d-77ca744b97fd)

Options
```
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name
  -u USERNAME, --username USERNAME
                        Username for authentication
  -p PASSWORD, --password PASSWORD
                        Password for authentication
  -s SERVER, --server SERVER
                        Domain controller IP
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds
  --trust               Get domain trust information
  --pass-pol            Get domain policy information
  --computers           Get domain computer information
  --users               Get domain user information
  --groups              Get domain group information
  --dump                Dump all information into respective JSON files
  --html                Convert JSON reports to HTML
```
