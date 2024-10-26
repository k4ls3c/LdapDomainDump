import ssl
import sys
import argparse
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple

import ldap3
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPOperationResult
import os
import codecs
import json
from jinja2 import Template  # Import Jinja2 for HTML templating

#Banner to be displayed
banner = r"""
 __    ____  _____ _____    ____                _        ____                
|  |  |    \|  _  |  _  |  |    \ ___ _____ ___|_|___   |    \ _ _ _____ ___ 
|  |__|  |  |     |   __|  |  |  | . |     | .'| |   |  |  |  | | |     | . |
|_____|____/|__|__|__|     |____/|___|_|_|_|__,|_|_|_|  |____/|___|_|_|_|  _|
                                                                        |_| 
    By k4ls3c 
"""

def convert_ad_timestamp(timestamp) -> str:
    """Convert Active Directory timestamp to readable datetime."""
    if timestamp in [0, '0']:
        return 'Never'
    try:
        return str(datetime.fromtimestamp((int(timestamp) / 10000000) - 11644473600))
    except (ValueError, TypeError):
        return 'Invalid timestamp'

def format_group_list(groups: List[str]) -> str:
    """Format group DN list to readable group names."""
    return ', '.join([g.split(',')[0].replace('CN=', '') for g in groups])

class LDAPAuthenticator:
    def __init__(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        timeout: int = 5
    ):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.timeout = timeout
        self.server = None
        self.connection = None
        self.base_dn = ','.join(['DC=' + dc for dc in domain.split('.')])

    def create_server(self) -> ldap3.Server:
        tls = ldap3.Tls(
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLSv1_2,
            ciphers='ALL:@SECLEVEL=0'
        )

        server = ldap3.Server(
            self.dc_ip,
            use_ssl=True,
            port=636,
            get_info=ldap3.ALL,
            tls=tls,
            connect_timeout=self.timeout
        )
        
        return server

    def authenticate(self) -> Optional[ldap3.Connection]:
        try:
            self.server = self.create_server()
            
            if not hasattr(ldap3, 'TLS_CHANNEL_BINDING'):
                raise Exception(
                    "LDAP channel binding requires patched ldap3 module. "
                    "Install: pip3 install git+https://github.com/ly4k/ldap3"
                )

            user = f"{self.domain}\\{self.username}"
            
            self.connection = ldap3.Connection(
                self.server,
                user=user,
                password=self.password,
                authentication=ldap3.NTLM,
                auto_referrals=False,
                receive_timeout=self.timeout * 10,
                channel_binding=ldap3.TLS_CHANNEL_BINDING
            )

            if not self.connection.bind():
                result = self.connection.result
                raise Exception(
                    f"Authentication failed: ({result['description']}) {result['message']}"
                )

            print(f"Successfully authenticated as {user}")
            return self.connection

        except Exception as e:
            raise Exception(f"Authentication failed: {e}")

    def get_all_users(self) -> List[Dict]:
        """
        Get detailed information about all domain users.
        
        Returns:
            List of dictionaries containing user information
        """
        if not self.connection or not self.connection.bound:
            raise Exception("Not authenticated to LDAP")

        # Define attributes to retrieve for users
        attributes = [
            'cn',                     # Common Name
            'name',                   # Name
            'sAMAccountName',         # SAM Account Name
            'userPrincipalName',      # User Principal Name
            'whenCreated',            # Created on
            'whenChanged',            # Changed on
            'lastLogon',              # Last Logon
            'description',            # Description
            'objectSid',              # Security Identifier
            'distinguishedName'       # Distinguished Name
        ]

        try:
            # Search for all user objects
            print("[+] Searching for Domain Users")
            self.connection.search(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(objectCategory=person))',
                attributes=attributes
            )

            print(f"    \\_ Search completed. Entries found: {len(self.connection.entries)}")
            users = []
            for entry in self.connection.entries:
                user_info = {attr: entry[attr].value if hasattr(entry, attr) else 'N/A' for attr in attributes}
                users.append(user_info)

            return users

        except LDAPSocketOpenError as e:
            raise Exception(f"LDAP connection failed: {e}")

    def get_primary_group_name(self, primary_group_id: int) -> str:
        """
        Get the name of the primary group by its ID.
        
        Args:
            primary_group_id (int): ID of the primary group
        
        Returns:
            str: Name of the primary group
        """
        if not self.connection or not self.connection.bound:
            raise Exception("Not authenticated to LDAP")

        try:
            # Search for the primary group
            self.connection.search(
                search_base=self.base_dn,
                search_filter=f'(&(objectClass=group)(primaryGroupID={primary_group_id}))',
                attributes=['cn']
            )

            # Get the primary group name
            primary_group_name = self.connection.entries[0].cn.value if self.connection.entries else 'N/A'

            return primary_group_name

        except IndexError:
            return 'N/A'

    def decode_uac_flags(self, uac: Optional[int]) -> str:
        """Decode User Account Control flags."""
        if uac is None:
            return 'No flags'

        flags = []
        flag_map = {
            0x0001: 'SCRIPT',
            0x0002: 'ACCOUNTDISABLE',
            0x0008: 'HOMEDIR_REQUIRED',
            0x0010: 'LOCKOUT',
            0x0020: 'PASSWD_NOTREQD',
            0x0040: 'PASSWD_CANT_CHANGE',
            0x0080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
            0x0100: 'TEMP_DUPLICATE_ACCOUNT',
            0x0200: 'NORMAL_ACCOUNT',
            0x0800: 'INTERDOMAIN_TRUST_ACCOUNT',
            0x1000: 'WORKSTATION_TRUST_ACCOUNT',
            0x2000: 'SERVER_TRUST_ACCOUNT',
            0x10000: 'DONT_EXPIRE_PASSWORD',
            0x20000: 'MNS_LOGON_ACCOUNT',
            0x40000: 'SMARTCARD_REQUIRED',
            0x80000: 'TRUSTED_FOR_DELEGATION',
            0x100000: 'NOT_DELEGATED',
            0x200000: 'USE_DES_KEY_ONLY',
            0x400000: 'DONT_REQ_PREAUTH',
            0x800000: 'PASSWORD_EXPIRED',
            0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
            0x04000000: 'PARTIAL_SECRETS_ACCOUNT'
        }
        
        for flag, name in flag_map.items():
            if uac & flag:
                flags.append(name)
        
        return ', '.join(flags) if flags else 'No flags'

    def get_domain_trusts(self) -> List[Dict[str, str]]:
        """
        Get information about domain trusts.
        
        Returns:
            List of dictionaries containing trust information
        """
        if not self.connection or not self.connection.bound:
            raise Exception("Not authenticated to LDAP")

        # Define attributes to retrieve for trusts
        attributes = [
            'cn',                     # CN
            'objectSid',              # Security Identifier
            'trustAttributes',         # Trust Attributes
            'trustDirection',          # Trust Direction
            'trustType'                # Trust Type
        ]

        try:
            # Search for all trust objects
            print("[+] Searching for Domain Trusts")
            self.connection.search(
                search_base=self.base_dn,
                search_filter='(&(objectClass=trustedDomain))',
                attributes=attributes
            )

            print(f"    \\_ Search completed. Entries found: {len(self.connection.entries)}")
            trusts = []
            for entry in self.connection.entries:
                trust_info = {
                    'CN': entry.cn.value if hasattr(entry, 'cn') else 'N/A',
                    'Security Identifier': entry.objectSid.value if hasattr(entry, 'objectSid') else 'N/A',
                    'Trust Attributes': entry.trustAttributes.value if hasattr(entry, 'trustAttributes') else 'N/A',
                    'Trust Direction': entry.trustDirection.value if hasattr(entry, 'trustDirection') else 'N/A',
                    'Trust Type': entry.trustType.value if hasattr(entry, 'trustType') else 'N/A'
                }
                trusts.append(trust_info)

            return trusts

        except LDAPSocketOpenError as e:
            raise Exception(f"LDAP connection failed: {e}")

    def get_domain_policy(self) -> List[Dict[str, str]]:
        """
        Get information about domain policies.
        
        Returns:
            List of dictionaries containing policy information
        """
        if not self.connection or not self.connection.bound:
            raise Exception("Not authenticated to LDAP")

        # Define attributes to retrieve for domain policies
        attributes = [
            'distinguishedName',        # Distinguished Name
            'lockOutObservationWindow',  # Lockout time window
            'lockoutDuration',          # Lockout Duration
            'lockoutThreshold',         # Lockout Threshold
            'maxPwdAge',                # Maximum password age
            'minPwdAge',                # Minimum password age
            'minPwdLength',             # Minimum password length
            'pwdHistoryLength',         # Password history length
            'pwdProperties',            # Password properties
            'ms-DS-MachineAccountQuota' # Machine Account Quota
        ]

        try:
            # Search for the domain policy
            print("[+] Searching for Domain Policies")
            self.connection.search(
                search_base=self.base_dn,
                search_filter='(&(objectClass=domain))',
                attributes=attributes
            )

            print(f"    \\_ Search completed. Entries found: {len(self.connection.entries)}")
            policies = []
            for entry in self.connection.entries:
                policy_info = {attr: entry[attr].value if hasattr(entry, attr) else 'N/A' for attr in attributes}
                policies.append(policy_info)

            return policies

        except LDAPSocketOpenError as e:
            raise Exception(f"LDAP connection failed: {e}")

    def get_all_computers(self) -> List[Dict]:
        """
        Get detailed information about all domain computers.
        
        Returns:
            List of dictionaries containing computer information
        """
        if not self.connection or not self.connection.bound:
            raise Exception("Not authenticated to LDAP")

        # Define attributes to retrieve for computers
        attributes = [
            'cn',                     # Common Name
            'name',                   # Name
            'sAMAccountName',         # SAM Account Name
            'operatingSystem',        # Operating System
            'operatingSystemVersion',  # Operating System Version
            'lastLogon',              # Last Logon
            'description',            # Description
            'objectSid',              # Security Identifier
            'distinguishedName'       # Distinguished Name
        ]

        try:
            # Search for all computer objects
            print("[+] Searching for Domain Computers")
            self.connection.search(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer))',
                attributes=attributes
            )

            print(f"    \\_ Search completed. Entries found: {len(self.connection.entries)}")
            computers = []
            for entry in self.connection.entries:
                computer_info = {attr: entry[attr].value if hasattr(entry, attr) else 'N/A' for attr in attributes}
                computers.append(computer_info)

            return computers

        except LDAPSocketOpenError as e:
            raise Exception(f"LDAP connection failed: {e}")

    def get_all_groups(self) -> List[Dict]:
        """
        Get detailed information about all domain groups, including members.
        
        Returns:
            List of dictionaries containing group information
        """
        if not self.connection or not self.connection.bound:
            raise Exception("Not authenticated to LDAP")

        # Define attributes to retrieve for groups, including members
        attributes = [
            'cn',                     # Common Name
            'description',            # Description
            'distinguishedName',      # Distinguished Name
            'member'                  # Members of the group
        ]

        try:
            # Search for all group objects
            print("[+] Searching for Domain Groups")
            self.connection.search(
                search_base=self.base_dn,
                search_filter='(&(objectClass=group))',
                attributes=attributes
            )

            print(f"    \\_ Search completed. Entries found: {len(self.connection.entries)}")
            groups = []
            for entry in self.connection.entries:
                group_info = {attr: entry[attr].value if hasattr(entry, attr) else 'N/A' for attr in attributes}
                groups.append(group_info)

            return groups

        except LDAPSocketOpenError as e:
            raise Exception(f"LDAP connection failed: {e}")

# New reportWriter class added
class reportWriter():
    def __init__(self, config):
        self.config = config
        self.dd = None
        # Define attributes for users, computers, policies, and trusts
        self.computerattributes = ['cn', 'sAMAccountName', 'dNSHostName', 'IPv4', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid', 'description']
        self.userattributes = ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId', 'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName']
        self.policyattributes = ['distinguishedName', 'lockOutObservationWindow', 'lockoutDuration', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties', 'ms-DS-MachineAccountQuota']
        self.trustattributes = ['cn', 'flatName', 'securityIdentifier', 'trustAttributes', 'trustDirection', 'trustType']

    # Write generated JSON to file
    def writeJsonFile(self, rel_outfile, jsondata):
        if not os.path.exists(self.config['basepath']):
            os.makedirs(self.config['basepath'])
        outfile = os.path.join(self.config['basepath'], rel_outfile)
        with codecs.open(outfile, 'w', 'utf8') as of:
            of.write(jsondata)

    # Convert datetime and timedelta objects to string
    def serialize_datetime(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()  # Convert to ISO 8601 format
        elif isinstance(obj, timedelta):
            return str(obj)  # Convert timedelta to string (e.g., "1 day, 12:00:00")
        elif isinstance(obj, list):
            return [self.serialize_datetime(item) for item in obj]  # Recursively serialize lists
        elif isinstance(obj, dict):
            return {key: self.serialize_datetime(value) for key, value in obj.items()}  # Recursively serialize dicts
        raise TypeError(f"Type {type(obj)} not serializable")

    # Generate report with domain policy information
    def generatePolicyReport(self, policies):
        if self.config['outputjson']:
            jsonout = json.dumps(policies, default=self.serialize_datetime, indent=4)  # Convert the list of policies to JSON format
            self.writeJsonFile('%s.json' % self.config['policyfile'], jsonout)

    # Generate report with domain trust information
    def generateTrustsReport(self, trusts):
        if self.config['outputjson']:
            jsonout = json.dumps(trusts, default=self.serialize_datetime, indent=4)  # Convert the list of trusts to JSON format
            self.writeJsonFile('%s.json' % self.config['trustfile'], jsonout)

    # Generate report with just a table of all computer accounts
    def generateComputersReport(self, computers):
        if self.config['outputjson']:
            jsonout = json.dumps(computers, default=self.serialize_datetime, indent=4)  # Convert the list of computers to JSON format
            self.writeJsonFile('%s.json' % self.config['computersfile'], jsonout)

           

    # Generate report with just a table of all users
    def generateUsersReport(self, users):
        if self.config['outputjson']:
            jsonout = json.dumps(users, default=self.serialize_datetime, indent=4)  # Convert the list of users to JSON format
            self.writeJsonFile('%s.json' % self.config['usersfile'], jsonout)

    # Generate report with just a table of all groups
    def generateGroupsReport(self, groups):
        if self.config['outputjson']:
            jsonout = json.dumps(groups, default=self.serialize_datetime, indent=4)  # Convert the list of groups to JSON format
            self.writeJsonFile('%s.json' % self.config['groupsfile'], jsonout)

    # New method to convert JSON to HTML
    def json_to_html(self, json_data, title):
        if not json_data:  # Check if json_data is empty
            return f"<h1>{title}</h1><p>No data available to display.</p>"

        template = Template("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ title }}</title>
            <style>
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid black; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>{{ title }}</h1>
            <table>
                <thead>
                    <tr>
                        {% for key in json_data[0].keys() %}
                        <th>{{ key }}</th>
                        {% endfor %}
                    </tr>
                </thead>
                <tbody>
                    {% for item in json_data %}
                    <tr>
                        {% for value in item.values() %}
                        <td>{{ value }}</td>
                        {% endfor %}
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </body>
        </html>
        """)
        return template.render(title=title, json_data=json_data)

    # New method to write HTML file
    def writeHtmlFile(self, rel_outfile, jsondata):
        html_content = self.json_to_html(jsondata, rel_outfile)
        outfile = os.path.join(self.config['basepath'], rel_outfile.replace('.json', '.html'))
        with codecs.open(outfile, 'w', 'utf8') as of:
            of.write(html_content)

def main():
    print(banner)
    parser = argparse.ArgumentParser(description='LDAP User Enumerator')
    parser.add_argument('-d', '--domain', help='Domain name', required=True)
    parser.add_argument('-u', '--username', help='Username for authentication', required=True)
    parser.add_argument('-p', '--password', help='Password for authentication', required=True)
    parser.add_argument('-s', '--server', help='Domain controller IP', required=True)
    parser.add_argument('-t', '--timeout', help='Connection timeout in seconds', default=5, type=int)
    parser.add_argument('--trust', action='store_true', help='Get domain trust information')
    parser.add_argument('--pass-pol', action='store_true', help='Get domain policy information')
    parser.add_argument('--computers', action='store_true', help='Get domain computer information')
    parser.add_argument('--users', action='store_true', help='Get domain user information')
    parser.add_argument('--groups', action='store_true', help='Get domain group information')
    parser.add_argument('--dump', action='store_true', help='Dump all information into respective JSON files')
    parser.add_argument('--html', action='store_true', help='Convert JSON reports to HTML')
    

    args = parser.parse_args()

    # Check if at least one of the flags is provided
    if not (args.trust or args.pass_pol or args.computers or args.users or args.dump):
        print("No specific option provided. Use --trust, --pass-pol, --computers, --users, or --dump.")
        return  # Exit the program if no valid option is provided

    ldap_auth = LDAPAuthenticator(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dc_ip=args.server,
        timeout=args.timeout
    )

    # Initialize reportWriter with a config object
    config = {
        'basepath': './reports',   # Example path, adjust as needed
        'outputjson': True,
        'computersfile': 'computers_report',
        'usersfile': 'users_report',
        'policyfile': 'policy_report',  # Add policy file configuration
        'trustfile': 'trust_report',  # Add trust file configuration
        'groupsfile': 'groups_report',  # Add groups file configuration
    }
    
    report_writer = reportWriter(config)

    try:
        connection = ldap_auth.authenticate()
        
        # Generate reports based on the flags
        if args.dump:
            computers = ldap_auth.get_all_computers()
            report_writer.generateComputersReport(computers)

            users = ldap_auth.get_all_users()
            report_writer.generateUsersReport(users)

            policies = ldap_auth.get_domain_policy()
            report_writer.generatePolicyReport(policies)

            trusts = ldap_auth.get_domain_trusts()
            report_writer.generateTrustsReport(trusts)

            groups = ldap_auth.get_all_groups()
            report_writer.generateGroupsReport(groups)

        # New section to handle HTML conversion
        if args.html:
            for report_file in ['computers_report.json', 'users_report.json', 'policy_report.json', 'trust_report.json', 'groups_report.json']:
                json_file_path = os.path.join(config['basepath'], report_file)
                if os.path.exists(json_file_path):
                    with codecs.open(json_file_path, 'r', 'utf8') as jf:
                        json_data = json.load(jf)
                        if json_data:  # Check if json_data is not empty
                            report_writer.writeHtmlFile(report_file, json_data)
                        else:
                            print(f"No data found in {report_file}. Skipping HTML conversion.")

        elif args.computers:  # New section to handle computers
            computers = ldap_auth.get_all_computers()
            report_writer.generateComputersReport(computers)
        elif args.users:
            users = ldap_auth.get_all_users()
            report_writer.generateUsersReport(users)
        elif args.pass_pol:  # Assuming this flag is used to get policy information
            policies = ldap_auth.get_domain_policy()
            report_writer.generatePolicyReport(policies)
        elif args.trust:  # Assuming this flag is used to get trust information
            trusts = ldap_auth.get_domain_trusts()
            report_writer.generateTrustsReport(trusts)
        elif args.groups:  # New section to handle groups
            groups = ldap_auth.get_all_groups()
            report_writer.generateGroupsReport(groups)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
