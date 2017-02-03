"""Detect if any domain returns SERVFAIL for a query for NS records.

Requires `dig` command in bash.

Usage:
    $ python app.py domain-list.txt
"""
import sys
import os
import subprocess
import re

def _usage(exit_code=1):
    print("Usage: python app.py domain-list.txt")
    sys.exit(exit_code)

def _get_command_result(command):
    return subprocess.check_output(command, stderr=None, shell=True)

def get_domain_list():
    """Get a list of domains to check."""
    if len(sys.argv) != 2:
        _usage()
    if sys.argv[1] in ('-h', '--help'):
        _usage(0)
    filename = sys.argv[1]
    if not os.path.isfile(filename):
        print("File {0} not found.".format(filename))
        _usage()

    lines = None
    domains = list()
    with open(filename) as in_file:
        lines = in_file.readlines()
    for line in lines:
        line = line.strip()
        if line == '':
            continue
        if is_domain(line):
            domains.append(line)
    if len(domains) == 0:
        print("Error: No domains found in supplied file.")
        _usage()
    return domains

def is_domain(_str):
    """Validate string is a valid domain name or IP address.

    From:
    http://stackoverflow.com/questions/1128168/validation-for-url-domain-using-regex-rails
    """
    return re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}$', _str) is not None

'''
def _get_tld(domain_name):
    match = re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.([a-z]{2,5})$', domain_name)
    assert match is not None
    return match.group(1)
'''

def get_status(dig_output):
    """Get the lookup status from the output of the "dig" command."""
    match = re.search(r'status: ([^,]+),', dig_output)
    assert match is not None
    return match.group(1)

def get_ns_records(domain, dig_trace_output):
    """Get the NS records from the output of "dig" using "+trace"."""
    output_lines = dig_trace_output.splitlines()

    #e.g. uk.			172800	IN	NS	nsb.nic.uk.
    records = list()
    pattern = r'^{0}.\s+\d+\s+\w+\s+NS\s+(\S+)$'.format(domain)
    for line in output_lines:
        match = re.match(pattern, line.strip())
        if match is not None:
            records.append(match.group(1))
    return records


def _main():
    domains = get_domain_list()
    count = 0
    for domain in domains:
        cmd = "dig NS {0}".format(domain)
        output = _get_command_result(cmd)
        status = get_status(output)
        if status == 'SERVFAIL':
            count += 1
            print("NS record lookup for domain {0} returns SERVFAIL!".format(
                domain))
            cmd = "dig NS {0} +trace".format(domain)
            output = _get_command_result(cmd)
            ns_records = get_ns_records(domain, output)
            if len(ns_records) == 0:
                print(("No records found for domain {0}. Consider manually "
                       "investigating.").format(domain))
            else:
                print("SERVFAIL-vulnerable domain {0} resolves to NS records:".
                      format(domain))
                for ns_record in ns_records:
                    print("\t{0}".format(ns_record))
    print("{0} domain(s) of {1} found with SERVFAIL response.".
        format(count, len(domains)))

if __name__ == '__main__':
    _main()
