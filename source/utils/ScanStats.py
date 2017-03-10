__author__ = 'willi'

import re
import logging
import csv
import os
logging.basicConfig(level=logging.INFO)

MAPPING2 = [
    'DES-CBC-MD5'	,
    'DES-CBC3-MD5'	,
    'EXP-RC2-CBC-MD5'	,
    'EXP-RC4-MD5'	,
    'IDEA-CBC-MD5'	,
    'RC2-CBC-MD5'	,
    'RC4-MD5'
]

MAPPING3 = [
    'AES128-SHA'	,
    'AES256-SHA'	,
    'CAMELLIA128-SHA'	,
    'CAMELLIA256-SHA'	,
    'DES-CBC3-SHA'	,
    'DHE-RSA-AES128-SHA'	,
    'DHE-RSA-AES256-SHA'	,
    'DHE-RSA-CAMELLIA128-SHA'	,
    'DHE-RSA-CAMELLIA256-SHA'	,
    'DHE-RSA-SEED-SHA'	,
    'EDH-RSA-DES-CBC3-SHA'	,
    'IDEA-CBC-SHA'	,
    'RC4-MD5'	,
    'RC4-SHA'	,
    'SEED-SHA'	,
    'ADH-AES128-GCM-SHA256'	,
    'ADH-AES128-SHA'	,
    'ADH-AES128-SHA256'	,
    'ADH-AES256-GCM-SHA384'	,
    'ADH-AES256-SHA'	,
    'ADH-AES256-SHA256'	,
    'ADH-CAMELLIA128-SHA'	,
    'ADH-CAMELLIA256-SHA'	,
    'ADH-DES-CBC-SHA'	,
    'ADH-DES-CBC3-SHA'	,
    'ADH-RC4-MD5'	,
    'ADH-SEED-SHA'	,
    'AECDH-AES128-SHA'	,
    'AECDH-AES256-SHA'	,
    'AECDH-DES-CBC3-SHA'	,
    'AECDH-NULL-SHA'	,
    'AECDH-RC4-SHA'	,
    'AES128-GCM-SHA256'	,
    'AES128-SHA256'	,
    'AES256-GCM-SHA384'	,
    'AES256-SHA256'	,
    'DES-CBC-SHA'	,
    'DH-DSS-AES128-GCM-SHA256'	,
    'DH-DSS-AES128-SHA'	,
    'DH-DSS-AES128-SHA256'	,
    'DH-DSS-AES256-GCM-SHA384'	,
    'DH-DSS-AES256-SHA'	,
    'DH-DSS-AES256-SHA256'	,
    'DH-DSS-CAMELLIA128-SHA'	,
    'DH-DSS-CAMELLIA256-SHA'	,
    'DH-DSS-DES-CBC-SHA'	,
    'DH-DSS-DES-CBC3-SHA'	,
    'DH-DSS-SEED-SHA'	,
    'DH-RSA-AES128-GCM-SHA256'	,
    'DH-RSA-AES128-SHA'	,
    'DH-RSA-AES128-SHA256'	,
    'DH-RSA-AES256-GCM-SHA384'	,
    'DH-RSA-AES256-SHA'	,
    'DH-RSA-AES256-SHA256'	,
    'DH-RSA-CAMELLIA128-SHA'	,
    'DH-RSA-CAMELLIA256-SHA'	,
    'DH-RSA-DES-CBC-SHA'	,
    'DH-RSA-DES-CBC3-SHA'	,
    'DH-RSA-SEED-SHA'	,
    'DHE-DSS-AES128-GCM-SHA256'	,
    'DHE-DSS-AES128-SHA'	,
    'DHE-DSS-AES128-SHA256'	,
    'DHE-DSS-AES256-GCM-SHA384'	,
    'DHE-DSS-AES256-SHA'	,
    'DHE-DSS-AES256-SHA256'	,
    'DHE-DSS-CAMELLIA128-SHA'	,
    'DHE-DSS-CAMELLIA256-SHA'	,
    'DHE-DSS-SEED-SHA'	,
    'DHE-RSA-AES128-GCM-SHA256'	,
    'DHE-RSA-AES128-SHA256'	,
    'DHE-RSA-AES256-GCM-SHA384'	,
    'DHE-RSA-AES256-SHA256'	,
    'ECDH-ECDSA-AES128-GCM-SHA256'	,
    'ECDH-ECDSA-AES128-SHA'	,
    'ECDH-ECDSA-AES128-SHA256'	,
    'ECDH-ECDSA-AES256-GCM-SHA384'	,
    'ECDH-ECDSA-AES256-SHA'	,
    'ECDH-ECDSA-AES256-SHA384'	,
    'ECDH-ECDSA-DES-CBC3-SHA'	,
    'ECDH-ECDSA-NULL-SHA'	,
    'ECDH-ECDSA-RC4-SHA'	,
    'ECDH-RSA-AES128-GCM-SHA256'	,
    'ECDH-RSA-AES128-SHA'	,
    'ECDH-RSA-AES128-SHA256'	,
    'ECDH-RSA-AES256-GCM-SHA384'	,
    'ECDH-RSA-AES256-SHA'	,
    'ECDH-RSA-AES256-SHA384'	,
    'ECDH-RSA-DES-CBC3-SHA'	,
    'ECDH-RSA-NULL-SHA'	,
    'ECDH-RSA-RC4-SHA'	,
    'ECDHE-ECDSA-AES128-GCM-SHA256'	,
    'ECDHE-ECDSA-AES128-SHA'	,
    'ECDHE-ECDSA-AES128-SHA256'	,
    'ECDHE-ECDSA-AES256-GCM-SHA384'	,
    'ECDHE-ECDSA-AES256-SHA'	,
    'ECDHE-ECDSA-AES256-SHA384'	,
    'ECDHE-ECDSA-DES-CBC3-SHA'	,
    'ECDHE-ECDSA-NULL-SHA'	,
    'ECDHE-ECDSA-RC4-SHA'	,
    'ECDHE-RSA-AES128-GCM-SHA256'	,
    'ECDHE-RSA-AES128-SHA'	,
    'ECDHE-RSA-AES128-SHA256'	,
    'ECDHE-RSA-AES256-GCM-SHA384'	,
    'ECDHE-RSA-AES256-SHA'	,
    'ECDHE-RSA-AES256-SHA384'	,
    'ECDHE-RSA-DES-CBC3-SHA'	,
    'ECDHE-RSA-NULL-SHA'	,
    'ECDHE-RSA-RC4-SHA'	,
    'EDH-DSS-DES-CBC-SHA'	,
    'EDH-DSS-DES-CBC3-SHA'	,
    'EDH-RSA-DES-CBC-SHA'	,
    'EXP-ADH-DES-CBC-SHA'	,
    'EXP-ADH-RC4-MD5'	,
    'EXP-DES-CBC-SHA'	,
    'EXP-DH-DSS-DES-CBC-SHA'	,
    'EXP-DH-RSA-DES-CBC-SHA'	,
    'EXP-EDH-DSS-DES-CBC-SHA'	,
    'EXP-EDH-RSA-DES-CBC-SHA'	,
    'EXP-RC2-CBC-MD5'	,
    'EXP-RC4-MD5'	,
    'NULL-MD5'	,
    'NULL-SHA'	,
    'NULL-SHA256'	,
    'PSK-3DES-EDE-CBC-SHA'	,
    'PSK-AES128-CBC-SHA'	,
    'PSK-AES256-CBC-SHA'	,
    'PSK-RC4-SHA'	,
    'SRP-3DES-EDE-CBC-SHA'	,
    'SRP-AES-128-CBC-SHA'	,
    'SRP-AES-256-CBC-SHA'	,
    'SRP-DSS-3DES-EDE-CBC-SHA'	,
    'SRP-DSS-AES-128-CBC-SHA'	,
    'SRP-DSS-AES-256-CBC-SHA'	,
    'SRP-RSA-3DES-EDE-CBC-SHA'	,
    'SRP-RSA-AES-128-CBC-SHA'	,
    'SRP-RSA-AES-256-CBC-SHA'	]


def init_pattern_dict():
    """
    Initialize the pattern dict and load all statistics from the file

    Statistics are not based on the total pattern over all TLS versions, because
    each TLS version is scanned with its own plugin, and thus with its own process
    """
    for port in ['25', '110', '143', '443', '465', '587', '993', '995']:
        for index, version in enumerate(['sslv2', 'sslv3', 'tlsv1', 'tlsv1_1', 'tlsv1_2']):
            with open(os.path.join('utils', 'data', 'pattern_%s_%s.csv' % (port, version))) as f:
                PATTERN_DICT[(port, index+1)] = [tuple(line)[1:] for line in csv.reader(f)][1:]

PATTERN_DICT = dict()
init_pattern_dict()


def get_pattern_for_result_dict(version, result_dicts):
    """
    Return a pattern string for 'result_dicts'

    See get_pattern_for_cipher_list
    """
    return get_pattern_for_cipher_lists(version,
                                        list(result_dicts['acceptedCipherSuites'].iterkeys()),
                                        list(result_dicts['rejectedCipherSuites'].iterkeys()),
                                        list(result_dicts['errors'].iterkeys()))


def get_pattern_for_cipher_lists(version, accepted, rejected, error):
    """
    Return a pattern string for different lists of cipher suites

    :param version: The TLS version (sslv2 => 1, ...)
    :param accepted: list of accepted ciphersuites
    :param rejected: list of rejected ciphersuites
    :param error: list of ciphersuites with errors
    :return: str e.g., 'aaarrrraaaarrrrraaaarrrr'
    """
    mapping = MAPPING2 if version == 1 else MAPPING3
    return ''.join([('a' if cipher in accepted else
                     'r' if cipher in rejected else
                     'e' if cipher in error else
                     '.') for cipher in mapping])


def list_ciphers_for_pattern(pattern, state, supported_cipher_list):
    """
    Return a list of ciphers in a specific state

    :param pattern: str e.g., 'aaarrrraaaarrrrraaaarrrr'
    :param state: str e.g., 'a' or 'r' or ...
    :param supported_cipher_list: list of ciphersuites; choose only ciphers which are in this list
    :return: list of ciphersuites
    """
    mapping = MAPPING2 if len(pattern) == 7 else MAPPING3
    ciphers = zip(*filter(lambda (ind, res): pattern[ind] == state and res in supported_cipher_list,
                          enumerate(mapping)))
    return list(ciphers[1]) if len(ciphers) > 1 else list()


def list_accepted_ciphers_for_pattern(pattern, supported_cipher_list):
    return list_ciphers_for_pattern(pattern, 'a', supported_cipher_list)


def list_rejected_ciphers_for_pattern(pattern, supported_cipher_list):
    return list_ciphers_for_pattern(pattern, 'r', supported_cipher_list)


def list_unassigned_ciphers_for_pattern(pattern, supported_cipher_list):
    return list_ciphers_for_pattern(pattern, '.', supported_cipher_list)


def calculate_new_jobs_stats_algorithm(supported_cipher_list, port, version, current_pattern):
    """
    Calculate new jobs with the stats algorithm

    :param supported_cipher_list: list of ciphersuites to choose from
    :param port: str e.g., '443', '25', ...
    :param version: int of TLS version for which statistics to use (1,2,3,4,5)
    :param current_pattern:
    :return: list of jobs - job is a list of ciphersuites
    """

    logging.debug("start comparing (version=%s)" % version)
    best_pattern = None
    # If port/version not in pattern_dict, use 443
    if port not in zip(*PATTERN_DICT.iterkeys())[0]:
        port = '443'

    for prob, pattern in PATTERN_DICT[(port, version)]:
        if re.match(current_pattern, pattern):
            best_pattern = pattern
            logging.debug("actual pattern                       %s" % current_pattern)
            logging.debug("found next best pattern (prob=%0.3f) %s" % (float(prob), best_pattern))
            break

    # if no pattern was found, fallback to naive strategy
    if not best_pattern:
        logging.debug("no pattern was found, fallback to naive")
        return [[job] for job in list_ciphers_for_pattern(current_pattern, '.', supported_cipher_list)]

    new_jobs_pattern = "".join(['X' if cipher != '.' else best_pattern[i] for i, cipher in enumerate(current_pattern)])
    logging.debug("new jobs  pattern                    %s" % new_jobs_pattern)

    jobs_a = [[job] for job in list_accepted_ciphers_for_pattern(new_jobs_pattern, supported_cipher_list)]
    jobs_r = [list_rejected_ciphers_for_pattern(new_jobs_pattern, supported_cipher_list)]

    jobs = jobs_a + jobs_r
    return jobs


def calculate_new_jobs_group_algorithm(supported_cipher_list, current_pattern):
    """
    Calculate new jobs with the group algorithm

    :param supported_cipher_list: list of all possible ciphersuites
    :param current_pattern:
    :return: list of jobs - job is a list of ciphersuites
    """

    variants = [['SRP'], ['PSK'],
                ['EXP'], ['NULL'],
                ['DSA', 'DSS'],
                ['ADH', 'AECDH'],
                ['CAMELLIA', 'SEED', 'IDEA', 'DES-CBC-'],
                ['RC4']
                ]
    jobs = {":".join(v): list() for v in variants}

    for c in list_unassigned_ciphers_for_pattern(current_pattern, supported_cipher_list):
        cipher_assigned = False
        for variant in variants:
            if filter(lambda x: x in c, variant) and not cipher_assigned:
                jobs[":".join(variant)].append(c)
                cipher_assigned = True
        if not cipher_assigned:
            jobs[c] = [c]

    logging.debug("calculate primitives returning %d jobs " % len([o for o in jobs.itervalues() if o]))

    return [o for o in jobs.itervalues() if o]


def test_cipher_list_for_differences():
    from nassl.SslClient import SslClient
    from nassl import SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2

    set2 = set(MAPPING2)
    set3 = set(MAPPING3)

    for sslVersion in (SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2):
        logging.info("Starting test for SSLV2")
        ssl_client = SslClient(sslVersion=sslVersion)
        ssl_client.set_cipher_list('ALL:COMPLEMENTOFALL')
        current = set(ssl_client.get_cipher_list())

        if sslVersion == SSLV2:
            statset = set2
        else:
            statset = set3

        logging.info("SSLv/TLSv (%d)" % sslVersion)
        logging.info("Only in currentVersion   %s" % (current - statset))
        logging.info("Only in statisticVersion %s" % (statset - current))
        logging.info("In both versions %s" % (current & statset))
        logging.info("-----")