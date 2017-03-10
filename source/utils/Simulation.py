from ScanStats import MAPPING2, MAPPING3, calculate_new_jobs_group_algorithm, calculate_new_jobs_stats_algorithm
import csv
import logging
import os

logging.basicConfig(level=logging.INFO)


################################################################################
# Tests for different Algorithms
################################################################################

def test_connections():
    """
    Calculate statistics for all algorithms and all files

    1) Load statistic files
    2) Print Out Results
    """
    results = []

    logging.info("port ")

    for port in ['25', '110', '143', '443', '465', '587', '993', '995']:
        for start, end, version, version_int in ([(0, 7, 'sslv2', 1),
                                                  (7, 143, 'sslv3', 2),
                                                  (143, 279, 'tlsv1', 3),
                                                  (279, 415, 'tlsv1_1', 4),
                                                  (415, 551, 'tlsv1_2', 5)]):
            # TODO other filepath would be nice.
            with open(
                    os.path.join('/home/willi/PycharmProjects/sslyze/data/patterns_without_error_and_p_equals_a/',
                                 'pattern_%s.csv' % port)) as f:
                data = [(count, percentage, pattern[start:end]) for count, percentage, _, pattern in csv.reader(f)][1:]
                results.append(print_connection_table_data(port, version, version_int, data))

    results_sums = tuple(map(sum, zip(*results)[2:]))
    logging.info("------------------------------------------------------------------------------------------")
    # logging.info("TOTAL                            %10d hosts %6d patterns - "
    #              "%10d naive / %10d connopt        / %10d groups        / %10d stats       " % results_sums)


def print_connection_table_data(port, version, version_int, data):
    """
    Print out the connection table

    :param port: str port e.g, '443'
    :param version: str version e.g., 'sslv2'
    :param data:
    :return:
    """
    hosts_count = sum([int(hosts) for hosts, _, _ in data])
    pattern_count = len(data)

    values_naive = [(int(hosts),)+estimate_naive_algorithm(pattern) for hosts, _, pattern in data]
    values_connopt = [(int(hosts),)+estimate_connections_connopt_algorithm(pattern) for hosts, _, pattern in data]
    values_groups = [(int(hosts),)+estimate_groups_algorithm(pattern) for hosts, _, pattern in data]
    values_stats = [(int(hosts),)+estimate_stats_algorithm(pattern, port, version_int) for hosts, _, pattern in data]



    naive_con = sum([a * b for a,b,_,_ in values_naive])
    naive_rr_sum = sum([a*c for a,_,c,_ in values_naive])
    naive_rr_max = max([c for _,_,c,_ in values_naive])

    conopt_con = sum([a * b for a,b,_,_ in values_connopt])
    conopt_rr_max = max([c for _,_,c,_ in values_connopt])
    conopt_rr_sum = sum([a*c for a,_,c,_ in values_connopt])



    groups_con = sum([a * b for a,b,_,_ in values_groups])
    groups_rr_sum = sum([a*c for a,_,c,_ in values_groups])
    groups_rr_max = max([c for _,_,c,_ in values_groups])

    stats_con = sum([a * b for a,b,_,_ in values_stats])
    stats_rr_sum = sum([a*c for a,_,c,_ in values_stats])
    stats_rr_max = max([c for _,_,c,_ in values_stats])

    result = (port,
              version,
              hosts_count,
              pattern_count,
              naive_con,
              naive_rr_sum,
              naive_rr_max,
              conopt_con,
              conopt_rr_sum,
              conopt_rr_max,
              groups_con,
              groups_rr_sum,
              groups_rr_max,
              stats_con,
              stats_rr_sum,
              stats_rr_max
              )

    logging.info("%3s %7s %10d %10d %10d %10d %10d %10d %10d %10d %10d %10d %10d %10d %10d %10d" % result)
    return result


"""
Estimate connections and request rounds
Functions return (connections, request_rounds, traffic)
"""


def estimate_connections_connopt_algorithm(pattern):
    """
    Estimate the numbers necessary with the connopt algorithm

    Connections is the number of accepted ciphersuites + 1 for all rejected ciphersuites in the last connection
    Request Rounds is #connections since all sequential

    :param pattern: str e.g., 'aaarrrraaaarrrrraaaarrrr'
    :return: (int, int, int) - connections, request_rounds, traffic
    """
    # simple for connopt   count all accepted + 1 for all rejected
    connections = len([c for c in pattern if c == 'a']) + 1
    request_rounds = connections
    traffic = None  # TODO

    return connections, request_rounds, traffic


def estimate_naive_algorithm(pattern):
    """
    Estimate the numbers necessary with the naive algorithm

    Connections is len(pattern) since there is one job for each ciphersuite
    RequestRounds is one since all are in parallel

    :param pattern: str e.g., 'aaarrrraaaarrrrraaaarrrr'
    :return: (int, int, int) - connections, request_rounds, traffic
    """
    connections = len(pattern)
    request_rounds = 1
    traffic = None  # TODO

    return connections, request_rounds, traffic


def estimate_groups_algorithm(pattern):
    """
    Estimate the number of connections for the groups algorithm

    To estimate this simulate the algorithm
    :param pattern: str e.g., 'aaarrrraaaarrrrraaaarrrr'
    :return: (int, int, int) - connections, request_rounds, traffic
    """
    connections, request_rounds =  simulate_algorithm(pattern,
                              lambda x: calculate_new_jobs_group_algorithm(MAPPING2 if len(pattern) == 7 else MAPPING3,
                                                                           x))
    traffic = None  # TODO

    return connections, request_rounds, traffic


def estimate_stats_algorithm(pattern, port, version):
    """
    Estimate the number of connections for the stats algorithm

    To estimate this simulate the algorithm
    :param pattern: str e.g., 'aaarrrraaaarrrrraaaarrrr'
    :param port: str e.g., '443', '25, ...
    :param version: the TLS version from 1 to 5
    :return: (int, int, int) - connections, request_rounds, traffic
    """
    connections, request_rounds = simulate_algorithm(pattern,
                              lambda x: calculate_new_jobs_stats_algorithm(MAPPING2 if len(pattern) == 7 else MAPPING3,
                                                                           port,
                                                                           version,
                                                                           x))
    traffic = None  # TODO

    return connections, request_rounds, traffic


def simulate_algorithm(pattern, algorithm):
    """
    Simulate an algorithm

    While result not complete
      1) Calculate all jobs with 'algorithm'
      2) Simulate the results for these jobs for the 'pattern'
      3) Modify result
    :param pattern:
    :param algorithm:
    :return: (int,int) - connections, request_rounds
    """

    total_connections = 0
    request_rounds = 0

    current_pattern = '.' * len(pattern)

    # While result not complete
    while '.' in current_pattern:

        logging.debug(" - round start - ")

        # 1) Calculate jobs
        jobs = algorithm(current_pattern)
        total_connections += len(jobs)
        request_rounds += 1

        logging.debug("%d jobs: %s" % (len(jobs), jobs))
        logging.debug("   old pattern %s" % current_pattern)

        for job in jobs:
            # 2) Simulate the results for these jobs for the 'pattern'
            answer = simulate_handshake(job, pattern)
            # 3) Modify result
            current_pattern = set_ciphersuite_results_within_pattern(answer, current_pattern)

            # Just some debug print
            logging.debug("   job %s" % job)
            logging.debug("   answer %s" % answer)
            logging.debug("   new pattern %s" % current_pattern)

    logging.debug("Total connections: %d" % total_connections)

    return total_connections, request_rounds


def simulate_handshake(job, pattern):
    """
    Simulate a TLS handshake

    Return the first accepted or all rejected ciphersuites
    :param job: list of cipher suites to check
    :param pattern: pattern to check it for
    :return: list of tuples with cipher-suite and result
    """
    for cs in job:
        res = get_ciphersuite_result_for_pattern(cs, pattern)
        if res == 'a':
            return [(cs, 'a')]
    return [(cs, 'r') for cs in job]


def set_ciphersuite_results_within_pattern(results, current_pattern):
    """
    Apply "scan results" to a current pattern

    :param results: list of tuples (ciphersuite, answer-char)
    :param current_pattern: current pattern
    :return: new pattern
    """
    current_pattern = list(current_pattern)
    if len(current_pattern) == 7:
        mapping = MAPPING2
    else:
        mapping = MAPPING3

    for cs, r in results:
        current_pattern[mapping.index(cs)] = r

    return ''.join(current_pattern)


def get_ciphersuite_result_for_pattern(ciphersuite, pattern):
    """Return the result of a specific ciphersuite within a pattern
    """
    if len(pattern) == 7:
        return pattern[MAPPING2.index(ciphersuite)]
    else:
        return pattern[MAPPING3.index(ciphersuite)]


test_connections()
# estimate_connections_stats_algorithm('aa'+'r'*134, 2)