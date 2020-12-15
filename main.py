from random import randint
import sys
import argparse

# libs
from lib.traceroute import Traceroute
from lib.generate_graph import GenerateGraph


if __name__ == '__main__':
    # get destination_server as arguemnt
    parser = argparse.ArgumentParser()
    parser.add_argument('destination_server')
    args = parser.parse_args(sys.argv[1:])
    destination_server = args.destination_server

    # settings
    timeout = 1000
    packet_size = 52
    max_hops = 64

    # get traceroute
    trace = Traceroute(destination_server=destination_server, timeout=timeout, packet_size=packet_size, max_hops=max_hops)
    result = trace.start_traceroute()

    # handle error
    if type(result) == str:
        print(f'ERROR: {result}')
        sys.exit()

    # generate traceroute graph
    gg = GenerateGraph(result, 'traceroute.png')
    res = gg.run()

    # stop if something went wrong
    if not res['ok']:
        print(res['message'])
        sys.exit()

    # print graph legend
    print('Graph legend:', end='\n\n')
    print(' 0 -- your computer')
    for i in range(len(result)):
        prefix = ''
        if i + 1 < 10:
            prefix = ' '
        if not result[i]['timeout']:
            print(f'{prefix}{i + 1} -- {result[i]["host"]} ({result[i]["ip"]}) -- {result[i]["delay"]}')
        else: print(f'{prefix}{i + 1} timeout')