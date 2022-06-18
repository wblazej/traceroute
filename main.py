import argparse
from igraph import Graph, plot

from src.traceroute import Traceroute
from src.config import Config


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination_server')
    args = parser.parse_args()

    trace = Traceroute(
        destination_server=args.destination_server, 
        timeout=Config.TIMEOUT, 
        packet_size=Config.PACKET_SIZE, 
        max_hops=Config.MAX_HOPS)

    result = trace.start_traceroute()

    g = Graph(directed=True)
    g.add_vertices(len(result))

    for i, r in enumerate(result):
        g.vs[i]["id"] = i
        g.vs[i]["label"] = f'{r.hostname}\n{r.ip}' if not r.timeout else 'timeout'

    g.add_edges([(i, i + 1) for i in range(len(result) - 1)])

    g.es['label_size'] = 20
    g.es['label'] = [r.delay_ms for r in result]
    g.vs['color'] = '#fff'

    plot(g, "result.png", bbox=(1500, 1500), margin=200, vertex_size=200, vertex_label_size=15, layout=g.layout_lgl())

    [print(r) for r in result]