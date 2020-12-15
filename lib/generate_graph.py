from igraph import Graph, plot

# libs
from lib.colors import Colors


class GenerateGraph:
    def __init__(self, data, filename):
        self.filename = filename
        self.delays = []
        self.gg = []
        self.colors = ['#fff']

        for i in range(len(data)):
            self.gg.append([i + 1])
            delay = data[i]['delay']
            self.delays.append(delay)

            float_delay = float(delay.replace('ms', ''))
            STEP = 10

            if float_delay < 1 * STEP:
                self.colors.append(Colors.VERY_GOOD)
            elif float_delay < 2 * STEP:
                self.colors.append(Colors.GOOD)
            elif float_delay < 3 * STEP:
                self.colors.append(Colors.OK)
            elif float_delay < 4 * STEP:
                self.colors.append(Colors.BAD)
            else: self.colors.append(Colors.VERY_BAD)

        self.gg.append([])

    def run(self):
        g = Graph(directed=True)
        g.add_vertices(len(self.gg))

        # Add ids and labels to vertices
        for i in range(len(self.gg)):
            g.vs[i]["id"] = i
            g.vs[i]["label"] = str(i)

        # Add edges
        edges = []
        for i in range(len(self.gg)):
            for c in self.gg[i]:
                edges.append((i, c))
        g.add_edges(edges)

        g.es['weight'] = self.delays
        g.es['label_size'] = 15
        g.es['label'] = self.delays

        g.vs['color'] = self.colors

        # STYLE
        visual_style = {}
        out_name = self.filename  # Set bbox and margin
        visual_style['bbox'] = (1000, 1000)
        visual_style['margin'] = 50  # Set vertex colours
        visual_style['vertex_size'] = 50  # Set vertex lable size
        visual_style['vertex_label_size'] = 20  # Don't curve the edges
        visual_style['edge_curved'] = False  # Set the layout
        my_layout = g.layout_lgl()
        visual_style['layout'] = my_layout  # Plot the graph
        plot(g, out_name, **visual_style)

        return {
            "ok": True,
            "message": "graph has been generated succesfuly"
        }