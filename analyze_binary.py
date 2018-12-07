import networkx as nx
from networkx.drawing.nx_agraph import (
    read_dot,
    from_agraph,
)
from networkx.convert import to_dict_of_lists
from networkx.algorithms.similarity import graph_edit_distance

import pygraphviz
import re
import r2pipe

# read, write, chmod, pipe, socket, open, close, kill, fork
caught_syscalls = [
    'read',
    'write',
    'open',
    'close',
    'chmod',
    'pipe',
    'socket',
    'kill',
    'fork'
]

def create_graph(binary):
    """
    Adds syscall nodes into the graph generated from the passed in binary and then
    links the syscall nodes to the according nodes that call the syscall

    Args:
        binary (string): file path for the binary

    Returns:
        MultiDiGraph with node format as follows -
            nodename is a string
            node values include 'label' (assembly instructions) and 'shape' = 'record'
    """

    # run Radare2 on the binary to get dotfile contents
    radare_pipe = r2pipe.open(binary)
    radare_pipe.cmd('aaaaa')
    dotContents = r.cmd('agfd')

    graph = from_agraph(pygraphviz.AGraph(dotContents))

    # add syscall nodes
    for syscall_name in caught_syscalls:
        node_name = 'syscall_{}'.format(syscall_name)
        graph.add_node(
            node_name,
            label='syscall {}'.format(syscall_name),
            shape='record'
        )

    # link syscall nodes to original nodes
    for node_name, node_info in graph.nodes.items():
        # skip over our added syscall nodes
        if 'syscall_' in node_name:
            continue

        instructions = node_info.get('label')

        for syscall_name in caught_syscalls:
            instr_regex = r"call\s.*sys.imp.{}".format(syscall_name)

            if re.search(instr_regex, instructions):
                # connect the syscall node to this node
                syscall_node_name = 'syscall_{}'.format(syscall_name)
                graph.add_edge(syscall_node_name, node_name)

    return graph


def main():
    graph = create_graph('test_programs/read_test')


if __name__ == "__main__":
    main()

