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
    dotContents = radare_pipe.cmd('agfd')

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
            instr_regex = r"call\s.*sym.imp.{}".format(syscall_name)

            if re.search(instr_regex, instructions):
                # connect the syscall node to this node
                syscall_node_name = 'syscall_{}'.format(syscall_name)
                graph.add_edge(
                    syscall_node_name,
                    node_name,
                    weight=10
                )

    return graph


# HEURISTICS
def node_match(graph1_node, graph2_node):
    """
    Return True if the two nodes should be considered equivalent,
    otherwise returns False

    Only matches syscall nodes to each other
    """
    if 'syscall' not in graph1_node.get('label'):
        return False

    return graph1_node.get('label') == graph2_node.get('label')


def edge_match(graph1_edge, graph2_edge):
    """
    Return True if the two edges should be considered equivalent,
    otherwise return False
    """
    pass


def node_del_cost(graph_node):
    """
    Return the cost of deleting a node from the graph
    """
    return 0


def node_ins_cost(graph_node):
    """
    Return the cost of inserting a node into the graph
    """
    return 0


def node_subst_cost(graph1_node, graph2_node):
    """
    Return the cost of substituting one node for another
    """
    return node_del_cost(graph1_node) + node_del_cost(graph2_node)


def edge_del_cost(graph_edge):
    """
    Return the cost of deleting an edge from the graph
    """
    return 0


def edge_ins_cost(graph_edge):
    """
    Return the cost of inserting an edge into a graph
    """
    return graph_edge.get('weight') if graph_edge.get('weight') else 1


def edge_subst_cost(graph1_edge, graph2_edge):
    """
    Return the cost of substituting one edge for another
    """
    return edge_del_cost(graph1_edge) + edge_ins_cost(graph2_edge)


def compare_graphs(old_graph, new_graph):
    """
    Return whether the graphs are effectively the same or not
    """
    return 0


def main():
    old_graph = create_graph('tests/forkbomb/forkbomb_v1')
    new_graph = create_graph('tests/forkbomb/forkbomb_v2')

    print(graph_edit_distance(
        old_graph,
        new_graph,
        node_match=node_match,
        edge_match=edge_match,
        node_subst_cost=node_subst_cost,
        node_del_cost=node_del_cost,
        node_ins_cost=node_ins_cost,
        edge_subst_cost=edge_subst_cost,
        edge_del_cost=edge_del_cost,
        edge_ins_cost=edge_ins_cost,
    ))


if __name__ == "__main__":
    main()

