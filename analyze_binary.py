#!/usr/bin/env python3

import networkx as nx
from networkx.drawing.nx_agraph import (
    read_dot,
    from_agraph,
)
from networkx.convert import to_dict_of_lists
from networkx.algorithms.similarity import graph_edit_distance

import argparse
from pathlib import Path
import pygraphviz
import re
import r2pipe
import subprocess
import tempfile

# retdec install directory path
RETDEC_DIR = Path.home() / 'retdec-install'
assert(RETDEC_DIR.exists())

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


def strip_dead_code(binary, dirname):
    """
    Recompiles the binary with (hopefully) all dead code stripped out by clang's
    optimization.

    Args:
        binary (string): file path for the binary
        dirname (string): directory to work in

    Returns:
        path to new stripped binary as a string
    """
    # decompile binary using retdec
    src_path = Path(dirname) / 'src.cpp'
    decompile_cmd = f"python3 {RETDEC_DIR / 'bin/retdec-decompiler.py'} -l c {binary} -o {src_path}"
    subprocess.run(decompile_cmd, shell=True, check=True)

    # prepend decompiled source with contents of retdec_functions.c
    with src_path.open(mode='r+') as src_file:
        src = src_file.read()
        with open('retdec_functions.c', 'r') as f:
            retdec_functions = f.read()
        src = ''.join((retdec_functions, src))
        src_file.seek(0)
        src_file.truncate()
        src_file.write(src.lstrip())

    # debug
    subprocess.run(f'cat {src_path}', shell=True, check=True)

    # recompile a new binary with max optimization level to eliminate dead code
    stripped_path = Path(dirname) / 'stripped'
    subprocess.run(f'gcc -m32 -fpermissive {src_path} -S -O3 -o {stripped_path}',
                   shell=True, check=True)
    return str(stripped_path)


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
    with tempfile.TemporaryDirectory() as dirname:
        # get a new binary with dead code removed
        binary = strip_dead_code(binary, dirname)

        # run Radare2 on the binary to get dotfile contents
        radare_pipe = r2pipe.open(binary)
        radare_pipe.cmd('aaaaa')
        dotContents = radare_pipe.cmd('agfd')
        dot_path = Path(dirname) / f'{binary}.dot'
        with (dot_path).open(mode='w+') as f:
            f.write(dotContents)
        subprocess.run(f'dot -Tpng {dot_path} -o {binary}.png',
                       shell=True, check=True)

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


def main(old_graph_path, new_graph_path):
    print(graph_edit_distance(
        create_graph(old_graph_path),
        create_graph(new_graph_path),
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
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', nargs=2, required=False,
                        default=['tests/forkbomb/forkbomb_v1',
                                 'tests/forkbomb/forkbomb_v2'])

    args = parser.parse_args()
    main(args.g[0], args.g[1])
