# CFG and Taint Analyzer for Solidity Contracts

import slither

from slither.core.cfg import Node
from slither.slithir.operations import LibraryCall, InternalCall
from slither.slithir.variables import Constant

import json
import networkx as nx
from typing import Dict, List, Tuple

class CFGTAintAnalyzer:
    """
    Analyzer for extracting Control Flow Graphs (CFG) and performing taint analysis
    on Solidity contracts using Slither. Integrates with ML models for feature extraction.
    """

    def __init__(self, contract_path: str):
        """
        Initialize the analyzer with the contract file path.
        :param contract_path: Path to the Solidity contract file.
        """
        self.slither = slither.Slither(contract_path)
        self.cfg_graphs: Dict[str, nx.DiGraph] = {}
        self.taint_results: Dict[str, List[str]] = {}

    def extract_cfg(self) -> Dict[str, nx.DiGraph]:
        """
        Extract Control Flow Graphs for all functions in the contract.
        :return: Dictionary of function names to their CFG graphs.
        """
        for contract in self.slither.contracts:
            for function in contract.functions_declared:
                func_name = f"{contract.name}.{function.full_name}"
                graph = nx.DiGraph()

                # Build CFG nodes and edges
                for node in function.nodes:
                    graph.add_node(node.node_id, statement=str(node.expression), lineno=node.source_mapping.lineno)

                for node in function.nodes:
                    for son in node.sons:
                        graph.add_edge(node.node_id, son.node_id)

                self.cfg_graphs[func_name] = graph

        return self.cfg_graphs

    def perform_taint_analysis(self) -> Dict[str, List[str]]:
        """
        Perform taint analysis to track data flows from user inputs to sensitive operations.
        :return: Dictionary of function names to tainted paths.
        """
        taint_paths = {}

        for contract in self.slither.contracts:
            for function in contract.functions_declared:
                func_name = f"{contract.name}.{function.full_name}"
                tainted_vars = set()
                tainted_operations = []

                # Simple taint propagation: track user inputs (msg.sender, msg.value, etc.)
                for node in function.nodes:
                    if isinstance(node.expression, LibraryCall) and 'msg.sender' in str(node.expression) or 'msg.value' in str(node.expression):
                        tainted_vars.add(str(node.expression))

                    # Propagate taint through assignments and calls
                    if node.expression and '=' in str(node.expression):
                        if any(var in str(node.expression) for var in tainted_vars):
                            tainted_vars.add(str(node.expression.split('=')[0].strip()))

                    # Detect taint reaching sensitive ops (e.g., transfers, calls)
                    if isinstance(node.expression, (LibraryCall, InternalCall)) and any(sens in str(node.expression) for sens in ['transfer', 'send', 'call', 'delegatecall']):
                        if any(var in str(node.expression) for var in tainted_vars):
                            tainted_operations.append({
                                'node_id': node.node_id,
                                'operation': str(node.expression),
                                'tainted_from': list(tainted_vars)
                            })

                self.taint_results[func_name] = tainted_operations

        return self.taint_results

    def generate_features_for_ml(self) -> Dict[str, Dict]:
        """
        Generate features from CFG and taint analysis for ML model input.
        Features include: graph metrics, taint paths, vulnerability indicators.
        :return: Dictionary of features per function.
        """
        features = {}

        for func_name, graph in self.cfg_graphs.items():
            graph_features = {
                'num_nodes': graph.number_of_nodes(),
                'num_edges': graph.number_of_edges(),
                'avg_degree': sum(d for n, d in graph.degree()) / len(graph),
                'density': nx.density(graph),
                'longest_path': nx.dag_longest_path_length(graph) if nx.is_directed_acyclic_graph(graph) else 0,
                'num_tainted_ops': len(self.taint_results.get(func_name, []))
            }

            if func_name in self.taint_results:
                graph_features['taint_ratios'] = len(self.taint_results[func_name]) / graph.number_of_nodes() if graph.number_of_nodes() > 0 else 0
                graph_features['sensitive_taint_paths'] = [op['tainted_from'] for op in self.taint_results[func_name]]

            features[func_name] = graph_features

        return features

    def save_analysis_results(self, output_path: str):
        """
        Save CFG graphs, taint results, and ML features to JSON.
        :param output_path: Path to save the results.
        """
        results = {
            'cfg_graphs': {name: {'nodes': list(graph.nodes(data=True)), 'edges': list(graph.edges())} for name, graph in self.cfg_graphs.items()},
            'taint_results': self.taint_results,
            'ml_features': self.generate_features_for_ml()
        }

        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

# Example usage
if __name__ == "__main__":
    analyzer = CFGTAintAnalyzer("path/to/contract.sol")
    analyzer.extract_cfg()
    analyzer.perform_taint_analysis()
    features = analyzer.generate_features_for_ml()
    analyzer.save_analysis_results("cfg_taint_results.json")
    print("CFG and Taint analysis completed.")