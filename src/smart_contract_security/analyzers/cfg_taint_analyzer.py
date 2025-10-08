# CFG and Taint Analyzer for Solidity Contracts

from typing import Any, Dict, List, Tuple

import json
import networkx as nx
from .slither_utils import SlitherUtils

class CFGTAintAnalyzer:
    """
    Analyzer for extracting Control Flow Graphs (CFG) and performing taint analysis
    on Solidity contracts using Slither. Integrates with ML models for feature extraction.
    """

    def __init__(self, contract_path: str, contract_name: str = None):
        self.contract_path = contract_path
        self.contract_name = contract_name
        self.slither = SlitherUtils.init_slither(contract_path)
        self.cfg_graphs: Dict[str, nx.DiGraph] = {}
        self.taint_results: Dict[str, List[str]] = {}

    def extract_cfg(self) -> Dict[str, nx.DiGraph]:
        """
        Extract Control Flow Graphs for all functions in the contract.
        :return: Dictionary of function names to their CFG graphs.
        """
        self.cfg_graphs = SlitherUtils().extract_cfg(self.slither)
        return self.cfg_graphs

    def perform_taint_analysis(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Perform taint analysis to track data flows from user inputs to sensitive operations.
        :return: Dictionary of function names to list of tainted operations.
        """
        self.taint_results = SlitherUtils().perform_basic_taint_analysis(self.slither)
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

    def analyze_contract(self, contract_address: str, source_code: str) -> Dict[str, Any]:
        """
        Perform full analysis: CFG extraction, taint analysis, ML features, and compute vulnerability score.
        :param contract_address: Ethereum contract address.
        :param source_code: Solidity source code.
        :return: Comprehensive analysis results including vulnerability score.
        """
        self.source_code = source_code  # Store source for potential use

        cfg_graphs = self.extract_cfg()
        taint_results = self.perform_taint_analysis()
        ml_features = self.generate_features_for_ml()

        # Simple vulnerability score based on taint density and graph complexity
        total_taint_ops = sum(len(taints) for taints in taint_results.values())
        total_nodes = sum(graph.number_of_nodes() for graph in cfg_graphs.values())
        vulnerability_score = (total_taint_ops / total_nodes) if total_nodes > 0 else 0
        vulnerability_score *= 10  # Scale to 0-10

        return {
            'cfg_graphs': cfg_graphs,
            'taint_results': taint_results,
            'ml_features': ml_features,
            'vulnerability_score': vulnerability_score,
            'contract_address': contract_address
        }

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
    analyzer = CFGTAintAnalyzer("path/to/contract.sol", "MyContract")
    analyzer.extract_cfg()
    analyzer.perform_taint_analysis()
    features = analyzer.generate_features_for_ml()
    analyzer.save_analysis_results("cfg_taint_results.json")
    print("CFG and Taint analysis completed.")