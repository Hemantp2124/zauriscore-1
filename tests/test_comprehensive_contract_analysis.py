"""Unit tests for ComprehensiveContractAnalyzer, focusing on Mythril integration and weighted scoring."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import tempfile
from pathlib import Path

from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer
from zauriscore.analyzers.mythril_analyzer import MythrilAnalyzer
from zauriscore.analyzers.gas_optimization_analyzer import GasOptimizationAnalyzer


class TestComprehensiveContractAnalyzer:
    @pytest.fixture
    def analyzer(self):
        with patch('zauriscore.analyzers.comprehensive_contract_analysis.GasOptimizationAnalyzer') as MockGas, \
             patch('zauriscore.analyzers.comprehensive_contract_analysis.MythrilAnalyzer') as MockMythril, \
             patch('zauriscore.analyzers.comprehensive_contract_analysis.Slither'):
            mock_gas = MockGas.return_value
            mock_gas.analyze.return_value = {'gas_score': 0.8, 'optimizations': []}
            
            mock_mythril = MockMythril.return_value
            mock_mythril.analyze.return_value = {
                'vulnerabilities': [],
                'mythril_score': 0.7,
                'summary': 'Mock Mythril summary'
            }
            
            # Mock Slither
            mock_slither = Mock()
            mock_slither.run_detectors.return_value = {'detectors': [], 'slither_score': 0.6}
            
            # Mock ML (CodeBERT)
            with patch('zauriscore.analyzers.comprehensive_contract_analysis.model_from_pretrained'):
                analyzer = ComprehensiveContractAnalyzer()
                analyzer.slither = mock_slither
                analyzer.ml_model = Mock(predict=Mock(return_value=0.75))
                yield analyzer

    def test_compute_trust_risk_score_basic(self, analyzer):
        """Test basic weighted risk score computation."""
        
        # Mock individual scores
        overall_score = 0.7  # security
        gas_optimization = 0.8  # gas
        historical_data = {'tx_count': 1000, 'reputation_index': 0.9}  # historical
        
        result = analyzer._compute_trust_risk_score(
            overall_score=overall_score,
            gas_optimization=gas_optimization,
            historical_data=historical_data
        )
        
        assert isinstance(result, dict)
        assert 'risk_score' in result
        assert 'reputation_index' in result
        assert 0 <= result['risk_score'] <= 1
        # Weighted: 0.5*security + 0.3*gas + 0.2*historical ~ 0.74
        assert 0.7 < result['risk_score'] < 0.8

    @patch('subprocess.run')
    def test_mythril_integration(self, mock_subprocess, analyzer):
        """Test Mythril analysis integration."""
        
        mock_output = Mock()
        mock_output.returncode = 0
        mock_output.stdout = json.dumps({
            'issues': [
                {'severity': 'medium', 'description': 'Mock issue'}
            ]
        }).encode()
        mock_subprocess.return_value = mock_output
        
        mythril = MythrilAnalyzer()
        result = mythril.analyze('mock_sol_file.sol')
        
        assert result['mythril_score'] is not None
        assert isinstance(result['vulnerabilities'], list)
        assert mock_subprocess.called

    def test_weighted_overall_score(self, analyzer):
        """Test computation of weighted overall score from Slither, Mythril, ML."""
        
        # Mock analyzer results
        analyzer.slither_score = 0.6
        analyzer.mythril_score = 0.7
        analyzer.ml_score = 0.75
        
        with patch.object(analyzer, '_compute_weighted_score'):
            result = analyzer.analyze_contract('0xmock')
            
        assert 'overall_score' in result
        # Weighted: e.g., 0.4*slither + 0.3*mythril + 0.3*ml ~ 0.68
        assert 0.6 < result['overall_score'] < 0.8

    def test_full_analyze_contract_mocks(self, analyzer):
        """Test full analyze_contract with all mocks in place."""
        
        result = analyzer.analyze_contract(contract_address='0x1234567890123456789012345678901234567890')
        
        assert isinstance(result, dict)
        assert 'slither_score' in result
        assert 'mythril_score' in result
        assert 'ml_score' in result
        assert 'overall_score' in result
        assert 'risk_score' in result
        assert len(result['vulnerabilities']) >= 0  # Combined vulns

    def test_error_handling_no_source(self, analyzer):
        """Test error handling when source code fetch fails."""
        
        with patch('zauriscore.analyzers.comprehensive_contract_analysis._fetch_contract_source_v2') as mock_fetch:
            mock_fetch.return_value = None
            
            result = analyzer.analyze_contract('0xinvalid')
            
        assert 'error' in result
        assert 'Source not found' in result['error']

    def test_proxy_detection(self, analyzer):
        """Test proxy pattern detection using Slither mocks."""
        
        # Mock Slither to detect proxy
        mock_contract = MagicMock()
        mock_contract.is_proxy = True
        mock_contract.detectors = {'unprotected-upgradeable-contract': {'impact': 'high'}}
        analyzer.slither.contracts = [mock_contract]
        
        mock_slither = Mock()
        mock_slither.run_detectors.return_value = {
            'detectors': [{'name': 'proxy', 'description': 'Transparent proxy detected'}],
            'slither_score': 0.5
        }
        analyzer.slither = mock_slither
        
        result = analyzer.analyze_contract('0xproxy')
        
        assert 'proxy_detected' in result
        assert result['proxy_detected'] == True
        assert 'upgrade_safety_score' in result
        assert len(result['vulnerabilities']) > 0  # Includes proxy-related issues

    def test_upgrade_safety_scoring(self, analyzer):
        """Test upgrade safety scoring and storage collision flagging."""
        
        # Mock contract with state variables for storage collision risk
        mock_contract = MagicMock()
        mock_contract.state_variables = ['var1', 'var2', 'var3']  # 3 vars > threshold
        mock_contract.is_upgradeable = True
        analyzer.slither.contracts = [mock_contract]
        
        mock_slither = Mock()
        mock_slither.run_detectors.return_value = {
            'detectors': [{'name': 'unprotected-upgrade', 'impact': 'medium'}],
            'slither_score': 0.6
        }
        analyzer.slither = mock_slither
        
        # Mock overall_score for trust risk computation
        with patch.object(analyzer, '_compute_weighted_score', return_value=0.7):
            with patch.object(analyzer, '_extract_features', return_value={'num_state_vars': 3}):
                result = analyzer.analyze_contract('0xupgradeable')
        
        assert 'upgrade_safety_score' in result
        assert 0 <= result['upgrade_safety_score'] <= 1
        assert 'storage_collision_risk' in result
        assert result['storage_collision_risk'] == 'high'  # Due to >2 state vars
        assert 'risk_score' in result  # Includes upgrade safety in weighting

    def test_integration_proxy_upgrade_flow(self, analyzer):
        """Integration test for full flow with upgradeable proxy contract."""
        
        # Mock full Slither response with proxy and upgrade detections
        mock_slither = Mock()
        mock_slither.run_detectors.return_value = {
            'detectors': [
                {'name': 'transparent-proxy', 'description': 'Transparent proxy pattern'},
                {'name': 'uups-proxy', 'description': 'UUPS proxy detected'}  # If applicable
            ],
            'slither_score': 0.55
        }
        mock_contract = MagicMock()
        mock_contract.is_proxy = True
        mock_contract.is_upgradeable = True
        mock_slither.contracts = [mock_contract]
        analyzer.slither = mock_slither
        
        # Mock other components to focus on new features
        analyzer.mythril_score = 0.7
        analyzer.ml_score = 0.75
        
        result = analyzer.analyze_contract('0xintegration')
        
        assert result['proxy_detected'] == True
        assert result['is_upgradeable'] == True
        assert 'upgrade_safety_score' in result
        assert 'storage_collision_risk' in result
        assert 'overall_score' in result  # Weighted including new scores
        assert len(result['vulnerabilities']) >= 2  # Proxy and upgrade issues


    @patch('zauriscore.analyzers.comprehensive_contract_analysis.requests.get')
    def test_multi_chain_source_fetch(self, mock_get, analyzer):
        """Test source code fetching for multi-chain support (Polygon, Arbitrum, Optimism)."""
        
        # Mock successful response for Polygon
        mock_response_polygon = Mock()
        mock_response_polygon.json.return_value = {
            'status': '1',
            'result': [{
                'SourceCode': 'pragma solidity ^0.8.0; contract Mock {}',
                'ABI': '[]',
                'ContractName': 'Mock'
            }]
        }
        mock_response_polygon.status_code = 200
        mock_get.return_value = mock_response_polygon
        
        # Test Polygon fetch
        source_polygon = analyzer.get_contract_source('0x123', chain='polygon')
        assert 'pragma solidity' in source_polygon
        assert mock_get.call_args[1]['url'].endswith('polygonscan.com/api')
        
        # Mock for Arbitrum
        mock_response_arbitrum = Mock()
        mock_response_arbitrum.json.return_value = {
            'status': '1',
            'result': [{
                'SourceCode': 'pragma solidity ^0.8.0; contract MockArbitrum {}',
                'ABI': '[]',
                'ContractName': 'MockArbitrum'
            }]
        }
        mock_response_arbitrum.status_code = 200
        mock_get.side_effect = [mock_response_polygon, mock_response_arbitrum]
        
        source_arbitrum = analyzer.get_contract_source('0x456', chain='arbitrum')
        assert 'MockArbitrum' in source_arbitrum
        
        # Test unsupported chain error
        with pytest.raises(ValueError, match='Unsupported chain'):
            analyzer.get_contract_source('0x789', chain='bitcoin')

    @patch('zauriscore.analyzers.comprehensive_contract_analysis.requests.get')
    def test_multi_chain_tx_count(self, mock_get, analyzer):
        """Test transaction count fetching across chains."""
        
        # Mock Ethereum tx count
        mock_eth_response = Mock()
        mock_eth_response.json.return_value = {'status': '1', 'result': '1000'}
        mock_eth_response.status_code = 200
        mock_get.return_value = mock_eth_response
        
        tx_eth = analyzer.get_transaction_count('0x123')
        assert tx_eth == 1000
        
        # Mock Polygon tx count
        mock_polygon_response = Mock()
        mock_polygon_response.json.return_value = {'status': '1', 'result': '500'}
        mock_polygon_response.status_code = 200
        mock_get.side_effect = [mock_eth_response, mock_polygon_response]
        
        tx_polygon = analyzer.get_transaction_count('0x456', chain='polygon')
        assert tx_polygon == 500
        assert mock_get.call_args[1]['url'].endswith('polygonscan.com/api')
        
        # Mock error response
        mock_error = Mock()
        mock_error.status_code = 404
        mock_get.return_value = mock_error
        
        with pytest.raises(Exception):
            analyzer.get_transaction_count('0xinvalid', chain='optimism')

    def test_multi_chain_analysis_integration(self, analyzer):
        """Integration test for full analysis on a multi-chain contract (e.g., Polygon)."""
        
        # Mock source fetch for Polygon
        with patch.object(analyzer, 'get_contract_source') as mock_source, \
             patch.object(analyzer, 'get_transaction_count') as mock_tx:
            
            mock_source.return_value = 'pragma solidity ^0.8.0; contract PolygonMock {}'
            mock_tx.return_value = 200
            
            # Mock Slither for multi-chain
            mock_slither = Mock()
            mock_slither.contracts[0].is_proxy = False
            mock_slither.run_detectors.return_value = {'slither_score': 0.8}
            analyzer.slither = mock_slither
            
            # Mock other analyzers
            analyzer.ml_score = 0.85
            analyzer.mythril_score = 0.9
            
            result = analyzer.analyze_contract('0xpoly', chain='polygon')
            
        assert result['chain'] == 'polygon'
        assert 'tx_count' in result
        assert result['tx_count'] == 200
        assert 'overall_score' in result
        assert 0.7 < result['overall_score'] < 0.9  # Weighted score
        assert 'slither_score' in result
        assert result['vulnerabilities'] == []  # No issues in mock