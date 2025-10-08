"""Continuous Monitoring Module for Zauriscore.

Monitors contract transactions in real-time, detects anomalies, and sends alerts.
"""

import asyncio
import logging
import json
from typing import Dict, Any, List
from datetime import datetime, timedelta

from web3 import Web3
from web3.exceptions import BadFunctionCallOutput

import sklearn.ensemble as ensemble
from sklearn.preprocessing import StandardScaler

# Assuming web3 provider is configured
w3 = None  # To be initialized with provider

logger = logging.getLogger(__name__)

class ContinuousMonitor:
    def __init__(self, contract_address: str, rpc_url: str = 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID'):
        """Initialize the continuous monitor."""
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.scaler = StandardScaler()
        self.isolation_forest = ensemble.IsolationForest(contamination=0.1, random_state=42)
        self.transaction_history: List[Dict[str, Any]] = []
        self.alert_thresholds = {
            'high_value_transfer': 1000000,  # Ether threshold
            'rapid_transactions': 10,  # Max tx per minute
            'anomaly_score': -0.5  # Isolation forest threshold
        }
        self.historical_features = []  # For ML training

    async def start_monitoring(self, from_block: int = None, interval: int = 60):
        """Start real-time monitoring loop."""
        if from_block is None:
            from_block = self.w3.eth.block_number - 1000  # Last 1000 blocks
        
        logger.info(f"Starting monitoring for {self.contract_address} from block {from_block}")
        
        while True:
            try:
                await self._scan_recent_blocks(from_block)
                from_block = self.w3.eth.block_number
                await self._detect_anomalies_and_alert()
                await asyncio.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(30)

    async def _scan_recent_blocks(self, start_block: int):
        """Scan recent blocks for transactions to the contract."""
        current_block = self.w3.eth.block_number
        for block_num in range(start_block + 1, current_block + 1):
            try:
                block = self.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block['transactions']:
                    if tx['to'] and tx['to'].lower() == self.contract_address.lower():
                        tx_data = await self._extract_features(tx)
                        self.transaction_history.append({
                            'tx_hash': tx['hash'].hex(),
                            'block': block_num,
                            'timestamp': datetime.fromtimestamp(block['timestamp']),
                            'gas_used': tx.get('gas', 0),
                            'value': self.w3.from_wei(tx.get('value', 0), 'ether'),
                            'from': tx['from'],
                            'features': tx_data
                        })
                        self.historical_features.append(tx_data)
            except Exception as e:
                logger.warning(f"Error scanning block {block_num}: {e}")

    def _extract_features(self, tx: Dict) -> List[float]:
        """Extract features for anomaly detection from transaction."""
        # Features: gas price, value, input data length, etc.
        features = [
            float(tx.get('gasPrice', 0)) / 1e9,  # Gwei
            float(self.w3.from_wei(tx.get('value', 0), 'ether')),
            len(tx.get('input', '0x')),  # Input data size
            float(tx.get('gas', 21000)) / 1e6,  # Gas in millions
            # Add more: nonce, chainId, etc.
        ]
        return features

    async def _detect_anomalies_and_alert(self):
        """Detect anomalies using Isolation Forest and generate alerts."""
        if len(self.transaction_history) < 10:
            return  # Need data
        
        recent_tx = self.transaction_history[-10:]  # Last 10 tx
        features = [tx['features'] for tx in recent_tx]
        
        # Scale features
        scaled_features = self.scaler.fit_transform(features)
        
        # Predict anomalies
        predictions = self.isolation_forest.fit_predict(scaled_features)
        anomaly_scores = self.isolation_forest.decision_function(scaled_features)
        
        alerts = []
        for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            tx = recent_tx[i]
            if pred == -1 or score < self.alert_thresholds['anomaly_score']:
                alerts.append(f"Anomaly detected in tx {tx['tx_hash']}: score {score:.3f}")
            
            # Rule-based alerts
            if tx['value'] > self.alert_thresholds['high_value_transfer']:
                alerts.append(f"High value transfer in tx {tx['tx_hash']}: {tx['value']} ETH")
            
            # Rapid transactions check
            recent_timestamps = [t['timestamp'] for t in self.transaction_history[-self.alert_thresholds['rapid_transactions']*2:]]
            time_diff = (recent_timestamps[0] - datetime.now()).total_seconds() / 60
            if len(recent_timestamps) >= self.alert_thresholds['rapid_transactions'] and time_diff < 1:
                alerts.append("Rapid transaction activity detected!")
        
        if alerts:
            await self._send_alerts(alerts)

    async def _send_alerts(self, alerts: List[str]):
        """Send alerts via email, webhook, or log."""
        for alert in alerts:
            logger.warning(f"ALERT: {alert}")
            # TODO: Integrate with notification service, e.g., Twilio, Slack
            # For now, just log
            print(f"🚨 {alert}")

    def update_model(self, new_data: List[List[float]]):
        """Update the anomaly detection model with new data."""
        if new_data:
            self.historical_features.extend(new_data)
            if len(self.historical_features) > 100:
                # Retrain periodically
                scaled_hist = self.scaler.fit_transform(self.historical_features[-100:])
                self.isolation_forest.fit(scaled_hist)

# Example usage
if __name__ == '__main__':
    monitor = ContinuousMonitor('0xContractAddressHere')
    asyncio.run(monitor.start_monitoring())