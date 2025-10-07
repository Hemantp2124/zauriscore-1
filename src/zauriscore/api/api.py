from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

# Custom modules
from ..reporting.consolidated_report_generator import create_report_generator

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Paths and configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, '..', 'reports')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
app.config['REPORTS_DIR'] = REPORTS_DIR

# Ensure required directories exist
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Logging setup
log_path = os.path.join(LOGS_DIR, 'app.log')
file_handler = RotatingFileHandler(log_path, maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_contract():
    """
    Analyzes a smart contract given an Ethereum address.
    Expects JSON payload: { "contract_address": "0x..." }
    """
    data = request.get_json()
    if not data or 'contract_address' not in data:
        return jsonify({'error': 'Missing contract_address in JSON payload'}), 400

    contract_address = data['contract_address']
    if not (contract_address.startswith('0x') and len(contract_address) == 42):
        return jsonify({'error': 'Invalid Ethereum contract address format'}), 400

    api_key = os.getenv("ETHERSCAN_API_KEY")
    if not api_key:
        return jsonify({'error': 'Etherscan API key is missing in environment variables'}), 500

    app.logger.info(f"Analyzing contract: {contract_address}")

    try:
        generator = create_report_generator()
        result = generator.generate_contract_report(contract_address, api_key, app.config['REPORTS_DIR'])

        if isinstance(result, tuple) and len(result) == 2:
            report_path_json, report_path_md = result
        else:
            raise ValueError("Unexpected result format from generate_contract_report.")

        if os.path.exists(report_path_json):
            with open(report_path_json, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            return jsonify({
                'report': report_data,
                'json_report_url': f'/download/{os.path.basename(report_path_json)}',
                'markdown_report_url': f'/download/{os.path.basename(report_path_md)}'
            }), 200
        else:
            return jsonify({'error': 'Report generation failed or file missing'}), 500

    except Exception as e:
        app.logger.error(f"Error during analysis for {contract_address}: {str(e)}", exc_info=True)
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/download/<filename>')
def download_report(filename):
    """
    Serves generated report files (JSON or Markdown) for download.
    """
    return send_from_directory(app.config['REPORTS_DIR'], filename, as_attachment=True)

if __name__ == '__main__':
    if not os.getenv("ETHERSCAN_API_KEY"):
        print("⚠️  ETHERSCAN_API_KEY not found in environment. Please set it in your .env file.")
    app.run(debug=True, port=5001)
