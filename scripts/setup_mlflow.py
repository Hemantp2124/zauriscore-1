#!/usr/bin/env python3
"""
MLflow Setup Script for ZauriScore

This script initializes MLflow tracking and provides utilities for managing experiments.
Run this before training models to ensure proper experiment tracking.

Usage:
    python scripts/setup_mlflow.py
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import mlflow
from mlflow.tracking import MlflowClient

def setup_mlflow():
    """Set up MLflow tracking for ZauriScore experiments."""

    # Set tracking URI to local mlruns directory (Windows-compatible)
    tracking_uri = './mlruns'
    mlflow.set_tracking_uri(tracking_uri)

    print(f"✅ MLflow tracking URI set to: {mlflow.get_tracking_uri()}")

    # Create MLflow client
    client = MlflowClient()

    # Create or get main experiment
    try:
        experiment = client.get_experiment_by_name('zauriscore_main')
        if experiment is None:
            experiment_id = client.create_experiment('zauriscore_main')
            print(f"✅ Created experiment 'zauriscore_main' with ID: {experiment_id}")
        else:
            experiment_id = experiment.experiment_id
            print(f"✅ Using existing experiment 'zauriscore_main' (ID: {experiment_id})")
    except Exception as e:
        print(f"⚠️ Could not create/get main experiment: {e}")

    # Create specific experiments for different training tasks
    experiments_to_create = [
        'zauriscore_exploit_fine_tune',
        'zauriscore_model_training',
        'zauriscore_hyperparameter_tuning'
    ]

    for exp_name in experiments_to_create:
        try:
            experiment = client.get_experiment_by_name(exp_name)
            if experiment is None:
                exp_id = client.create_experiment(exp_name)
                print(f"✅ Created experiment '{exp_name}' (ID: {exp_id})")
            else:
                print(f"✅ Experiment '{exp_name}' already exists (ID: {experiment.experiment_id})")
        except Exception as e:
            print(f"⚠️ Could not create experiment '{exp_name}': {e}")

def show_mlflow_info():
    """Display current MLflow configuration and recent runs."""

    print("\n📊 Current MLflow Configuration:")
    print(f"Tracking URI: {mlflow.get_tracking_uri()}")

    try:
        client = MlflowClient()
        experiments = client.search_experiments()

        print(f"\n🔬 Available Experiments ({len(experiments)}):")
        for exp in experiments:
            run_count = len(client.search_runs(exp.experiment_id))
            print(f"  - {exp.name} (ID: {exp.experiment_id}) - {run_count} runs")

        # Show recent runs across all experiments
        all_runs = client.search_runs(experiment_ids=[exp.experiment_id for exp in experiments], max_results=5)
        if all_runs:
            print(f"\n🏃 Recent Runs (last 5):")
            for run in all_runs:
                print(f"  - Run {run.info.run_id} in '{run.info.experiment_id}' - Status: {run.info.status}")
    except Exception as e:
        print(f"⚠️ Could not retrieve experiment info: {e}")

if __name__ == "__main__":
    print("🚀 Setting up MLflow for ZauriScore...")

    setup_mlflow()
    show_mlflow_info()

    print("\n✅ MLflow setup complete!")
    print("💡 You can now run training scripts and they will automatically log to MLflow.")
    print("🔍 View results with: mlflow ui")
    print("📈 Access programmatically with: mlflow.search_runs()")
