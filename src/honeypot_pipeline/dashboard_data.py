"""Compatibility wrapper for dashboard data loading helpers."""

from .api.dashboard_data import DashboardDataset, filter_records, load_dataset, load_records

__all__ = ["DashboardDataset", "filter_records", "load_dataset", "load_records"]

