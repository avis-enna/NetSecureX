"""
CVE Lookup Widget for NetSecureX
================================

GUI widget for CVE vulnerability lookup and display with full functionality.
"""

import asyncio
import json
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QTableWidget,
    QTableWidgetItem, QGroupBox, QComboBox, QProgressBar,
    QMessageBox, QFileDialog, QHeaderView, QSplitter,
    QScrollArea, QFrame, QCheckBox
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor

from core.cve_lookup import CVELookup


class CVEWorker(QThread):
    """Worker thread for CVE lookup operations."""

    # Signals
    progress_updated = Signal(int)
    result_ready = Signal(list)
    error_occurred = Signal(str)
    finished = Signal()

    def __init__(self, query, severity_filter=None, year_filter=None):
        super().__init__()
        self.query = query
        self.severity_filter = severity_filter
        self.year_filter = year_filter
        self.cve_lookup = None

    def run(self):
        """Run CVE lookup in background thread."""
        try:
            self.cve_lookup = CVELookup()

            # Run async CVE lookup
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            results = loop.run_until_complete(
                self.cve_lookup.search_cves(
                    query=self.query,
                    severity_filter=self.severity_filter,
                    year_filter=self.year_filter
                )
            )

            loop.close()
            self.result_ready.emit(results)

        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.finished.emit()


class CVELookupWidget(QWidget):
    """Enhanced CVE lookup widget with full functionality."""

    def __init__(self):
        super().__init__()
        self.cve_worker = None
        self.current_results = []
        self.setup_ui()

        # Auto-refresh timer for real-time updates
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.auto_refresh)
        self.auto_refresh_enabled = False
        
    def setup_ui(self):
        """Setup enhanced CVE lookup interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Create splitter for search and results
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)

        # Search section
        search_section = self.create_search_section()
        splitter.addWidget(search_section)

        # Results section
        results_section = self.create_results_section()
        splitter.addWidget(results_section)

        # Set splitter proportions
        splitter.setSizes([200, 600])

    def create_search_section(self):
        """Create search input and configuration section."""
        group = QGroupBox(">>> CVE VULNERABILITY SEARCH")
        group.setStyleSheet("QGroupBox { font-weight: bold; }")
        layout = QVBoxLayout(group)

        # Search input row
        search_layout = QHBoxLayout()

        search_layout.addWidget(QLabel("TARGET:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("CVE-2023-1234, nginx, apache, kernel...")
        self.search_input.returnPressed.connect(self.search_cves)
        search_layout.addWidget(self.search_input)

        self.search_button = QPushButton("SCAN")
        self.search_button.clicked.connect(self.search_cves)
        search_layout.addWidget(self.search_button)

        layout.addLayout(search_layout)

        # Options row
        options_layout = QHBoxLayout()

        options_layout.addWidget(QLabel("SEVERITY:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        options_layout.addWidget(self.severity_combo)

        options_layout.addWidget(QLabel("YEAR:"))
        self.year_combo = QComboBox()
        current_year = datetime.now().year
        years = ["ALL"] + [str(year) for year in range(current_year, current_year-10, -1)]
        self.year_combo.addItems(years)
        options_layout.addWidget(self.year_combo)

        # Real-time monitoring
        self.auto_refresh_check = QCheckBox("AUTO-REFRESH")
        self.auto_refresh_check.toggled.connect(self.toggle_auto_refresh)
        options_layout.addWidget(self.auto_refresh_check)

        options_layout.addStretch()

        # Export button
        self.export_button = QPushButton("EXPORT")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        options_layout.addWidget(self.export_button)

        layout.addLayout(options_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        return group

    def create_results_section(self):
        """Create results display section."""
        group = QGroupBox(">>> VULNERABILITY DATABASE RESULTS")
        group.setStyleSheet("QGroupBox { font-weight: bold; }")
        layout = QVBoxLayout(group)

        # Statistics row
        stats_layout = QHBoxLayout()

        self.total_label = QLabel("TOTAL: 0")
        self.total_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        stats_layout.addWidget(self.total_label)

        self.critical_label = QLabel("CRITICAL: 0")
        self.critical_label.setStyleSheet("font-weight: bold; color: #ff0000;")
        stats_layout.addWidget(self.critical_label)

        self.high_label = QLabel("HIGH: 0")
        self.high_label.setStyleSheet("font-weight: bold; color: #ff8800;")
        stats_layout.addWidget(self.high_label)

        self.medium_label = QLabel("MEDIUM: 0")
        self.medium_label.setStyleSheet("font-weight: bold; color: #ffff00;")
        stats_layout.addWidget(self.medium_label)

        self.low_label = QLabel("LOW: 0")
        self.low_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        stats_layout.addWidget(self.low_label)

        stats_layout.addStretch()

        layout.addLayout(stats_layout)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "CVE ID", "CVSS", "SEVERITY", "PUBLISHED", "DESCRIPTION", "VENDOR", "PRODUCT"
        ])

        # Configure table for nmap-style display
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSortingEnabled(True)

        # Set column widths
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # CVE ID
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # CVSS
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Severity
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Published
        header.setSectionResizeMode(4, QHeaderView.Stretch)          # Description
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Vendor
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Product

        # Connect double-click for details
        self.results_table.itemDoubleClicked.connect(self.show_cve_details)

        layout.addWidget(self.results_table)

        # Status bar
        self.status_label = QLabel("READY - Enter search terms and click SCAN")
        self.status_label.setStyleSheet("font-family: monospace; color: #00ff00;")
        layout.addWidget(self.status_label)

        return group
        
    def search_cves(self):
        """Search for CVE vulnerabilities."""
        query = self.search_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Warning", "Please enter a search query.")
            return

        # Get filter options
        severity_filter = self.severity_combo.currentText()
        if severity_filter == "ALL":
            severity_filter = None

        year_filter = self.year_combo.currentText()
        if year_filter == "ALL":
            year_filter = None

        # Update UI state
        self.search_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText(f"SCANNING for '{query}'...")

        # Clear previous results
        self.results_table.setRowCount(0)
        self.update_statistics(0, 0, 0, 0, 0)

        # Start CVE lookup worker
        self.cve_worker = CVEWorker(query, severity_filter, year_filter)
        self.cve_worker.result_ready.connect(self.on_search_complete)
        self.cve_worker.error_occurred.connect(self.on_search_error)
        self.cve_worker.finished.connect(self.on_search_finished)
        self.cve_worker.start()

    def on_search_complete(self, results):
        """Handle search completion with results."""
        self.current_results = results
        self.display_results(results)

    def on_search_error(self, error_message):
        """Handle search error."""
        self.status_label.setText(f"ERROR: {error_message}")
        QMessageBox.critical(self, "CVE Search Error", f"Search failed: {error_message}")

    def on_search_finished(self):
        """Handle search completion."""
        self.search_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        if self.current_results:
            self.export_button.setEnabled(True)

    def display_results(self, results):
        """Display CVE search results in the table."""
        self.results_table.setRowCount(len(results))

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for row, cve in enumerate(results):
            # CVE ID
            cve_item = QTableWidgetItem(cve.cve_id)
            cve_item.setFont(QFont("Courier New", 10, QFont.Bold))
            self.results_table.setItem(row, 0, cve_item)

            # CVSS Score
            cvss_item = QTableWidgetItem(f"{cve.cvss_score:.1f}" if cve.cvss_score else "N/A")
            cvss_item.setTextAlignment(Qt.AlignCenter)
            self.results_table.setItem(row, 1, cvss_item)

            # Severity with color coding
            severity_item = QTableWidgetItem(cve.severity.upper())
            severity_item.setTextAlignment(Qt.AlignCenter)
            severity_item.setFont(QFont("Courier New", 10, QFont.Bold))

            # Color code by severity
            if cve.severity.lower() == "critical":
                severity_item.setForeground(QColor(255, 0, 0))  # Red
                severity_counts["critical"] += 1
            elif cve.severity.lower() == "high":
                severity_item.setForeground(QColor(255, 136, 0))  # Orange
                severity_counts["high"] += 1
            elif cve.severity.lower() == "medium":
                severity_item.setForeground(QColor(255, 255, 0))  # Yellow
                severity_counts["medium"] += 1
            elif cve.severity.lower() == "low":
                severity_item.setForeground(QColor(0, 255, 0))  # Green
                severity_counts["low"] += 1

            self.results_table.setItem(row, 2, severity_item)

            # Published date
            pub_date = cve.published_date.strftime("%Y-%m-%d") if cve.published_date else "N/A"
            self.results_table.setItem(row, 3, QTableWidgetItem(pub_date))

            # Description (truncated)
            desc = cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
            self.results_table.setItem(row, 4, QTableWidgetItem(desc))

            # Vendor and Product
            self.results_table.setItem(row, 5, QTableWidgetItem(cve.vendor or "N/A"))
            self.results_table.setItem(row, 6, QTableWidgetItem(cve.product or "N/A"))

        # Update statistics
        total = len(results)
        self.update_statistics(total, severity_counts["critical"],
                             severity_counts["high"], severity_counts["medium"],
                             severity_counts["low"])

        # Update status
        self.status_label.setText(f"SCAN COMPLETE - Found {total} vulnerabilities")

    def update_statistics(self, total, critical, high, medium, low):
        """Update vulnerability statistics display."""
        self.total_label.setText(f"TOTAL: {total}")
        self.critical_label.setText(f"CRITICAL: {critical}")
        self.high_label.setText(f"HIGH: {high}")
        self.medium_label.setText(f"MEDIUM: {medium}")
        self.low_label.setText(f"LOW: {low}")

    def show_cve_details(self, item):
        """Show detailed CVE information."""
        row = item.row()
        if row < len(self.current_results):
            cve = self.current_results[row]
            self.show_cve_detail_dialog(cve)

    def show_cve_detail_dialog(self, cve):
        """Show detailed CVE information in a dialog."""
        dialog = QMessageBox(self)
        dialog.setWindowTitle(f"CVE Details - {cve.cve_id}")
        dialog.setTextFormat(Qt.RichText)

        details = f"""
        <h3>{cve.cve_id}</h3>
        <p><b>CVSS Score:</b> {cve.cvss_score:.1f if cve.cvss_score else 'N/A'}</p>
        <p><b>Severity:</b> {cve.severity.upper()}</p>
        <p><b>Published:</b> {cve.published_date.strftime('%Y-%m-%d') if cve.published_date else 'N/A'}</p>
        <p><b>Modified:</b> {cve.modified_date.strftime('%Y-%m-%d') if cve.modified_date else 'N/A'}</p>
        <p><b>Vendor:</b> {cve.vendor or 'N/A'}</p>
        <p><b>Product:</b> {cve.product or 'N/A'}</p>
        <p><b>Description:</b></p>
        <p>{cve.description}</p>
        """

        if cve.references:
            details += "<p><b>References:</b></p><ul>"
            for ref in cve.references[:5]:  # Show first 5 references
                details += f"<li><a href='{ref}'>{ref}</a></li>"
            details += "</ul>"

        dialog.setText(details)
        dialog.exec()

    def toggle_auto_refresh(self, enabled):
        """Toggle auto-refresh functionality."""
        self.auto_refresh_enabled = enabled
        if enabled:
            self.refresh_timer.start(30000)  # Refresh every 30 seconds
            self.status_label.setText("AUTO-REFRESH ENABLED - Monitoring for new CVEs...")
        else:
            self.refresh_timer.stop()

    def auto_refresh(self):
        """Perform automatic refresh of CVE data."""
        if self.auto_refresh_enabled and self.search_input.text().strip():
            self.search_cves()

    def export_results(self):
        """Export CVE results to file."""
        if not self.current_results:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export CVE Results",
            f"cve_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )

        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump([cve.to_dict() for cve in self.current_results],
                                f, indent=2, default=str)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['CVE ID', 'CVSS Score', 'Severity', 'Published',
                                       'Description', 'Vendor', 'Product'])
                        for cve in self.current_results:
                            writer.writerow([
                                cve.cve_id, cve.cvss_score or '', cve.severity,
                                cve.published_date.strftime('%Y-%m-%d') if cve.published_date else '',
                                cve.description, cve.vendor or '', cve.product or ''
                            ])
                else:
                    # Text format
                    with open(filename, 'w') as f:
                        f.write("NetSecureX CVE Lookup Results\n")
                        f.write("=" * 50 + "\n\n")
                        for cve in self.current_results:
                            f.write(f"CVE ID: {cve.cve_id}\n")
                            f.write(f"CVSS Score: {cve.cvss_score or 'N/A'}\n")
                            f.write(f"Severity: {cve.severity}\n")
                            f.write(f"Published: {cve.published_date.strftime('%Y-%m-%d') if cve.published_date else 'N/A'}\n")
                            f.write(f"Description: {cve.description}\n")
                            f.write("-" * 50 + "\n")

                QMessageBox.information(self, "Export Complete",
                                      f"CVE results exported to {filename}")

            except Exception as e:
                QMessageBox.critical(self, "Export Error",
                                   f"Failed to export results: {e}")
