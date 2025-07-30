"""
Nmap-Style Classic Theme for NetSecureX
=======================================

Classic terminal-style theme inspired by nmap and traditional security tools.
Uses green text on black background with monospace fonts.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor, QFont


def apply_nmap_theme(app):
    """Apply classic nmap-style theme to the application."""
    
    # Set style
    app.setStyle("Fusion")
    
    # Create classic terminal palette
    palette = QPalette()
    
    # Define classic terminal colors
    colors = {
        'background': QColor(0, 0, 0),              # Pure black background
        'surface': QColor(10, 10, 10),              # Slightly lighter black
        'primary': QColor(0, 255, 0),               # Bright green (classic terminal)
        'secondary': QColor(128, 128, 128),         # Gray
        'text': QColor(0, 255, 0),                  # Bright green text
        'text_secondary': QColor(0, 200, 0),        # Dimmer green
        'accent': QColor(255, 255, 0),              # Yellow accent
        'warning': QColor(255, 165, 0),             # Orange warning
        'error': QColor(255, 0, 0),                 # Red error
        'success': QColor(0, 255, 0),               # Green success
        'border': QColor(0, 128, 0),                # Dark green border
        'hover': QColor(20, 40, 20),                # Dark green hover
        'selected': QColor(0, 128, 0),              # Green selection
        'inactive': QColor(64, 64, 64),             # Dark gray inactive
    }
    
    # Set palette colors
    palette.setColor(QPalette.Window, colors['background'])
    palette.setColor(QPalette.WindowText, colors['text'])
    palette.setColor(QPalette.Base, colors['surface'])
    palette.setColor(QPalette.AlternateBase, colors['hover'])
    palette.setColor(QPalette.ToolTipBase, colors['surface'])
    palette.setColor(QPalette.ToolTipText, colors['text'])
    palette.setColor(QPalette.Text, colors['text'])
    palette.setColor(QPalette.Button, colors['surface'])
    palette.setColor(QPalette.ButtonText, colors['text'])
    palette.setColor(QPalette.BrightText, colors['accent'])
    palette.setColor(QPalette.Link, colors['primary'])
    palette.setColor(QPalette.Highlight, colors['selected'])
    palette.setColor(QPalette.HighlightedText, colors['background'])
    
    # Apply palette
    app.setPalette(palette)
    
    # Set monospace font for terminal feel
    font = QFont("Courier New", 10)
    font.setStyleHint(QFont.Monospace)
    app.setFont(font)
    
    # Set custom stylesheet for nmap-style appearance
    stylesheet = f"""
    QMainWindow {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
        font-family: "Courier New", "Monaco", "Consolas", monospace;
    }}
    
    QTabWidget::pane {{
        border: 2px solid {colors['border'].name()};
        background-color: {colors['background'].name()};
    }}
    
    QTabBar::tab {{
        background-color: {colors['surface'].name()};
        color: {colors['text_secondary'].name()};
        padding: 8px 16px;
        margin-right: 2px;
        border: 1px solid {colors['border'].name()};
        border-bottom: none;
        font-family: "Courier New", monospace;
        font-weight: bold;
    }}
    
    QTabBar::tab:selected {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
        border: 2px solid {colors['primary'].name()};
        border-bottom: none;
    }}
    
    QTabBar::tab:hover {{
        background-color: {colors['hover'].name()};
        color: {colors['text'].name()};
    }}
    
    QPushButton {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border: 2px solid {colors['border'].name()};
        padding: 8px 16px;
        font-family: "Courier New", monospace;
        font-weight: bold;
        text-transform: uppercase;
    }}
    
    QPushButton:hover {{
        background-color: {colors['hover'].name()};
        border-color: {colors['primary'].name()};
        color: {colors['primary'].name()};
    }}
    
    QPushButton:pressed {{
        background-color: {colors['primary'].name()};
        color: {colors['background'].name()};
    }}
    
    QPushButton:disabled {{
        background-color: {colors['surface'].name()};
        color: {colors['inactive'].name()};
        border-color: {colors['inactive'].name()};
    }}
    
    QLineEdit, QTextEdit, QPlainTextEdit {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
        border: 2px solid {colors['border'].name()};
        padding: 6px;
        font-family: "Courier New", monospace;
        selection-background-color: {colors['selected'].name()};
        selection-color: {colors['background'].name()};
    }}
    
    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border-color: {colors['primary'].name()};
        background-color: {colors['surface'].name()};
    }}
    
    QTableWidget {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
        gridline-color: {colors['border'].name()};
        selection-background-color: {colors['selected'].name()};
        selection-color: {colors['background'].name()};
        font-family: "Courier New", monospace;
        alternate-background-color: {colors['surface'].name()};
    }}
    
    QTableWidget::item {{
        padding: 8px;
        border-bottom: 1px solid {colors['border'].name()};
    }}
    
    QTableWidget::item:selected {{
        background-color: {colors['selected'].name()};
        color: {colors['background'].name()};
    }}
    
    QHeaderView::section {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        padding: 8px;
        border: 2px solid {colors['border'].name()};
        font-family: "Courier New", monospace;
        font-weight: bold;
        text-transform: uppercase;
    }}
    
    QProgressBar {{
        border: 2px solid {colors['border'].name()};
        text-align: center;
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        font-family: "Courier New", monospace;
        font-weight: bold;
    }}
    
    QProgressBar::chunk {{
        background-color: {colors['primary'].name()};
    }}
    
    QStatusBar {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border-top: 2px solid {colors['border'].name()};
        font-family: "Courier New", monospace;
    }}
    
    QMenuBar {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border-bottom: 2px solid {colors['border'].name()};
        font-family: "Courier New", monospace;
        font-weight: bold;
    }}
    
    QMenuBar::item {{
        padding: 6px 12px;
        background-color: transparent;
    }}
    
    QMenuBar::item:selected {{
        background-color: {colors['hover'].name()};
        color: {colors['primary'].name()};
    }}
    
    QMenu {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border: 2px solid {colors['border'].name()};
        font-family: "Courier New", monospace;
    }}
    
    QMenu::item {{
        padding: 6px 20px;
    }}
    
    QMenu::item:selected {{
        background-color: {colors['primary'].name()};
        color: {colors['background'].name()};
    }}
    
    QScrollBar:vertical {{
        background-color: {colors['surface'].name()};
        width: 16px;
        border: 2px solid {colors['border'].name()};
    }}
    
    QScrollBar::handle:vertical {{
        background-color: {colors['border'].name()};
        min-height: 20px;
    }}
    
    QScrollBar::handle:vertical:hover {{
        background-color: {colors['primary'].name()};
    }}
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        border: none;
        background: none;
    }}
    
    QGroupBox {{
        color: {colors['text'].name()};
        border: 2px solid {colors['border'].name()};
        border-radius: 0px;
        margin-top: 1ex;
        font-family: "Courier New", monospace;
        font-weight: bold;
        text-transform: uppercase;
    }}
    
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px 0 5px;
        color: {colors['primary'].name()};
    }}
    
    QLabel {{
        color: {colors['text'].name()};
        font-family: "Courier New", monospace;
    }}
    
    QComboBox {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border: 2px solid {colors['border'].name()};
        padding: 6px;
        font-family: "Courier New", monospace;
    }}
    
    QComboBox:hover {{
        border-color: {colors['primary'].name()};
    }}
    
    QComboBox::drop-down {{
        border: none;
        width: 20px;
    }}
    
    QComboBox::down-arrow {{
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 5px solid {colors['text'].name()};
    }}
    
    QSpinBox {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border: 2px solid {colors['border'].name()};
        padding: 6px;
        font-family: "Courier New", monospace;
    }}
    
    QSpinBox:hover {{
        border-color: {colors['primary'].name()};
    }}
    
    QCheckBox {{
        color: {colors['text'].name()};
        font-family: "Courier New", monospace;
    }}
    
    QCheckBox::indicator {{
        width: 16px;
        height: 16px;
        border: 2px solid {colors['border'].name()};
        background-color: {colors['surface'].name()};
    }}
    
    QCheckBox::indicator:checked {{
        background-color: {colors['primary'].name()};
        border-color: {colors['primary'].name()};
    }}
    
    QListWidget {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
        border: 2px solid {colors['border'].name()};
        font-family: "Courier New", monospace;
        alternate-background-color: {colors['surface'].name()};
    }}
    
    QListWidget::item {{
        padding: 4px;
        border-bottom: 1px solid {colors['border'].name()};
    }}
    
    QListWidget::item:selected {{
        background-color: {colors['selected'].name()};
        color: {colors['background'].name()};
    }}
    """
    
    app.setStyleSheet(stylesheet)
