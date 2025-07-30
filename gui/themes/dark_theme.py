"""
Dark Cybersecurity Theme for NetSecureX
=======================================

Professional dark theme optimized for cybersecurity applications.
Uses a dark color palette with blue/cyan accents for a modern look.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor


def apply_dark_theme(app):
    """Apply dark cybersecurity theme to the application."""
    
    # Set dark style
    app.setStyle("Fusion")
    
    # Create dark palette
    palette = QPalette()
    
    # Define color scheme
    colors = {
        'background': QColor(30, 30, 30),           # Dark gray background
        'surface': QColor(45, 45, 45),              # Slightly lighter surface
        'primary': QColor(0, 150, 200),             # Cyan blue primary
        'secondary': QColor(100, 100, 100),         # Gray secondary
        'text': QColor(255, 255, 255),              # White text
        'text_secondary': QColor(200, 200, 200),    # Light gray text
        'accent': QColor(0, 255, 150),              # Green accent
        'warning': QColor(255, 165, 0),             # Orange warning
        'error': QColor(255, 100, 100),             # Red error
        'success': QColor(100, 255, 100),           # Green success
        'border': QColor(70, 70, 70),               # Border color
        'hover': QColor(60, 60, 60),                # Hover color
        'selected': QColor(0, 120, 160),            # Selection color
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
    palette.setColor(QPalette.HighlightedText, colors['text'])
    
    # Apply palette
    app.setPalette(palette)
    
    # Set custom stylesheet for additional styling
    stylesheet = f"""
    QMainWindow {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
    }}
    
    QTabWidget::pane {{
        border: 1px solid {colors['border'].name()};
        background-color: {colors['surface'].name()};
    }}
    
    QTabBar::tab {{
        background-color: {colors['background'].name()};
        color: {colors['text_secondary'].name()};
        padding: 8px 16px;
        margin-right: 2px;
        border: 1px solid {colors['border'].name()};
        border-bottom: none;
    }}
    
    QTabBar::tab:selected {{
        background-color: {colors['primary'].name()};
        color: {colors['text'].name()};
    }}
    
    QTabBar::tab:hover {{
        background-color: {colors['hover'].name()};
        color: {colors['text'].name()};
    }}
    
    QPushButton {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border: 1px solid {colors['border'].name()};
        padding: 8px 16px;
        border-radius: 4px;
        font-weight: bold;
    }}
    
    QPushButton:hover {{
        background-color: {colors['hover'].name()};
        border-color: {colors['primary'].name()};
    }}
    
    QPushButton:pressed {{
        background-color: {colors['primary'].name()};
    }}
    
    QPushButton:disabled {{
        background-color: {colors['secondary'].name()};
        color: {colors['text_secondary'].name()};
        border-color: {colors['secondary'].name()};
    }}
    
    QLineEdit, QTextEdit, QPlainTextEdit {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border: 1px solid {colors['border'].name()};
        padding: 6px;
        border-radius: 4px;
    }}
    
    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border-color: {colors['primary'].name()};
    }}
    
    QTableWidget {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        gridline-color: {colors['border'].name()};
        selection-background-color: {colors['selected'].name()};
    }}
    
    QTableWidget::item {{
        padding: 8px;
        border-bottom: 1px solid {colors['border'].name()};
    }}
    
    QTableWidget::item:selected {{
        background-color: {colors['selected'].name()};
    }}
    
    QHeaderView::section {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
        padding: 8px;
        border: 1px solid {colors['border'].name()};
        font-weight: bold;
    }}
    
    QProgressBar {{
        border: 1px solid {colors['border'].name()};
        border-radius: 4px;
        text-align: center;
        background-color: {colors['surface'].name()};
    }}
    
    QProgressBar::chunk {{
        background-color: {colors['primary'].name()};
        border-radius: 3px;
    }}
    
    QStatusBar {{
        background-color: {colors['background'].name()};
        color: {colors['text_secondary'].name()};
        border-top: 1px solid {colors['border'].name()};
    }}
    
    QMenuBar {{
        background-color: {colors['background'].name()};
        color: {colors['text'].name()};
        border-bottom: 1px solid {colors['border'].name()};
    }}
    
    QMenuBar::item {{
        padding: 6px 12px;
    }}
    
    QMenuBar::item:selected {{
        background-color: {colors['hover'].name()};
    }}
    
    QMenu {{
        background-color: {colors['surface'].name()};
        color: {colors['text'].name()};
        border: 1px solid {colors['border'].name()};
    }}
    
    QMenu::item {{
        padding: 6px 20px;
    }}
    
    QMenu::item:selected {{
        background-color: {colors['primary'].name()};
    }}
    
    QScrollBar:vertical {{
        background-color: {colors['background'].name()};
        width: 12px;
        border: none;
    }}
    
    QScrollBar::handle:vertical {{
        background-color: {colors['secondary'].name()};
        border-radius: 6px;
        min-height: 20px;
    }}
    
    QScrollBar::handle:vertical:hover {{
        background-color: {colors['primary'].name()};
    }}
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        border: none;
        background: none;
    }}
    """
    
    app.setStyleSheet(stylesheet)
