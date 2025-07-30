#!/usr/bin/env python3
"""
NetSecureX Configuration Manager
===============================

Handles configuration file management, API key storage, and user settings.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

class ConfigManager:
    """Manages NetSecureX configuration and API keys."""
    
    def __init__(self):
        self.config_dir = Path.home() / ".netsecurex"
        self.config_file = self.config_dir / "config.yaml"
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        if not self.config_file.exists():
            self._create_default_config()
        
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration structure."""
        return {
            'api_keys': {
                'abuseipdb': '',
                'ipqualityscore': '',
                'virustotal': '',
                'vulners': '',
                'shodan': '',
                'greynoise': ''
            },
            'settings': {
                'timeout': 10,
                'max_concurrent': 100,
                'log_level': 'INFO',
                'output_format': 'table'
            }
        }
    
    def _create_default_config(self):
        """Create default configuration file."""
        self.config_dir.mkdir(exist_ok=True)
        
        config_content = """# NetSecureX Configuration
# Add your API keys below (all have free tiers available)

api_keys:
  # AbuseIPDB API Key (free tier: 1000 requests/day)
  # Get from: https://www.abuseipdb.com/api
  abuseipdb: ""
  
  # IPQualityScore API Key (free tier: 5000 requests/month)
  # Get from: https://www.ipqualityscore.com/create-account
  ipqualityscore: ""
  
  # VirusTotal API Key (free tier: 500 requests/day)
  # Get from: https://www.virustotal.com/gui/join-us
  virustotal: ""
  
  # Vulners API Key (free tier: 100 requests/day)
  # Get from: https://vulners.com/api
  vulners: ""
  
  # Shodan API Key (paid service, $49/month)
  # Get from: https://www.shodan.io/
  shodan: ""
  
  # GreyNoise API Key (free tier: 10000 requests/month)
  # Get from: https://www.greynoise.io/
  greynoise: ""

# Default settings
settings:
  timeout: 10
  max_concurrent: 100
  log_level: "INFO"
  output_format: "table"
"""
        
        with open(self.config_file, 'w') as f:
            f.write(config_content)
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service."""
        api_keys = self.config.get('api_keys', {})
        key = api_keys.get(service, '').strip()
        return key if key else None
    
    def set_api_key(self, service: str, key: str):
        """Set API key for a specific service."""
        if 'api_keys' not in self.config:
            self.config['api_keys'] = {}
        
        self.config['api_keys'][service] = key
        self._save_config()
    
    def get_setting(self, key: str, default=None):
        """Get a configuration setting."""
        return self.config.get('settings', {}).get(key, default)
    
    def set_setting(self, key: str, value: Any):
        """Set a configuration setting."""
        if 'settings' not in self.config:
            self.config['settings'] = {}
        
        self.config['settings'][key] = value
        self._save_config()
    
    def _save_config(self):
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
        except Exception as e:
            console.print(f"[red]Error saving config: {e}[/red]")
    
    def show_config_status(self):
        """Display current configuration status."""
        table = Table(title="NetSecureX Configuration Status")
        table.add_column("Service", style="cyan")
        table.add_column("API Key Status", style="green")
        table.add_column("Free Tier", style="yellow")
        table.add_column("Get API Key", style="blue")
        
        services = {
            'abuseipdb': ('1000 req/day', 'https://www.abuseipdb.com/api'),
            'ipqualityscore': ('5000 req/month', 'https://www.ipqualityscore.com/create-account'),
            'virustotal': ('500 req/day', 'https://www.virustotal.com/gui/join-us'),
            'vulners': ('100 req/day', 'https://vulners.com/api'),
            'greynoise': ('10000 req/month', 'https://www.greynoise.io/'),
            'shodan': ('Paid only', 'https://www.shodan.io/')
        }
        
        for service, (free_tier, url) in services.items():
            key = self.get_api_key(service)
            status = "✅ Configured" if key else "❌ Missing"
            table.add_row(service.title(), status, free_tier, url)
        
        console.print(table)
        
        if not any(self.get_api_key(s) for s in services.keys()):
            console.print("\n[yellow]No API keys configured. Some features will be limited.[/yellow]")
            console.print(f"[cyan]Edit your config file: {self.config_file}[/cyan]")
    
    def setup_wizard(self):
        """Interactive setup wizard for API keys."""
        console.print(Panel.fit(
            "[bold blue]NetSecureX API Key Setup Wizard[/bold blue]\n\n"
            "This wizard will help you configure API keys for enhanced functionality.\n"
            "All services offer free tiers - you can skip any you don't want to use.",
            title="Setup"
        ))
        
        services = {
            'abuseipdb': {
                'name': 'AbuseIPDB',
                'description': 'IP reputation and abuse reporting',
                'free_tier': '1000 requests/day',
                'url': 'https://www.abuseipdb.com/api'
            },
            'vulners': {
                'name': 'Vulners',
                'description': 'CVE and vulnerability database',
                'free_tier': '100 requests/day',
                'url': 'https://vulners.com/api'
            },
            'virustotal': {
                'name': 'VirusTotal',
                'description': 'File and URL analysis',
                'free_tier': '500 requests/day',
                'url': 'https://www.virustotal.com/gui/join-us'
            },
            'ipqualityscore': {
                'name': 'IPQualityScore',
                'description': 'IP fraud detection and scoring',
                'free_tier': '5000 requests/month',
                'url': 'https://www.ipqualityscore.com/create-account'
            },
            'greynoise': {
                'name': 'GreyNoise',
                'description': 'Internet scanning activity',
                'free_tier': '10000 requests/month',
                'url': 'https://www.greynoise.io/'
            }
        }
        
        for service_id, info in services.items():
            console.print(f"\n[bold cyan]{info['name']}[/bold cyan]")
            console.print(f"Description: {info['description']}")
            console.print(f"Free tier: {info['free_tier']}")
            console.print(f"Get API key: {info['url']}")
            
            current_key = self.get_api_key(service_id)
            if current_key:
                console.print(f"[green]Current key: {current_key[:8]}...{current_key[-4:]}[/green]")
            
            if click.confirm(f"Do you want to configure {info['name']}?"):
                key = click.prompt(f"Enter your {info['name']} API key", hide_input=True, default="")
                if key.strip():
                    self.set_api_key(service_id, key.strip())
                    console.print(f"[green]✅ {info['name']} API key saved![/green]")
        
        console.print("\n[green]Setup complete! You can always edit your config file later:[/green]")
        console.print(f"[cyan]{self.config_file}[/cyan]")


# Global config instance
config = ConfigManager()
