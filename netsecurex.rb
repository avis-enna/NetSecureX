# typed: strict
# frozen_string_literal: true

class Netsecurex < Formula
  desc "Advanced Cybersecurity Toolkit with Network Traffic Analysis"
  homepage "https://github.com/avis-enna/NetSecureX"
  url "https://github.com/avis-enna/NetSecureX/archive/refs/tags/v1.4.0.tar.gz"
  sha256 "58ca704e8e4e42c9b6413fcf94cabfac7217c05f1d21b95bd5704ffdcb8d7662"
  license "MIT"
  head "https://github.com/avis-enna/NetSecureX.git", branch: "main"

  depends_on "nmap"
  depends_on "openssl@3"
  depends_on "python@3.12"

  def install
    # Use standard Python installation with proper package structure
    python3 = Formula["python@3.12"].opt_bin/"python3.12"

    # Install using setup.py which creates proper entry points
    system python3, "-m", "pip", "install", "--prefix=#{prefix}", "--no-deps", buildpath

    # Install dependencies separately to avoid conflicts
    system python3, "-m", "pip", "install", "--prefix=#{prefix}",
           "click", "rich", "requests", "scapy", "cryptography", "python-nmap", "pysocks"

    # The setup.py should have created the console scripts automatically
    # But let's create a wrapper to ensure it works
    (bin/"netsecurex").write <<~EOS
            #!/bin/bash
            export PYTHONPATH="#{prefix}/lib/python3.12/site-packages:$PYTHONPATH"
            exec "#{python3}" -c "
      import sys
      sys.path.insert(0, '#{prefix}/lib/python3.12/site-packages')
      from ui.cli import main_cli
      sys.exit(main_cli())
      " "$@"
    EOS

    # Create aliases
    (bin/"nsx").write <<~EOS
      #!/bin/bash
      exec "#{bin}/netsecurex" "$@"
    EOS

    (bin/"netsecx").write <<~EOS
      #!/bin/bash
      exec "#{bin}/netsecurex" "$@"
    EOS

    # Make all scripts executable
    chmod 0755, bin/"netsecurex"
    chmod 0755, bin/"nsx"
    chmod 0755, bin/"netsecx"

    # Install configuration directory
    (etc/"netsecurex").mkpath

    # Install example configuration
    (etc/"netsecurex/config.example.yaml").write <<~EOS
      # NetSecureX Configuration
      # Copy this file to ~/.netsecurex/config.yaml and add your API keys

      api_keys:
        abuseipdb: "your_abuseipdb_api_key_here"
        virustotal: "your_virustotal_api_key_here"
        shodan: "your_shodan_api_key_here"

      scanning:
        default_ports: "1-1000"
        timeout: 3
        max_concurrent: 100
        log_level: "INFO"
        output_format: "table"
    EOS

    # Install documentation
    doc.install "README.md"
    doc.install "docs" if File.directory?("docs")
    doc.install "examples" if File.directory?("examples")
  end

  def post_install
    # Create user config directory
    config_dir = "#{Dir.home}/.netsecurex"
    mkdir_p config_dir unless Dir.exist?(config_dir)

    # Copy example config if user config doesn't exist
    user_config = "#{config_dir}/config.yaml"
    cp "#{etc}/netsecurex/config.example.yaml", user_config unless File.exist?(user_config)
  end

  def caveats
    <<~EOS
      🚀 NetSecureX v1.4.0 has been installed successfully!

      🆕 NEW IN v1.4.0 - ADVANCED NETWORK TRAFFIC ANALYSIS:
        • Real-time packet sniffing and analysis
        • CSV export for packet data analysis
        • Enhanced GUI with hex/ASCII packet viewer
        • Advanced anomaly detection (DNS tunneling, beaconing, data exfiltration)
        • Professional-grade threat hunting capabilities

      Configuration:
        Edit ~/.netsecurex/config.yaml to add your API keys.

      API Keys (all have free tiers):
        • AbuseIPDB: https://www.abuseipdb.com/api
        • IPQualityScore: https://www.ipqualityscore.com/create-account
        • VirusTotal: https://www.virustotal.com/gui/join-us
        • Vulners: https://vulners.com/api
        • GreyNoise: https://www.greynoise.io/
        • Shodan: https://www.shodan.io/ (paid)

      Quick Start:
        netsecurex --help
        netsecurex scan 192.168.1.1
        netsecurex gui

      🔍 NEW NETWORK TRAFFIC ANALYSIS (v1.4.0):
        # Real-time packet sniffing with CSV export
        netsecurex sniff --duration 60 --csv-output packets.csv

        # Advanced anomaly detection and reporting
        netsecurex sniff --detect-anomalies --report analysis.md

        # Professional packet analysis in GUI
        netsecurex gui  # Double-click packets for hex/ASCII view

      Advanced Features:
        netsecurex cve --query "nginx"
        netsecurex sslcheck google.com
        netsecurex scan --scan-type syn 192.168.1.0/24

      Security Notes:
        ⚠️  Packet sniffing requires elevated privileges (sudo/admin)
        ⚠️  Only analyze networks you own or have explicit permission to monitor
        ⚠️  Use responsibly and in accordance with local laws

      Documentation:
        #{doc}/README.md
        #{doc}/examples/
    EOS
  end

  test do
    assert_match "NetSecureX", shell_output("#{bin}/netsecurex --version")
    assert_match "Usage:", shell_output("#{bin}/netsecurex --help")
  end
end
