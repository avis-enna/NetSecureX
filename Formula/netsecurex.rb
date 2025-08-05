class Netsecurex < Formula
  desc "Advanced Cybersecurity Toolkit with Port Scanning and Network Assessment"
  homepage "https://github.com/avis-enna/NetSecureX"
  url "https://github.com/avis-enna/NetSecureX/archive/refs/tags/v1.3.0.tar.gz"
  sha256 "adaa0353661a7e1c163c2a106d9a6475c0d62d9eaea445690827f9f8e1a75649"
  license "MIT"
  head "https://github.com/avis-enna/NetSecureX.git", branch: "main"

  depends_on "python@3.12"
  depends_on "openssl@3"
  depends_on "nmap"

  def install
    # Create virtualenv
    venv = virtualenv_create(libexec, "python3.12")

    # Install the package and its dependencies
    venv.pip_install buildpath

    # Create the main executable
    (bin/"netsecurex").write_env_script libexec/"bin/python", libexec/"bin/netsecurex",
      PATH: "#{libexec}/bin:$PATH"

    # Install configuration directory
    (etc/"netsecurex").mkpath
    
    # Install example configuration
    (etc/"netsecurex/config.example.yaml").write <<~EOS
      # NetSecureX Configuration
      # Copy this file to ~/.netsecurex/config.yaml and add your API keys
      
      api_keys:
        # AbuseIPDB API Key (free tier available)
        # Get from: https://www.abuseipdb.com/api
        abuseipdb: "your_abuseipdb_api_key_here"
        
        # IPQualityScore API Key (free tier available)
        # Get from: https://www.ipqualityscore.com/create-account
        ipqualityscore: "your_ipqualityscore_api_key_here"
        
        # VirusTotal API Key (free tier available)
        # Get from: https://www.virustotal.com/gui/join-us
        virustotal: "your_virustotal_api_key_here"
        
        # Vulners API Key (free tier available)
        # Get from: https://vulners.com/api
        vulners: "your_vulners_api_key_here"
        
        # Shodan API Key (paid service)
        # Get from: https://www.shodan.io/
        shodan: "your_shodan_api_key_here"
        
        # GreyNoise API Key (free tier available)
        # Get from: https://www.greynoise.io/
        greynoise: "your_greynoise_api_key_here"

      # Default settings
      settings:
        timeout: 10
        max_concurrent: 100
        log_level: "INFO"
        output_format: "table"
    EOS

    # Install documentation
    doc.install "README.md"
    doc.install "examples"
  end

  def post_install
    # Create user config directory
    config_dir = "#{Dir.home}/.netsecurex"
    system "mkdir", "-p", config_dir unless Dir.exist?(config_dir)
    
    # Copy example config if user config doesn't exist
    user_config = "#{config_dir}/config.yaml"
    unless File.exist?(user_config)
      system "cp", "#{etc}/netsecurex/config.example.yaml", user_config
    end
  end

  def caveats
    <<~EOS
      🚀 NetSecureX v1.3.0 has been installed successfully!

      ✨ NEW in v1.3.0 - Advanced Port Scanning:
        • Multiple scan types: TCP SYN, FIN, NULL, Xmas, UDP
        • Enhanced service detection with version fingerprinting
        • Timing templates from Paranoid to Insane
        • Stealth options with port/timing randomization
        • Professional-grade reconnaissance capabilities

      Configuration:
        Edit ~/.netsecurex/config.yaml to add your API keys.

      API Keys (all have free tiers):
        • AbuseIPDB: https://www.abuseipdb.com/api
        • IPQualityScore: https://www.ipqualityscore.com/create-account
        • VirusTotal: https://www.virustotal.com/gui/join-us
        • Vulners: https://vulners.com/api
        • GreyNoise: https://www.greynoise.io/
        • Shodan: https://www.shodan.io/ (paid)

      Basic Usage:
        netsecurex --help
        netsecurex cve --query "nginx"
        netsecurex scan 192.168.1.1
        netsecurex sslcheck google.com

      Advanced Scanning (NEW):
        netsecurex scan --type syn 192.168.1.1
        netsecurex scan --timing aggressive --service-detect 192.168.1.0/24
        netsecurex scan --stealth --randomize 10.0.0.1

      ⚠️  Important Notes:
        • Advanced scanning (SYN, FIN, etc.) requires elevated privileges
        • Only scan systems you own or have explicit permission to test
        • Unauthorized scanning may violate laws and policies

      Documentation:
        #{doc}/README.md
        #{doc}/examples/
    EOS
  end

  test do
    assert_match "NetSecureX", shell_output("#{bin}/netsecurex --version")
    assert_match "Usage:", shell_output("#{bin}/netsecurex --help")

    # Test advanced scanning options are available
    help_output = shell_output("#{bin}/netsecurex scan --help")
    assert_match "scan-type", help_output
    assert_match "timing", help_output
    assert_match "service-detect", help_output
  end
end
