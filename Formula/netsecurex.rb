class Netsecurex < Formula
  desc "Unified Cybersecurity Toolkit for Network Security Assessment"
  homepage "https://github.com/avis-enna/NetSecureX"
  url "https://github.com/avis-enna/NetSecureX/archive/refs/tags/v1.2.3.tar.gz"
  sha256 "99132a77dd9cd4fce74feec63c7c749ac830943962b84dfa7080b407a01a07d1"
  license "MIT"
  head "https://github.com/avis-enna/NetSecureX.git", branch: "main"

  depends_on "nmap"
  depends_on "openssl@3"
  depends_on "python@3.12"

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
    mkdir_p config_dir unless Dir.exist?(config_dir)

    # Copy example config if user config doesn't exist
    user_config = "#{config_dir}/config.yaml"
    cp "#{etc}/netsecurex/config.example.yaml", user_config unless File.exist?(user_config)
  end

  def caveats
    <<~EOS
      NetSecureX has been installed successfully!

      Configuration:
        Edit ~/.netsecurex/config.yaml to add your API keys.

      API Keys (all have free tiers):
        • AbuseIPDB: https://www.abuseipdb.com/api
        • IPQualityScore: https://www.ipqualityscore.com/create-account
        • VirusTotal: https://www.virustotal.com/gui/join-us
        • Vulners: https://vulners.com/api
        • GreyNoise: https://www.greynoise.io/
        • Shodan: https://www.shodan.io/ (paid)

      Usage:
        netsecurex --help
        netsecurex cve --query "nginx"
        netsecurex scan 192.168.1.1
        netsecurex sslcheck google.com

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
