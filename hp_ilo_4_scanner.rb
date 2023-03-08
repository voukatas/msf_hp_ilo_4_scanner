require 'msf/core'

# sudo mkdir /usr/share/metasploit-framework/modules/auxiliary/scanner/hpilo4
# reload_all

# ToDo:
# Commit this to the official metasploit framework repo

class MetasploitModule < Msf::Auxiliary 

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'HP iLO 4 1.00-2.50 Scanner',
      'Description'    => %q{
        This module checks if the provided host is vulnerable to an authentication bypass in HP iLO 4 1.00 to 2.50.
      },
      'Author'         => 'vostdev [at] gmail [dot] com',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2017-12542' ],          
          [ 'URL', 'https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbhf03769en_us' ],
          [ 'URL', 'https://www.synacktiv.com/en/publications/hp-ilo-talk-at-recon-brx-2018.html' ]
        ],
        'DefaultOptions' => { 'SSL' => true }
    ))

    register_options([
      OptString.new('RHOST', [true, 'The target host', '']),
      OptInt.new('RPORT', [false, 'The target port', 443])
    ])
  end

  def run
    # Get the target host and port from the user input
    rhost = datastore['RHOST']
    rport = datastore['RPORT']

    # Construct the URL for fetching the XML data
    url = "https://#{rhost}:#{rport}/xmldata?item=All"

    # Fetch the XML data from the remote server
    print_status("Fetching XML data from #{url}...")
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    request = Net::HTTP::Get.new(uri.request_uri)
    res = http.request(request)

    # Parse the XML data using Nokogiri
    xml = Nokogiri::XML(res.body)

    # Extract the <PN> element and check if it contains "iLO 4"
    ilo_element = xml.xpath('//PN').text
    if ilo_element.include?('iLO 4')
      # Extract and print the <FWRI> element
      fwri = xml.xpath('//FWRI').text
      if fwri.present? && fwri.to_f.between?(1.0, 2.50)
        print_good("Version: #{fwri} - Vulnerable version")
      else
        print_warning("Version: #{fwri} - Not a vulnerable version")
      end
    else
      print_status("Not an iLO 4 device")
    end
  end

end
