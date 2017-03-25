class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::RFTransceiver::RFTransceiver

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Send Binary AM/OOK Signals (ie: Garage Doors, Gate Motors)',
        'Description'   => %q{ Post Module for HWBridge RFTranscievers. Sends an AM OOK signal. When RAW is
                               set to TRUE, signals will not be PWM encoded.
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
      OptInt.new('FREQ', [true, "Frequency to transmit on", 43350000]),
      OptInt.new('BAUD', [false, "Baud rate to use", 2000]),
      OptInt.new('REPEAT', [false, "Number of times to repeat the signal", 3]),
      OptString.new('BINARY', [true, "Specify the binary to send", nil]),
      OptString.new('PPAD', [false, "Specify your own binary padding before the binary", nil]),
      OptString.new('TPAD', [false, "Specify your own binary padding after the binary", nil]),
      OptString.new('PWMZERO', [false, "Specify the binary that represents a 'pwmified' zero", "110"]),
      OptString.new('PWMONE', [false, "Specify the binary that represents a 'pwmified' one", "100"]),
      OptBool.new('RAW', [false, "When set, disables PWM encoding. BINLENGTH must be -1", false]),
      OptInt.new('INDEX', [false, "USB Index to use", 0]),
      OptInt.new('DELAY', [false, "Delay in milliseconds between transmissions", 500])
    ], self.class)
  end

  # @param key [String] binary/trinary represntation
  # @return [Array] ByteArray
  def convert_ook(key)
    pwm_str_key = ""
    key.each_char do |k|
      x = "*"
      case k
      when "0"
        x = datastore["PWMZERO"]
      when "1"
        x = datastore["PWMONE"]
      end
      pwm_str_key += x
    end
    return pwm_str_key.scan(/.{1,8}/).collect{|x| x.to_i(2).chr}
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

    set_modulation("ASK/OOK")
    set_freq(datastore["FREQ"])
    set_sync_mode(0)
    set_baud(datastore["BAUD"])
    max_power

    print_status("Using frequency: #{datastore['FREQ']}")
    print_status("Padding before binary: #{datastore['PPAD']}") if datastore["PPAD"]
    print_status("Padding after binary: #{datastore["TPAD"]}") if datastore["TPAD"]

    # Pad the binary if there are padding values
    brutepackettemp = datastore["BINARY"]
    brutepackettemp = datastore["PPAD"] + brutepackettemp if datastore["PPAD"]
    brutepackettemp += datastore["TPAD"] if datastore["TPAD"]

    # PWM-ify if needed
    if datastore["RAW"]
      key_packed = brutepackettemp.scan(/.{1,8}/).collect{|x| x.to_i(2).chr}
    else
      key_packed = convert_ook(brutepackettemp)

      print_status("Binary before PWM encoding: #{brutepackettemp}")
      print_status("Binary after PWM encoding: #{key_packed.join.unpack("H*")[0].hex.to_s(2)}")
    end

    # Transmit
    (0..datastore["REPEAT"]-1).each do |i|
      print_good("Transmitting packet #{i}...")
      set_flen(key_packed.length)
      rfxmit(key_packed.join, datastore["REPEAT"])
      sleep(datastore["DELAY"] / 1000) if datastore["DELAY"] > 0
    end

    print_status("Done")
    set_mode("IDLE")
  end

end
