class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::RFTransceiver::RFTransceiver

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Search for AM/OOK Signals in a Frequency Range',
        'Description'   => %q{ Post Module for HWBridge RFTranscievers. Searches for an
                               AM OOK signal by hopping through frequencies.
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
      OptInt.new('FREQLOW', [true, "Frequency to start on", 433000000]),
      OptInt.new('FREQHIGH', [true, "Frequency to end on", 434000000]),
      OptInt.new('SCANLOOPS', [false, "Number of times to scan the range", 3]),
      OptInt.new('BAUD', [false, "Baud rate to use", 4800]),
      OptInt.new('INDEX', [false, "USB Index to use", 0]),
      OptInt.new('DELAY', [false, "Delay in milliseconds between transmissions", 500])
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

    print_status("Starting frequency: #{datastore['FREQLOW']}")
    print_status("Ending frequency: #{datastore['FREQHIGH']}")

    if datastore["FREQHIGH"] < datastore["FREQLOW"]
      print_error("End frequency is lower than start frequency. I don't count backwards.")
      return
    else
      print_status("Frequency range is: #{datastore['FREQHIGH'] - datastore['FREQLOW']}")
    end

    set_modulation("ASK/OOK")
    set_freq(datastore["FREQLOW"])
    set_sync_mode(0)
    set_flen(0)
    set_baud(datastore["BAUD"])
    set_lowball
    max_power

    print_status("Giving the radio a second to settle in...") if datastore["VERBOSE"]
    sleep(1)

    # init some placeholders
    s = Hash.new(0)
    current_frequency = datastore["FREQLOW"]
    scan_loops = datastore["SCANLOOPS"]

    # search
    while scan_loops > 0 do

      if current_frequency > datastore["FREQHIGH"]
        print_status("Reached the frequency high, restarting at low. #{scan_loops-1} scan loops left")
        current_frequency = datastore["FREQLOW"]
        scan_loops -= 1
      end

      set_freq(current_frequency)
      print_good("Checking frequency: #{current_frequency}") if datastore["VERBOSE"]

      rf_data = rfrecv()

      if rf_data.length > 0
        rf_data = rf_data["data"].unpack("H*")[0]

        # 38 zero's seem like a good thumb suck indicator
        if rf_data.include? "0"*38
         print_good("Got something on: #{current_frequency}")
         s[current_frequency] += 1
        end
      end

      current_frequency += 50000
    end

    print_status("Done")
    set_mode("IDLE")

    # output results
    if s.length <= 0
      print_error("No signals were found")
      return
    end

    print_good("Symbol Count per Frequency")
    s.sort_by {|_key, value| value}.each do |frequency, symbol_count|
     print_good("#{symbol_count}: #{frequency}")
    end
  end

end
