sysmon_and_event_log_phrases_to_delete = [
# These are phrases highly likely not to be malicious.
    # Remember, there are always exceptions!
    # Remember, everything is case sensitive!
    ###########################################
    ##########################################
    #########################################


    # rundll32
    r":\"\\\\\\\"C:\Windows\system32\rundll32.exe\\\\\\\" C:\Windows\system32\PcaSvc.dll,PcaPatchSdbTask",

    # certutil
    r"",

    # powershell
    r"",

    # EDR
    r"",

    # Patch tool
    r"",

]
