on run argv
    if (count of argv) < 2 then error "Usage: send-imessage.applescript <recipient> <message>" number 64

    set recipient to item 1 of argv
    set messageText to item 2 of argv

    tell application "Messages"
        if not (exists service 1) then error "No Messages service available" number 65

        set chosenService to missing value
        try
            set chosenService to 1st service whose service type = iMessage
        on error
            set chosenService to service 1
        end try

        try
            set targetBuddy to buddy recipient of chosenService
            send messageText to targetBuddy
        on error
            set targetParticipant to participant recipient of chosenService
            send messageText to targetParticipant
        end try
    end tell
end run
