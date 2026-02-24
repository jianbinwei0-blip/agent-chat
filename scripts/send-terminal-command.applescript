on _trim(textValue)
    set t to textValue as text
    set oldDelims to AppleScript's text item delimiters
    set AppleScript's text item delimiters to {space, tab, return, linefeed}
    set parts to text items of t
    set AppleScript's text item delimiters to ""
    set compact to parts as text
    set AppleScript's text item delimiters to oldDelims
    return compact
end _trim

on _contains_ci(haystack, needle)
    if needle is "" then return false
    considering case
        set hayLower to do shell script "/bin/echo " & quoted form of (haystack as text) & " | /usr/bin/tr '[:upper:]' '[:lower:]'"
        set needleLower to do shell script "/bin/echo " & quoted form of (needle as text) & " | /usr/bin/tr '[:upper:]' '[:lower:]'"
    end considering
    return (hayLower contains needleLower)
end _contains_ci

on _basename(pathText)
    set trimmed to my _trim(pathText)
    if trimmed is "" then return ""
    try
        set base to do shell script "/usr/bin/basename " & quoted form of trimmed
        return my _trim(base)
    on error
        return trimmed
    end try
end _basename

on _window_matches(titleText, sidToken)
    set t to titleText as text
    if sidToken is not "" then
        if my _contains_ci(t, sidToken) then return true
    end if
    return false
end _window_matches

on _try_terminal(ttyTarget, sidToken, inputText)
    tell application "Terminal"
        if not running then return "MISS:app-not-running"
        repeat with w in windows
            repeat with t in tabs of w
                set matched to false

                if ttyTarget is not "" then
                    try
                        set tabTTY to tty of t as text
                        if tabTTY is ttyTarget then set matched to true
                    end try
                end if

                if not matched then
                    try
                        set c to contents of t as text
                        if sidToken is not "" and my _contains_ci(c, sidToken) then set matched to true
                    end try
                end if

                if matched then
                    do script inputText in t
                    return "OK:terminal"
                end if
            end repeat
        end repeat
    end tell
    return "MISS:no-terminal-match"
end _try_terminal

on _try_iterm(appName, ttyTarget, sidToken, inputText)
    tell application appName
        if not running then return "MISS:app-not-running"
        repeat with w in windows
            repeat with t in tabs of w
                repeat with s in sessions of t
                    set matched to false

                    if ttyTarget is not "" then
                        try
                            set sessionTTY to tty of s as text
                            if sessionTTY is ttyTarget then set matched to true
                        end try
                    end if

                    if not matched then
                        try
                            set c to contents of s as text
                            if sidToken is not "" and my _contains_ci(c, sidToken) then set matched to true
                        end try
                    end if

                    if matched then
                        tell s to write text inputText
                        return "OK:iterm"
                    end if
                end repeat
            end repeat
        end repeat
    end tell
    return "MISS:no-iterm-match"
end _try_iterm

on _try_generic(appName, sidToken, inputText)
    try
        tell application appName to activate
    on error
        return "MISS:app-not-running"
    end try

    delay 0.05

    tell application "System Events"
        if not (exists process appName) then return "MISS:app-not-running"
        set p to first process whose name is appName

        set targetWindow to missing value
        set matchedCount to 0
        set winCount to count of windows of p
        repeat with w in windows of p
            set titleText to ""
            try
                set titleText to name of w as text
            end try

            if my _window_matches(titleText, sidToken) then
                set matchedCount to matchedCount + 1
                set targetWindow to w
            end if
        end repeat

        if matchedCount = 0 then
            if winCount is 1 then
                set targetWindow to window 1 of p
            else
                return "MISS:window-ambiguous"
            end if
        else if matchedCount > 1 then
            return "MISS:window-ambiguous"
        end if

        set frontmost of p to true
        if targetWindow is not missing value then
            try
                perform action "AXRaise" of targetWindow
            end try
        end if

        keystroke inputText
        key code 36
    end tell

    return "OK:generic"
end _try_generic

on run argv
    if (count of argv) < 5 then error "Usage: send-terminal-command.applescript <terminal_app> <terminal_tty> <terminal_session_id> <session_id> <prompt_text>" number 64

    set terminalApp to my _trim(item 1 of argv)
    set terminalTTY to my _trim(item 2 of argv)
    set _terminalSessionID to my _trim(item 3 of argv)
    set sessionID to my _trim(item 4 of argv)
    set inputText to item 5 of argv

    if terminalApp is "" then return "MISS:terminal-app-missing"
    if inputText is "" then return "MISS:prompt-missing"

    set sidToken to sessionID
    if (length of sidToken) > 8 then set sidToken to text 1 thru 8 of sidToken

    if terminalApp is "Terminal" then
        return my _try_terminal(terminalTTY, sidToken, inputText)
    end if

    if terminalApp is "iTerm2" or terminalApp is "iTerm" then
        try
            return my _try_iterm("iTerm2", terminalTTY, sidToken, inputText)
        on error
            return my _try_iterm("iTerm", terminalTTY, sidToken, inputText)
        end try
    end if

    return my _try_generic(terminalApp, sidToken, inputText)
end run
