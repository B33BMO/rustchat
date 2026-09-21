# The README's demo GIF. Render it with docs/record-demo.sh, which starts a
# local relay, generates throwaway keys and runs docs/demo-partner.py to play
# the other side of the conversation.
#
#   sh docs/record-demo.sh
#
# The invite arrives in RUSTCHAT_INVITE from that script, so nothing secret is
# written down here.

Output "docs/demo.gif"
Require rustchat

Set Shell "bash"
Set FontSize 15
Set Width 1080
Set Height 500
Set Padding 18
Set Framerate 20
Set TypingSpeed 60ms
Set WaitTimeout 60s
Set Theme { "background": "#0f1116", "foreground": "#c8cdd6", "cursor": "#7ee7d1", "selection": "#2a2f3a", "black": "#0f1116", "red": "#e76f51", "green": "#92d17d", "yellow": "#f0c86e", "blue": "#81b8ef", "magenta": "#c59ae8", "cyan": "#7ee7d1", "white": "#c8cdd6", "brightBlack": "#7a8494", "brightRed": "#e76f51", "brightGreen": "#92d17d", "brightYellow": "#f0c86e", "brightBlue": "#81b8ef", "brightMagenta": "#c59ae8", "brightCyan": "#7ee7d1", "brightWhite": "#ffffff" }

# Join off-camera, so the GIF opens on the room rather than on a shell prompt
# and a connection wait.
Hide
Type "clear"
Enter
Type "rustchat --no-vault -u bmo"
Enter
Wait+Screen /online/
Sleep 1500ms
Show

Sleep 1200ms
Type "yep, behind the tunnel now"
Enter

# sam answers when he sees "tunnel". Wait on the whole screen, not the cursor
# line, since his reply lands up in the transcript rather than where we type.
Wait+Screen /byte/
Sleep 900ms
Type "nope. only ciphertext and a room id"
Enter

Sleep 1400ms
Type "/who"
Enter

# sam's closing line, four seconds after he sees "ciphertext".
Wait+Screen /perfect/
Sleep 2500ms

Hide
Ctrl+C
