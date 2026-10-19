# fish completion for wombat, the command line of Wombat (https://wombat.vpetkov.net).
#
# The Homebrew cask links this file into $(brew --prefix)/share/fish/vendor_completions.d.
# To set it up by hand:
#   wombat completion fish > ~/.config/fish/completions/wombat.fish

# Tunnel names come from `wombat _names`: from the app when it's running, else from macOS; it
# never launches the app and prints each name sanitized. --state adds a tab and the state, which
# fish shows as the description; each line is one literal candidate. For up/connect it lists
# the tunnels that aren't connected, for down/disconnect the connected ones (all when none match).
function __wombat_tunnels
    set -l cmd
    for token in (commandline -opc)[2..-1]
        switch $token
            case '-*'
            case up connect down disconnect
                set cmd $token
                break
            case '*'
                break
        end
    end
    wombat _names --state $cmd 2>/dev/null
end

# The arguments after the command, without flags and option values.
function __wombat_args
    set -l tokens (commandline -opc)
    set -e tokens[1]
    set -l skip 0
    set -l seen_command 0
    for token in $tokens
        if test $skip -eq 1
            set skip 0
            continue
        end
        switch $token
            case --name --last --dir
                set skip 1
            case '-?*'
            case '*'
                if test $seen_command -eq 1
                    echo $token
                end
                set seen_command 1
        end
    end
end

# True when the command is one of the given names and N arguments come before the cursor.
function __wombat_at
    set -l count $argv[1]
    set -e argv[1]
    __fish_seen_subcommand_from $argv; or return 1
    test (count (__wombat_args)) -eq $count
end

# True after `wombat completion <action>` for one of the given actions.
function __wombat_setup
    __fish_seen_subcommand_from completion; or return 1
    set -l args (__wombat_args)
    test (count $args) -ge 1; and contains -- $args[1] $argv
end

set -l commands status list ls up connect down disconnect toggle show import export rename \
    delete rm ondemand killswitch log logs routes dns dnsleak doctor check lint genkey pubkey \
    genpsk completion install-skill install-skills start stop quit version help
set -l no_command "not __fish_seen_subcommand_from $commands"

complete -c wombat -f
complete -c wombat -n $no_command -s h -l help -d 'Show help'
complete -c wombat -n $no_command -s v -l version -d 'Print the version'

complete -c wombat -n $no_command -a 'status list ls' -d 'Show tunnels and their state'
complete -c wombat -n $no_command -a 'up connect' -d 'Connect a tunnel'
complete -c wombat -n $no_command -a 'down disconnect' -d 'Disconnect one tunnel, or all'
complete -c wombat -n $no_command -a toggle -d 'Connect or disconnect a tunnel'
complete -c wombat -n $no_command -a show -d 'Live peers, handshakes and transfer'
complete -c wombat -n $no_command -a import -d 'Add a tunnel or AnyConnect VPN from a file'
complete -c wombat -n $no_command -a export -d "Print a tunnel's config"
complete -c wombat -n $no_command -a rename -d 'Rename a tunnel'
complete -c wombat -n $no_command -a 'delete rm' -d 'Delete a tunnel'
complete -c wombat -n $no_command -a ondemand -d 'Connect automatically, or trust a Wi-Fi network'
complete -c wombat -n $no_command -a killswitch -d 'Block traffic outside the tunnel'
complete -c wombat -n $no_command -a log -d 'Recent log lines from a running tunnel'
complete -c wombat -n $no_command -a logs -d 'App and extension logs'
complete -c wombat -n $no_command -a routes -d 'Routes through tunnel interfaces'
complete -c wombat -n $no_command -a 'dns dnsleak' -d 'Resolvers in use, and whether they are tunneled'
complete -c wombat -n $no_command -a doctor -d 'Check the install, extension, app and socket'
complete -c wombat -n $no_command -a 'check lint' -d 'Lint wg-quick files and .anyconnect profiles'
complete -c wombat -n $no_command -a genkey -d 'New private key'
complete -c wombat -n $no_command -a pubkey -d 'Public key for the private key on stdin'
complete -c wombat -n $no_command -a genpsk -d 'New preshared key'
complete -c wombat -n $no_command -a completion -d 'Print a shell completion script'
complete -c wombat -n $no_command -a install-skill -d 'Teach coding agents to use wombat'
complete -c wombat -n $no_command -a start -d 'Launch the app'
complete -c wombat -n $no_command -a 'stop quit' -d 'Quit the app (tunnels keep running)'
complete -c wombat -n $no_command -a version -d 'Print the version'
complete -c wombat -n $no_command -a help -d 'Show help'

# Tunnel names
complete -c wombat -n '__wombat_at 0 status list ls up connect down disconnect toggle export rename delete rm log ondemand killswitch' \
    -a '(__wombat_tunnels)'
complete -c wombat -n '__fish_seen_subcommand_from show' -a '(__wombat_tunnels)'

# Flags
complete -c wombat -n '__fish_seen_subcommand_from status list ls up connect down disconnect toggle show import ondemand check lint' \
    -l json -d 'Print JSON'
complete -c wombat -n '__fish_seen_subcommand_from import' -l name -x -d 'Name for the new tunnel'
complete -c wombat -n '__wombat_at 0 import' -F -d 'Config file'
complete -c wombat -n '__fish_seen_subcommand_from export' -l with-keys -d 'Include private keys (Touch ID or password)'
complete -c wombat -n '__wombat_at 1 ondemand' -a on -d 'Connect automatically'
complete -c wombat -n '__wombat_at 1 ondemand' -a off -d 'Stop connecting automatically'
complete -c wombat -n '__wombat_at 1 ondemand' -a trust -d 'Disconnect on a Wi-Fi network'
complete -c wombat -n '__wombat_at 1 ondemand' -a untrust -d 'Stop trusting a Wi-Fi network'
complete -c wombat -n '__fish_seen_subcommand_from ondemand' -l wifi -d 'Connect on Wi-Fi'
complete -c wombat -n '__fish_seen_subcommand_from ondemand' -l no-wifi -d 'Do not connect on Wi-Fi'
complete -c wombat -n '__fish_seen_subcommand_from ondemand' -l ethernet -d 'Connect on Ethernet'
complete -c wombat -n '__fish_seen_subcommand_from ondemand' -l no-ethernet -d 'Do not connect on Ethernet'
complete -c wombat -n '__wombat_at 1 killswitch' -a on -d 'Block traffic outside the tunnel'
complete -c wombat -n '__wombat_at 1 killswitch' -a off -d 'Turn the kill switch off'
complete -c wombat -n '__fish_seen_subcommand_from killswitch' -l allow-lan -d 'Let local network traffic through'
complete -c wombat -n '__fish_seen_subcommand_from logs' -s f -l follow -d 'Stream new log lines'
complete -c wombat -n '__fish_seen_subcommand_from logs' -l last -x -d 'How far back to show (like 10m, 1h)'
complete -c wombat -n '__fish_seen_subcommand_from check lint' -F -d 'Config file'
complete -c wombat -n '__fish_seen_subcommand_from check lint' -l strict -d 'Also exit 1 on security risks'
complete -c wombat -n '__wombat_at 0 completion' -a install -d 'Set up Tab completion for your shells'
complete -c wombat -n '__wombat_at 0 completion' -a status -d 'Show what install set up'
complete -c wombat -n '__wombat_at 0 completion' -a uninstall -d 'Remove what install set up'
complete -c wombat -n '__wombat_at 0 completion' -a 'zsh bash fish' -d 'Print the script'
complete -c wombat -n '__wombat_setup install uninstall status' -a 'zsh bash fish' -d Shell
complete -c wombat -n '__wombat_setup install uninstall' -s n -l dry-run -d 'Show what would change, change nothing'
complete -c wombat -n '__wombat_setup install' -l force -d "Replace a file that isn't Wombat's (kept as a backup)"
complete -c wombat -n '__wombat_setup install' -s y -l yes -d 'Change shell startup files without asking'
complete -c wombat -n '__wombat_setup install' -l dir -x -a '(__fish_complete_directories)' -d 'Put the file in this folder'
complete -c wombat -n '__fish_seen_subcommand_from install-skill install-skills' -l dir -x -a '(__fish_complete_directories)' -d 'Directory for SKILL.md'
