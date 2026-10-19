# bash completion for wombat, the command line of Wombat (https://wombat.vpetkov.net).
#
# The Homebrew cask links this file into $(brew --prefix)/etc/bash_completion.d, which
# bash-completion loads (brew install bash-completion@2). To set it up by hand, save it where
# bash-completion 2 finds it:
#   wombat completion bash > ~/.local/share/bash-completion/completions/wombat
# or, without bash-completion, add this to ~/.bashrc (works in macOS's bash 3.2 too):
#   eval "$(wombat completion bash)"

# COMPREPLY=($(compgen ...)) splits on purpose: the word lists are fixed words, and file names are
# split on newlines only. (mapfile would need bash 4.)
# shellcheck disable=SC2207

# Tunnel names come from `wombat _names`: from the app when it's running, else from macOS; it
# never launches the app and prints each name sanitized. For up/connect it lists the tunnels
# that aren't connected, for down/disconnect the connected ones (all when none match). Names are
# compared and quoted here, never passed to `compgen -W`, which would expand $(...) inside a
# name taken from a downloaded file.
_wombat_tunnels() {
    local word=${cur#[\"\']} name for=""
    word=${word//\\/}
    case $cmd in up | connect | down | disconnect) for=$cmd ;; esac
    while IFS= read -r name; do
        [[ -n $name && $name == "$word"* ]] && COMPREPLY+=("$(printf '%q' "$name")")
    done < <(wombat _names ${for:+"$for"} 2>/dev/null)
    if declare -F __ltrim_colon_completions >/dev/null; then __ltrim_colon_completions "$cur"; fi
}

# Files (or directories with -d), quoted for the shell. bash 3.2 has no compopt: there an empty
# reply falls back to readline's own file completion (see `complete -o default` below).
_wombat_files() {
    if declare -F _filedir >/dev/null; then
        _filedir "$@"
    elif type compopt >/dev/null 2>&1; then
        compopt -o filenames
        local IFS=$'\n'
        if [[ $1 == -d ]]; then COMPREPLY=($(compgen -d -- "$cur")); else COMPREPLY=($(compgen -f -- "$cur")); fi
    fi
}

_wombat() {
    local cur prev words cword
    if declare -F _get_comp_words_by_ref >/dev/null; then
        _get_comp_words_by_ref -n =: cur prev words cword
    else
        cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]} cword=$COMP_CWORD
        words=("${COMP_WORDS[@]}")
    fi
    COMPREPLY=()

    local commands="status list ls up connect down disconnect toggle show import export rename
        delete rm ondemand killswitch log logs routes dns dnsleak doctor check lint genkey pubkey
        genpsk completion install-skill start stop quit version help"

    # The command, and the arguments before the cursor without flags and option values.
    local cmd="" word i skip=0
    local -a args=()
    for ((i = 1; i < cword; i++)); do
        word=${words[i]}
        if ((skip)); then skip=0; continue; fi
        case $word in
            --name | --last | --dir) skip=1 ;;
            -?*) [[ -n $cmd ]] || cmd=$word ;;
            *) if [[ -z $cmd ]]; then cmd=$word; else args+=("$word"); fi ;;
        esac
    done
    local pos=${#args[@]}

    if [[ -z $cmd ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return
    fi

    case $prev in
        --name | --last) return ;;  # free text
        --dir) _wombat_files -d; return ;;
    esac

    if [[ $cur == -?* || ($cur == - && $cmd != import && $cmd != check && $cmd != lint) ]]; then
        local flags=""
        case $cmd in
            status | list | ls | up | connect | down | disconnect | toggle | show) flags="--json" ;;
            import) flags="--name --json" ;;
            export) flags="--with-keys" ;;
            ondemand) flags="--wifi --no-wifi --ethernet --no-ethernet --json" ;;
            killswitch) flags="--allow-lan" ;;
            logs) flags="-f --follow --last" ;;
            check | lint) flags="--strict --json" ;;
            install-skill | install-skills) flags="--dir" ;;
            completion)
                case ${args[0]} in
                    install) flags="--dry-run --force --yes --dir" ;;
                    uninstall) flags="--dry-run" ;;
                esac ;;
        esac
        COMPREPLY=($(compgen -W "$flags" -- "$cur"))
        return
    fi

    case $cmd in
        status | list | ls | up | connect | down | disconnect | toggle | export | rename | delete | rm | log)
            ((pos == 0)) && _wombat_tunnels ;;
        show) _wombat_tunnels ;;
        ondemand)
            case $pos in
                0) _wombat_tunnels ;;
                1) COMPREPLY=($(compgen -W "on off trust untrust" -- "$cur")) ;;
            esac ;;
        killswitch)
            case $pos in
                0) _wombat_tunnels ;;
                1) COMPREPLY=($(compgen -W "on off" -- "$cur")) ;;
            esac ;;
        import) ((pos == 0)) && _wombat_files ;;
        check | lint) _wombat_files ;;
        completion)
            if ((pos == 0)); then
                COMPREPLY=($(compgen -W "install status uninstall zsh bash fish" -- "$cur"))
            elif [[ ${args[0]} == install || ${args[0]} == uninstall || ${args[0]} == status ]]; then
                COMPREPLY=($(compgen -W "zsh bash fish" -- "$cur"))
            fi ;;
    esac
    return 0
}

if ((BASH_VERSINFO[0] < 4)); then
    complete -o default -F _wombat wombat
else
    complete -F _wombat wombat
fi
