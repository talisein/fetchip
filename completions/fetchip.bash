# bash completion for fetchip

_fetchip()
{
    local cur prev words cword split
    _init_completion -s || return

    case $prev in
        -s | --service)
            COMPREPLY=($(compgen -W "$("$1" --list type 2>/dev/null)" -- "$cur"))
            return
            ;;
        -n | --name)
            COMPREPLY=($(compgen -W "$("$1" --list name 2>/dev/null)" -- "$cur"))
            return
            ;;
    esac

    $split && return

    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W '-h --help -s --service -n --name -i --insecure
            -v --verbose -4 -6' -- "$cur"))
    fi
} &&
    complete -F _fetchip fetchip
