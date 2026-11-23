#!/bin/sh
# Installs the SSH settings of a sandbox service, as "trajrl setup" runs it
# (internal/sshsetup, embedded). On macOS, Linux or WSL.
#
# Next to it: ssh_config (the "Host *.DOMAIN" lines, their ProxyCommand the
# trajrl that runs setup), domain (DOMAIN), and, after an older setup,
# legacy_pin (the known_hosts line that setup pinned the entry point's key
# with). The lines go to the top of config in a block marked for DOMAIN.
# An older setup's block for the same domain ("# BEGIN sandbox SSH entry:
# NAME", with ProxyJump) is taken out, and with legacy_pin that pin too:
# trajrl proxy pins the entry point's key itself.
#
# With --remove it takes them out again. An optional SSH directory lets it
# be tried without touching ~/.ssh.
set -eu
die() { echo "STOP: $*" >&2; exit 1; }
remove=
if [ "${1:-}" = --remove ]; then remove=1; shift; fi
[ "$#" -le 1 ] || die "usage: $0 [--remove] [ssh-directory]"
kit=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ssh_dir=${1:-$HOME/.ssh}
for tool in ssh ssh-keygen awk mktemp; do
    command -v "$tool" >/dev/null || die "$tool is required"
done
[ -s "$kit/ssh_config" ] && [ -s "$kit/domain" ] || die "keep this script next to ssh_config and domain"
read -r domain < "$kit/domain"
case "$domain" in ''|.*|*[!a-z0-9.-]*) die "invalid domain" ;; esac
begin="# BEGIN trajrl ssh: $domain"
end="# END trajrl ssh: $domain"

# The older setup's pin, if any: NAME KEYTYPE KEY, NAME being [HOST]:PORT
# or HOST.
pin_host= key_type= key_data=
if [ -s "$kit/legacy_pin" ]; then
    read -r pin_host key_type key_data rest < "$kit/legacy_pin"
    [ -z "$rest" ] || die "expected one pinned entry key"
    case "$pin_host" in ''|*[!][a-zA-Z0-9._:-]*) die "invalid entry name in legacy_pin" ;; esac
    ssh-keygen -lf "$kit/legacy_pin" >/dev/null || die "invalid entry host key in legacy_pin"
fi

# ends_in_newline FILE prints 1 if FILE's last byte is a newline, else 0.
ends_in_newline() { tail -c 1 "$1" | wc -l | tr -d ' '; }

# without_block FILE prints FILE without the managed block, and without an
# older setup's block whose lines are for *.DOMAIN. Its other bytes stay as
# they are: a last line without a newline keeps none.
without_block() {
    awk -v begin="$begin" -v end="$end" -v pat="Host *.$domain" -v nl="$(ends_in_newline "$1")" '
        function emit(line) { if (have) print prev; prev = line; have = 1 }
        $0 == begin { inside = 1; next }
        $0 == end { inside = 0; next }
        inside { next }
        !old && index($0, "# BEGIN sandbox SSH entry: ") == 1 {
            old = 1; n = 0; mine = 0; name = substr($0, 28); buf[++n] = $0; next
        }
        old {
            buf[++n] = $0
            if ($0 == pat || index($0, pat " ") == 1) mine = 1
            if ($0 == "# END sandbox SSH entry: " name) {
                old = 0
                if (!mine) for (i = 1; i <= n; i++) emit(buf[i])
            }
            next
        }
        { emit($0) }
        END {
            if (inside || old) exit 1
            if (have) { printf "%s", prev; if (nl > 0) printf "\n" }
        }
    ' "$1"
}

# without_pin FILE prints the known_hosts FILE without the lines that pin
# the older setup's key for the entry point, hashed ones too, each with the
# empty line that setup put before it. Another key under that name is not
# setup's and stays.
without_pin() {
    pins=$(ssh-keygen -F "$pin_host" -f "$1" | awk -v t="$key_type" -v k="$key_data" '
        /^# Host / { n = ""; for (i = 1; i < NF; i++) if ($i == "line") n = $(i + 1); next }
        n != "" && $1 !~ /^@/ && $2 == t && $3 == k { printf "%s ", n }
        { n = "" }
    ') || :
    awk -v pins="$pins" -v nl="$(ends_in_newline "$1")" '
        BEGIN { n = split(pins, p, " "); for (i = 1; i <= n; i++) pin[p[i]] = 1 }
        NR in pin { if (have && prev == "") have = 0; next }
        { if (have) print prev; prev = $0; have = 1 }
        END { if (have) { printf "%s", prev; if (nl > 0) printf "\n" } }
    ' "$1"
}

if [ -n "$remove" ] && [ ! -d "$ssh_dir" ]; then
    echo "Nothing of trajrl's is installed in $ssh_dir."
    exit 0
fi
umask 077
mkdir -p "$ssh_dir"
ssh_dir=$(CDPATH= cd -- "$ssh_dir" && pwd)
work=$(mktemp -d "$ssh_dir/.trajrl-ssh.XXXXXX")
trap 'rm -rf "$work"' 0
trap 'exit 1' HUP INT TERM

: > "$work/rest"
if [ -f "$ssh_dir/config" ]; then
    without_block "$ssh_dir/config" > "$work/rest" ||
        die "the managed block in $ssh_dir/config is incomplete; nothing was changed"
fi
if [ -n "$pin_host" ] && [ -f "$ssh_dir/known_hosts" ]; then
    without_pin "$ssh_dir/known_hosts" > "$work/known_hosts"
fi

if [ -n "$remove" ]; then
    cp "$work/rest" "$work/config"
else
    # In an SSH directory other than ~/.ssh the sandbox lines name that
    # directory's known-hosts files, so that a trial there reads nothing
    # of ~/.ssh.
    home_ssh=$(CDPATH= cd -- "${HOME:-}/.ssh" 2>/dev/null && pwd) || home_ssh=
    if [ "$ssh_dir" = "$home_ssh" ]; then
        cat "$kit/ssh_config" > "$work/block"
    else
        case "$ssh_dir" in *'"'*|*'\'*) die "ssh_config cannot name $ssh_dir: choose a directory without a quote or backslash in its name" ;; esac
        SBX_SSH_DIR=$ssh_dir awk '
            NF == 3 && $1 == "UserKnownHostsFile" && $2 == "~/.ssh/known_hosts" && $3 == "~/.ssh/sbx_known_hosts" {
                d = ENVIRON["SBX_SSH_DIR"]; gsub(/%/, "%%", d)
                printf "    UserKnownHostsFile \"%s/known_hosts\" \"%s/sbx_known_hosts\"\n", d, d
                next
            }
            { print }
        ' "$kit/ssh_config" > "$work/block"
    fi
    {
        printf '%s\n' "$begin"
        cat "$work/block"
        # Restore global scope before the user's original configuration.
        printf '\nHost *\n%s\n' "$end"
        cat "$work/rest"
    } > "$work/config"
    ssh -G -T -F "$work/config" "trajrl-check.$domain" > /dev/null || die "the combined SSH config is invalid"
fi

# The block goes first: OpenSSH uses the first value it sees, so an earlier
# Host * must not override these lines. A file that changes is backed up
# first; one left with nothing in it is removed.
changed= label=before-entry
[ -z "$remove" ] || label=before-remove
for file in config known_hosts; do
    [ -f "$work/$file" ] || continue
    if [ -f "$ssh_dir/$file" ] && cmp -s "$work/$file" "$ssh_dir/$file"; then continue; fi
    [ -f "$ssh_dir/$file" ] || [ -s "$work/$file" ] || continue
    if [ -e "$ssh_dir/$file" ]; then
        backup=$(mktemp "$ssh_dir/$file.$label.XXXXXX")
        cp -p "$ssh_dir/$file" "$backup"
        echo "Backup: $backup"
    fi
    if [ -s "$work/$file" ]; then
        cat "$work/$file" > "$ssh_dir/$file"
        chmod 600 "$ssh_dir/$file"
    else
        rm -f "$ssh_dir/$file"
    fi
    changed=1
done
if [ -n "$remove" ]; then
    if [ -n "$changed" ]; then
        echo "Removed trajrl's lines for *.$domain from $ssh_dir."
    else
        echo "Nothing of trajrl's is installed in $ssh_dir."
    fi
    exit 0
fi
echo "Installed trajrl's lines for *.$domain in $ssh_dir."
