#requires -version 7
$POSHPA = Split-Path -Parent $PROFILE
[void]((Test-Path $POSHPA) ?? (mkdir -p $POSHPA))
$FETCHFI = Join-Path $POSHPA fetch.ps1
Invoke-RestMethod -Uri https://raw.githubusercontent.com/Hexality/fetch/main/fetch.ps1 > $FETCHFI
"`n. $FETCHFI" >> $PROFILE
