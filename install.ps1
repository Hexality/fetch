#requires -version 7
$POSHPA = Split-Path -Parent $PROFILE
if(Test-Path $PROFILE){
  Copy-Item $PROFILE "$($PROFILE).bkp"
}
if(!(Test-Path $POSHPA)){ 
  mkdir -p $POSHPA
}
$FETCHFI = Join-Path $POSHPA fetch.ps1
Invoke-RestMethod -Uri https://raw.githubusercontent.com/Hexality/fetch/main/fetch.ps1 > $FETCHFI
"`n. $FETCHFI" >> $PROFILE
. $PROFILE
if(Test-Path $FETCHFI) { Write-Host "Successfully installed, use 'fetch' to invoke it. (use -noclear after the command to avoid it from clearing the console)" } else { "Something gone wrong..." }
