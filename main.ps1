<#
.SYNOPSIS
    .
.DESCRIPTION
    .
.PARAMETER Path
    The path to the .
.PARAMETER LiteralPath
    Specifies a path to one or more locations. Unlike Path, the value of 
    LiteralPath is used exactly as it is typed. No characters are interpreted 
    as wildcards. If the path includes escape characters, enclose it in single
    quotation marks. Single quotation marks tell Windows PowerShell not to 
    interpret any characters as escape sequences.
.EXAMPLE
    C:\PS> 
    <Description of example>
.NOTES
    Author: Ryan V
    Date:   June 19, 2017  
#>


# check to make sure all of the files are present. 
# Looking for WordList, Rules, exes, etc
if(!(Test-Path "hashcat64.exe") -Or !(Test-Path "hashcat32.exe")){
    Write-Host "Hashcat Executables not present"
    break
}

if(!(Test-Path "../WordLists") -and !(Test-Path "./rules")){
    Write-Host "Required Folders not present"
    break
}

#
# Find the hashcat exes based on os architecture
# 
if ((gwmi win32_operatingsystem | select osarchitecture).osarchitecture -eq "64-bit")
{
    #64 bit logic here
    $HASHCAT="./hashcat64.exe"
}
else
{
    #32 bit logic here
    $HASHCAT="./hashcat32.exe"
}

#
## Functions 
#

# Handle getting the input file
Function Get-FileName($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

# main run function
function run([string]$arg1){

    # start time for record keeping
    $START=(Get-Date).Millisecond

    # Call the hashcat command here. 
    Write-Host $HASHCAT $FLAGS $arg1

    # stop time for record keeping
    $STOP=$(Get-Date).Millisecond
    Write-Host "Time to Complete: "($STOP - $START)
}


$currentpath = (Get-Item -Path ".\" -Verbose).FullName
$inputfile = Get-FileName $currentpath
if(! $inputfile){
    Write-Host "No File Selected"
    break
}

# Get Company code 
$COMPANYCODE = Read-Host -Prompt 'Comapny Code'
$OUTPUT_FILE= "batchcrack_" + $COMPANYCODE + ".out"
Write-Host "Output File:" $OUTPUT_FILE

## Change the Dictionaries listed below to your favorites!
## Note: the dics listed here are only used for RULES, COMBINATOR, and HYBRID attacks. 
## The WORDLIST attack checks against all dics in the WordLists directory.
$DICT_FILE_TINY="../WordLists/john.txt"

Write-Host  '0  =  MD5'
Write-Host '10  =  md5($pass.$salt)'
Write-Host '11  =  Joomla < 2.5.18'
Write-Host '12  =  PostgreSQL'
Write-Host '20  =  md5($salt.$pass)'
Write-Host '21  =  osCommerce'
Write-Host '21  =  xt:Commerce'
Write-Host '22  =  Juniper Netscreen/SSG (ScreenOS)'
Write-Host '23  =  Skype'
Write-Host '30  =  md5(unicode($pass).$salt)'
Write-Host '40  =  md5($salt.unicode($pass))'
Write-Host '50  =  HMAC-MD5 (key  $pass)'
Write-Host '60  =  HMAC-MD5 (key  $salt)'
Write-Host '100  =  SHA1'
Write-Host '101  =  nsldap, SHA-1(Base64), Netscape LDAP SHA'
Write-Host '110  =  sha1($pass.$salt)'
Write-Host '111  =  nsldaps, SSHA-1(Base64), Netscape LDAP SSHA'
Write-Host '112  =  Oracle S: Type (Oracle 11+)'
Write-Host '120  =  sha1($salt.$pass)'
Write-Host '121  =  SMF (Simple Machines Forum)'
Write-Host '122  =  OSX v10.4'
Write-Host '122  =  OSX v10.5'
Write-Host '122  =  OSX v10.6'
Write-Host '124  =  Django (SHA-1)'
Write-Host '130  =  sha1(unicode($pass).$salt)'
Write-Host '131  =  MSSQL(2000)'
Write-Host '132  =  MSSQL(2005)'
Write-Host '133  =  PeopleSoft'
Write-Host '140  =  sha1($salt.unicode($pass))'
Write-Host '141  =  EPiServer 6.x < v4'
Write-Host '150  =  HMAC-SHA1 (key  $pass)'
Write-Host '160  =  HMAC-SHA1 (key  $salt)'
Write-Host '200  =  MySQL323'
Write-Host '300  =  MySQL4.1/MySQL5'
Write-Host '400  =  phpass'
Write-Host '400  =  phpBB3'
Write-Host '400  =  Joomla > 2.5.18'
Write-Host '400  =  Wordpress'
Write-Host '500  =  md5crypt $1$, MD5(Unix)'
Write-Host '500  =  Cisco-IOS $1$'
Write-Host '501  =  Juniper IVE'
Write-Host '900  =  MD4'
Write-Host '1000  =  NTLM'
Write-Host '1100  =  Domain Cached Credentials (DCC), MS Cache'
Write-Host '1400  =  SHA-256'
Write-Host '1410  =  sha256($pass.$salt)'
Write-Host '1420  =  sha256($salt.$pass)'
Write-Host '1421  =  hMailServer'
Write-Host '1430  =  sha256(unicode($pass).$salt)'
Write-Host '1440  =  sha256($salt.unicode($pass))'
Write-Host '1441  =  EPiServer 6.x > v4'
Write-Host '1450  =  HMAC-SHA256 (key  $pass)'
Write-Host '1460  =  HMAC-SHA256 (key  $salt)'
Write-Host '1500  =  descrypt, DES(Unix), Traditional DES'
Write-Host '1600  =  Apache $apr1$'
Write-Host '1700  =  SHA-512'
Write-Host '1710  =  sha512($pass.$salt)'
Write-Host '1711  =  SSHA-512(Base64), LDAP {SSHA512}'
Write-Host '1720  =  sha512($salt.$pass)'
Write-Host '1722  =  OSX v10.7'
Write-Host '1730  =  sha512(unicode($pass).$salt)'
Write-Host '1731  =  MSSQL(2012)'
Write-Host '1731  =  MSSQL(2014)'
Write-Host '1740  =  sha512($salt.unicode($pass))'
Write-Host '1750  =  HMAC-SHA512 (key  $pass)'
Write-Host '1760  =  HMAC-SHA512 (key  $salt)'
Write-Host '1800  =  sha512crypt $6$, SHA512(Unix)'
Write-Host '2100  =  Domain Cached Credentials 2 (DCC2), MS Cache 2'
Write-Host '2400  =  Cisco-PIX'
Write-Host '2410  =  Cisco-ASA'
Write-Host '2500  =  WPA/WPA2'
Write-Host '2600  =  md5(md5($pass)'
Write-Host '2611  =  vBulletin < v3.8.5'
Write-Host '2612  =  PHPS'
Write-Host '2711  =  vBulletin > v3.8.5'
Write-Host '2811  =  MyBB'
Write-Host '2811  =  IPB (Invison Power Board)'
Write-Host '3000  =  LM'
Write-Host '3100  =  Oracle H: Type (Oracle 7+)'
Write-Host '3200  =  bcrypt $2*$, Blowfish(Unix)'
Write-Host '3710  =  md5($salt.md5($pass))'
Write-Host '3711  =  Mediawiki B type'
Write-Host '3800  =  md5($salt.$pass.$salt)'
Write-Host '4300  =  md5(strtoupper(md5($pass)))'
Write-Host '4400  =  md5(sha1($pass))'
Write-Host '4500  =  sha1(sha1($pass)'
Write-Host '4700  =  sha1(md5($pass))'
Write-Host '4800  =  iSCSI CHAP authentication, MD5(Chap)'
Write-Host '4900  =  sha1($salt.$pass.$salt)'
Write-Host '5000  =  SHA-3(Keccak)'
Write-Host '5100  =  Half MD5'
Write-Host '5200  =  Password Safe v3'
Write-Host '5300  =  IKE-PSK MD5'
Write-Host '5400  =  IKE-PSK SHA1'
Write-Host '5500  =  NetNTLMv1'
Write-Host '5500  =  NetNTLMv1 + ESS'
Write-Host '5600  =  NetNTLMv2'
Write-Host '5700  =  Cisco-IOS $4$'
Write-Host '5800  =  Android PIN'
Write-Host '6000  =  RipeMD160'
Write-Host '6100  =  Whirlpool'
Write-Host '6300  =  AIX {smd5}'
Write-Host '6400  =  AIX {ssha256}'
Write-Host '6500  =  AIX {ssha512}'
Write-Host '6600  =  1Password, agilekeychain'
Write-Host '6700  =  AIX {ssha1}'
Write-Host '6800  =  Lastpass'
Write-Host '6900  =  GOST R 34.11-94'
Write-Host '7100  =  OSX v10.8'
Write-Host '7100  =  OSX v10.9'
Write-Host '7100  =  OSX v10.10'
Write-Host '7200  =  GRUB 2'
Write-Host '7300  =  IPMI2 RAKP HMAC-SHA1'
Write-Host '7400  =  sha256crypt $5$, SHA256(Unix)'
Write-Host '7500  =  Kerberos 5 AS-REQ Pre-Auth etype 23'
Write-Host '7600  =  Redmine'
Write-Host '7700  =  SAP CODVN B (BCODE)'
Write-Host '7800  =  SAP CODVN F/G (PASSCODE)'
Write-Host '7900  =  Drupal7'
Write-Host '8000  =  Sybase ASE'
Write-Host '8100  =  Citrix Netscaler'
Write-Host '8200  =  1Password, cloudkeychain'
Write-Host '8300  =  DNSSEC (NSEC3)'
Write-Host '8400  =  WBB3 (Woltlab Burning Board)'
Write-Host '8500  =  RACF'
Write-Host '8600  =  Lotus Notes/Domino 5'
Write-Host '8700  =  Lotus Notes/Domino 6'
Write-Host '8800  =  Android FDE < v4.3'
Write-Host '8900  =  scrypt'
Write-Host '9000  =  Password Safe v2'
Write-Host '9100  =  Lotus Notes/Domino 8'
Write-Host '9200  =  Cisco-IOS $8$'
Write-Host '9300  =  Cisco-IOS $9$'
Write-Host '9400  =  MS Office 2007'
Write-Host '9500  =  MS Office 2010'
Write-Host '9600  =  MS Office 2013'
Write-Host '9900  =  Radmin2'
Write-Host '10000  =  Django (PBKDF2-SHA256)'
Write-Host '10100  =  SipHash'
Write-Host '10200  =  Cram MD5'
Write-Host '10300  =  SAP CODVN H (PWDSALTEDHASH) iSSHA-1'
Write-Host '10400  =  PDF 1.1 - 1.3 (Acrobat 2 - 4)'
Write-Host '10410  =  PDF 1.1 - 1.3 (Acrobat 2 - 4) + collider-mode #1'
Write-Host '10420  =  PDF 1.1 - 1.3 (Acrobat 2 - 4) + collider-mode #2'
Write-Host '10500  =  PDF 1.4 - 1.6 (Acrobat 5 - 8)'
Write-Host '10600  =  PDF 1.7 Level 3 (Acrobat 9)'
Write-Host '10700  =  PDF 1.7 Level 8 (Acrobat 10 - 11)'
Write-Host '10800  =  SHA-384'
Write-Host '10900  =  PBKDF2-HMAC-SHA256'
Write-Host '11000  =  PrestaShop'
Write-Host '11100  =  PostgreSQL Challenge-Response Authentication (MD5)'
Write-Host '11200  =  MySQL Challenge-Response Authentication (SHA1)'
Write-Host '11300  =  Bitcoin/Litecoin wallet.dat'
Write-Host '11400  =  SIP digest authentication (MD5)'
Write-Host '11500  =  CRC32'
Write-Host '11600  =  7-Zip'
Write-Host '11700  =  GOST R 34.11-2012 (Streebog) 256-bit'
Write-Host '11800  =  GOST R 34.11-2012 (Streebog) 512-bit'
Write-Host '11900  =  PBKDF2-HMAC-MD5'
Write-Host '12000  =  PBKDF2-HMAC-SHA1'
Write-Host '12100  =  PBKDF2-HMAC-SHA512'
Write-Host '12200  =  eCryptfs'
Write-Host '12300  =  Oracle T: Type (Oracle 12+)'
Write-Host '12400  =  BSDiCrypt, Extended DES'
Write-Host '12500  =  RAR3-hp'
Write-Host '12600  =  ColdFusion 10+'
Write-Host '12700  =  Blockchain, My Wallet'
Write-Host '12800  =  MS-AzureSync PBKDF2-HMAC-SHA256'
Write-Host ""

# Get Hash Mode from User Input
# Change after debugging
$HASH_MODE = Read-Host -Prompt 'Hash Mode [0]'
# setup Hashcat flags
$FLAGS = " --remove --outfile=$OUTPUT_FILE --hash-type=$HASH_MODE "


#STOP AND READ THIS SECTION
Write-Host ""
Write-Host "Wordlist Mode just does a straight check against the lists stored in the Wordlist directory.
Rules Mode runs the wordlists defined above against all the rules you select in the Rules section further down in this script.
Combinator Mode takes two wordlists, defined in that section below, and combines them in various ways.
Mask Mode does brute forcing against pre-defined masks (e.g., ?u?l?l?l?l?l?l?d?d?s, where ?=character, u=uppercase, l=lowercase, d=digit, s=symbol)
Hybrid Mode takes the defined wordlists and appends or prepends characters in a wordlist/bruteforce attack.
Bruteforce tries every combination for the defined word length."
Read-Host -Prompt "Press Enter To Continue..."

# Setup options
$WORDLIST=0
$RULES=0
$COMBINATOR=0
$MASK=0
$HYBRID=0
$BRUTEFORCE=0

# Get attack Type and setting options accordingly
Write-Host "[1]WordList`n[2]Rules`n[3]Combinator`n[4]Mask`n[5]Hybrid`n[6]BruteForce`n"
$ATTACK_TYPE = Read-Host -Prompt "What Type of Attack? [6]"
switch($ATTACK_TYPE){
    1{$WORDLIST=1}
    2{$RULES=1}
    3{$COMBINATOR=1}
    4{$MASK=1}
    5{$HYBRID=1}
    6{$BRUTEFORCE=1}
    default{$BRUTEFORCE=1}
}

#
# wordlist attacks
#
if ($WORDLIST -eq 1){
    Write-Host 'Running all ..\Dictionaries in current folder by smallest size to largest'
    Write-Host ""
    Get-ChildItem "../WordLists/" | Sort-Object length | ForEach-Object{
        # Define the per-wordlist action
        Write-Host $_.FullName
        run $_.FullName
    }
}

#
# rules attacks
#
if ($RULES -eq 1){
    # dont run all the rules ... to many dupes etc ... 
    Write-Host 'Running rules in the rules folder'
    Write-Host ""
    Get-ChildItem "./rules" | ForEach-Object{
        Write-Host $_.FullName
        $arg1 = $_.FullName + " " + $DICT_FILE_TINY
        run  $arg1
    }
}

#
# combo attacks
#
if ($COMBINATOR -eq 1){
    Write-Host 'Running combinator attacks'
    Write-Host ""
    $arg1 = "-a 1 " + $DICT_FILE_TINY + " " + $DICT_FILE_TINY
    run $arg1
}

#
# mask attacks
#
if ($MASK -eq 1){
    Write-Host 'Running mask attacks'
    Write-Host ""
    $arg1 = "-a 3 ?l?l?l?l?l?l?d?d?"
    run $arg1
}

#
# hybrid attacks
#
if ($HYBRID -eq 1){
    Write-Host 'Running hybrid attacks'
    Write-Host ""
    $arg1 = "-a 6 -1 ?l?d?s?u $DICT_FILE_TINY ?1"
    $arg2 = "-a 7 -1 ?l?d?s?u ?1 $DICT_FILE_SMALL"
    run $arg1
    run $arg2
}

#
# bruteforce attacks
#
if ($BRUTEFORCE -eq 1){
    Write-Host 'Running brute-force attacks'
    Write-Host ""
    $arg1 = "-a 3 -1 ?l?u?d?s ?1?1?1?1?1?1?1?1"
    run $arg1
}
