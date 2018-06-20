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
#GLOBAL Variables
$global:currentpath = (Get-Item -Path ".\" -Verbose).FullName
# Setup options
$global:WORDLIST=0
$global:RULES=0
$global:COMBINATOR=0
$global:MASK=0
$global:HYBRID=0
$global:BRUTEFORCE=0
$global:DICT
$global:DICT_ONE
$global:DICT_TWO

#
## Functions 
#

function fileCheck(){
    # check to make sure all of the files are present. 
    # Looking for WordList, Rules, exes, etc
    if(!(Test-Path "hashcat64.exe") -Or !(Test-Path "hashcat32.exe")){
        Write-Host "Hashcat Executables not present"
        # Want to grab them?  Maybe make a call to download the hashcat exes and unpack?
        break
    }

    if(!(Test-Path "../WordLists") -and !(Test-Path "./rules")){
        Write-Host "Required Folders not present"
        # Want to build them?  grab the SecLists with passwords and ./rules from hashcat?
        break
    }
    # check to see if the Output file is there.  if not build it. 
    if(!(Test-Path "./Output")){
        New-Item -Name "Output" -ItemType directory
    }

    #
    # Find the hashcat exes based on os architecture
    # 
    if ((gwmi win32_operatingsystem | select osarchitecture).osarchitecture -eq "64-bit")
    {
        #64 bit logic here
        $HASHCAT=".\hashcat64.exe"
        return $HASHCAT
    }
    else
    {
        #32 bit logic here
        $HASHCAT=".\hashcat32.exe"
        return $HASHCAT
    }
}


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
    # Call the hashcat command here. 
    Invoke-Expression "& $HASHCAT $FLAGS $INPUT_FILE $arg1"
	  #Write-Host "$HASHCAT $FLAGS $INPUT_FILE $arg1"
}

function getHashMode($CODENAME){
Write-Host $CODENAME
   Write-Host "
        # | Name                                             | Category
  ======+==================================================+======================================
    900 | MD4                                              | Raw Hash
      0 | MD5                                              | Raw Hash
   5100 | Half MD5                                         | Raw Hash
    100 | SHA1                                             | Raw Hash
   1300 | SHA-224                                          | Raw Hash
   1400 | SHA-256                                          | Raw Hash
  10800 | SHA-384                                          | Raw Hash
   1700 | SHA-512                                          | Raw Hash
   5000 | SHA-3 (Keccak)                                   | Raw Hash
    600 | BLAKE2b-512                                      | Raw Hash
  10100 | SipHash                                          | Raw Hash
   6000 | RIPEMD-160                                       | Raw Hash
   6100 | Whirlpool                                        | Raw Hash
   6900 | GOST R 34.11-94                                  | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit             | Raw Hash
  11800 | GOST R 34.11-2012 (Streebog) 512-bit             | Raw Hash
     10 | md5($pass.$salt)                                 | Raw Hash, Salted and/or Iterated
     20 | md5($salt.$pass)                                 | Raw Hash, Salted and/or Iterated
     30 | md5(utf16le($pass).$salt)                        | Raw Hash, Salted and/or Iterated
     40 | md5($salt.utf16le($pass))                        | Raw Hash, Salted and/or Iterated
   3800 | md5($salt.$pass.$salt)                           | Raw Hash, Salted and/or Iterated
   3710 | md5($salt.md5($pass))                            | Raw Hash, Salted and/or Iterated
   4010 | md5($salt.md5($salt.$pass))                      | Raw Hash, Salted and/or Iterated
   4110 | md5($salt.md5($pass.$salt))                      | Raw Hash, Salted and/or Iterated
   2600 | md5(md5($pass))                                  | Raw Hash, Salted and/or Iterated
   3910 | md5(md5($pass).md5($salt))                       | Raw Hash, Salted and/or Iterated
   4300 | md5(strtoupper(md5($pass)))                      | Raw Hash, Salted and/or Iterated
   4400 | md5(sha1($pass))                                 | Raw Hash, Salted and/or Iterated
    110 | sha1($pass.$salt)                                | Raw Hash, Salted and/or Iterated
    120 | sha1($salt.$pass)                                | Raw Hash, Salted and/or Iterated
    130 | sha1(utf16le($pass).$salt)                       | Raw Hash, Salted and/or Iterated
    140 | sha1($salt.utf16le($pass))                       | Raw Hash, Salted and/or Iterated
   4500 | sha1(sha1($pass))                                | Raw Hash, Salted and/or Iterated
   4520 | sha1($salt.sha1($pass))                          | Raw Hash, Salted and/or Iterated
   4700 | sha1(md5($pass))                                 | Raw Hash, Salted and/or Iterated
   4900 | sha1($salt.$pass.$salt)                          | Raw Hash, Salted and/or Iterated
  14400 | sha1(CX)                                         | Raw Hash, Salted and/or Iterated
   1410 | sha256($pass.$salt)                              | Raw Hash, Salted and/or Iterated
   1420 | sha256($salt.$pass)                              | Raw Hash, Salted and/or Iterated
   1430 | sha256(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated
   1440 | sha256($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated
   1710 | sha512($pass.$salt)                              | Raw Hash, Salted and/or Iterated
   1720 | sha512($salt.$pass)                              | Raw Hash, Salted and/or Iterated
   1730 | sha512(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated
   1740 | sha512($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated
     50 | HMAC-MD5 (key = $pass)                           | Raw Hash, Authenticated
     60 | HMAC-MD5 (key = $salt)                           | Raw Hash, Authenticated
    150 | HMAC-SHA1 (key = $pass)                          | Raw Hash, Authenticated
    160 | HMAC-SHA1 (key = $salt)                          | Raw Hash, Authenticated
   1450 | HMAC-SHA256 (key = $pass)                        | Raw Hash, Authenticated
   1460 | HMAC-SHA256 (key = $salt)                        | Raw Hash, Authenticated
   1750 | HMAC-SHA512 (key = $pass)                        | Raw Hash, Authenticated
   1760 | HMAC-SHA512 (key = $salt)                        | Raw Hash, Authenticated
  14000 | DES (PT = $salt, key = $pass)                    | Raw Cipher, Known-Plaintext attack
  14100 | 3DES (PT = $salt, key = $pass)                   | Raw Cipher, Known-Plaintext attack
  14900 | Skip32 (PT = $salt, key = $pass)                 | Raw Cipher, Known-Plaintext attack
  15400 | ChaCha20                                         | Raw Cipher, Known-Plaintext attack
    400 | phpass                                           | Generic KDF
   8900 | scrypt                                           | Generic KDF
  11900 | PBKDF2-HMAC-MD5                                  | Generic KDF
  12000 | PBKDF2-HMAC-SHA1                                 | Generic KDF
  10900 | PBKDF2-HMAC-SHA256                               | Generic KDF
  12100 | PBKDF2-HMAC-SHA512                               | Generic KDF
     23 | Skype                                            | Network Protocols
   2500 | WPA/WPA2                                         | Network Protocols
   2501 | WPA/WPA2 PMK                                     | Network Protocols
   4800 | iSCSI CHAP authentication, MD5(CHAP)             | Network Protocols
   5300 | IKE-PSK MD5                                      | Network Protocols
   5400 | IKE-PSK SHA1                                     | Network Protocols
   5500 | NetNTLMv1                                        | Network Protocols
   5500 | NetNTLMv1+ESS                                    | Network Protocols
   5600 | NetNTLMv2                                        | Network Protocols
   7300 | IPMI2 RAKP HMAC-SHA1                             | Network Protocols
   7500 | Kerberos 5 AS-REQ Pre-Auth etype 23              | Network Protocols
   8300 | DNSSEC (NSEC3)                                   | Network Protocols
  10200 | CRAM-MD5                                         | Network Protocols
  11100 | PostgreSQL CRAM (MD5)                            | Network Protocols
  11200 | MySQL CRAM (SHA1)                                | Network Protocols
  11400 | SIP digest authentication (MD5)                  | Network Protocols
  13100 | Kerberos 5 TGS-REP etype 23                      | Network Protocols
  16100 | TACACS+                                          | Network Protocols
  16500 | JWT (JSON Web Token)                             | Network Protocols
    121 | SMF (Simple Machines Forum) > v1.1               | Forums, CMS, E-Commerce, Frameworks
    400 | phpBB3 (MD5)                                     | Forums, CMS, E-Commerce, Frameworks
   2611 | vBulletin < v3.8.5                               | Forums, CMS, E-Commerce, Frameworks
   2711 | vBulletin >= v3.8.5                              | Forums, CMS, E-Commerce, Frameworks
   2811 | MyBB 1.2+                                        | Forums, CMS, E-Commerce, Frameworks
   2811 | IPB2+ (Invision Power Board)                     | Forums, CMS, E-Commerce, Frameworks
   8400 | WBB3 (Woltlab Burning Board)                     | Forums, CMS, E-Commerce, Frameworks
     11 | Joomla < 2.5.18                                  | Forums, CMS, E-Commerce, Frameworks
    400 | Joomla >= 2.5.18 (MD5)                           | Forums, CMS, E-Commerce, Frameworks
    400 | WordPress (MD5)                                  | Forums, CMS, E-Commerce, Frameworks
   2612 | PHPS                                             | Forums, CMS, E-Commerce, Frameworks
   7900 | Drupal7                                          | Forums, CMS, E-Commerce, Frameworks
     21 | osCommerce                                       | Forums, CMS, E-Commerce, Frameworks
     21 | xt:Commerce                                      | Forums, CMS, E-Commerce, Frameworks
  11000 | PrestaShop                                       | Forums, CMS, E-Commerce, Frameworks
    124 | Django (SHA-1)                                   | Forums, CMS, E-Commerce, Frameworks
  10000 | Django (PBKDF2-SHA256)                           | Forums, CMS, E-Commerce, Frameworks
  16000 | Tripcode                                         | Forums, CMS, E-Commerce, Frameworks
   3711 | MediaWiki B type                                 | Forums, CMS, E-Commerce, Frameworks
  13900 | OpenCart                                         | Forums, CMS, E-Commerce, Frameworks
   4521 | Redmine                                          | Forums, CMS, E-Commerce, Frameworks
   4522 | PunBB                                            | Forums, CMS, E-Commerce, Frameworks
  12001 | Atlassian (PBKDF2-HMAC-SHA1)                     | Forums, CMS, E-Commerce, Frameworks
     12 | PostgreSQL                                       | Database Server
    131 | MSSQL (2000)                                     | Database Server
    132 | MSSQL (2005)                                     | Database Server
   1731 | MSSQL (2012, 2014)                               | Database Server
    200 | MySQL323                                         | Database Server
    300 | MySQL4.1/MySQL5                                  | Database Server
   3100 | Oracle H: Type (Oracle 7+)                       | Database Server
    112 | Oracle S: Type (Oracle 11+)                      | Database Server
  12300 | Oracle T: Type (Oracle 12+)                      | Database Server
   8000 | Sybase ASE                                       | Database Server
    141 | Episerver 6.x < .NET 4                           | HTTP, SMTP, LDAP Server
   1441 | Episerver 6.x >= .NET 4                          | HTTP, SMTP, LDAP Server
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)            | HTTP, SMTP, LDAP Server
  12600 | ColdFusion 10+                                   | HTTP, SMTP, LDAP Server
   1421 | hMailServer                                      | HTTP, SMTP, LDAP Server
    101 | nsldap, SHA-1(Base64), Netscape LDAP SHA         | HTTP, SMTP, LDAP Server
    111 | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA      | HTTP, SMTP, LDAP Server
   1411 | SSHA-256(Base64), LDAP {SSHA256}                 | HTTP, SMTP, LDAP Server
   1711 | SSHA-512(Base64), LDAP {SSHA512}                 | HTTP, SMTP, LDAP Server
  16400 | CRAM-MD5 Dovecot                                 | HTTP, SMTP, LDAP Server
  15000 | FileZilla Server >= 0.9.55                       | FTP Server
  11500 | CRC32                                            | Checksums
   3000 | LM                                               | Operating Systems
   1000 | NTLM                                             | Operating Systems
   1100 | Domain Cached Credentials (DCC), MS Cache        | Operating Systems
   2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2   | Operating Systems
  15300 | DPAPI masterkey file v1                          | Operating Systems
  15900 | DPAPI masterkey file v2                          | Operating Systems
  12800 | MS-AzureSync  PBKDF2-HMAC-SHA256                 | Operating Systems
   1500 | descrypt, DES (Unix), Traditional DES            | Operating Systems
  12400 | BSDi Crypt, Extended DES                         | Operating Systems
    500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)        | Operating Systems
   3200 | bcrypt $2*$, Blowfish (Unix)                     | Operating Systems
   7400 | sha256crypt $5$, SHA256 (Unix)                   | Operating Systems
   1800 | sha512crypt $6$, SHA512 (Unix)                   | Operating Systems
    122 | macOS v10.4, MacOS v10.5, MacOS v10.6            | Operating Systems
   1722 | macOS v10.7                                      | Operating Systems
   7100 | macOS v10.8+ (PBKDF2-SHA512)                     | Operating Systems
   6300 | AIX {smd5}                                       | Operating Systems
   6700 | AIX {ssha1}                                      | Operating Systems
   6400 | AIX {ssha256}                                    | Operating Systems
   6500 | AIX {ssha512}                                    | Operating Systems
   2400 | Cisco-PIX MD5                                    | Operating Systems
   2410 | Cisco-ASA MD5                                    | Operating Systems
    500 | Cisco-IOS $1$ (MD5)                              | Operating Systems
   5700 | Cisco-IOS type 4 (SHA256)                        | Operating Systems
   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                    | Operating Systems
   9300 | Cisco-IOS $9$ (scrypt)                           | Operating Systems
     22 | Juniper NetScreen/SSG (ScreenOS)                 | Operating Systems
    501 | Juniper IVE                                      | Operating Systems
  15100 | Juniper/NetBSD sha1crypt                         | Operating Systems
   7000 | FortiGate (FortiOS)                              | Operating Systems
   5800 | Samsung Android Password/PIN                     | Operating Systems
  13800 | Windows Phone 8+ PIN/password                    | Operating Systems
   8100 | Citrix NetScaler                                 | Operating Systems
   8500 | RACF                                             | Operating Systems
   7200 | GRUB 2                                           | Operating Systems
   9900 | Radmin2                                          | Operating Systems
    125 | ArubaOS                                          | Operating Systems
   7700 | SAP CODVN B (BCODE)                              | Enterprise Application Software (EAS)
   7800 | SAP CODVN F/G (PASSCODE)                         | Enterprise Application Software (EAS)
  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1              | Enterprise Application Software (EAS)
   8600 | Lotus Notes/Domino 5                             | Enterprise Application Software (EAS)
   8700 | Lotus Notes/Domino 6                             | Enterprise Application Software (EAS)
   9100 | Lotus Notes/Domino 8                             | Enterprise Application Software (EAS)
    133 | PeopleSoft                                       | Enterprise Application Software (EAS)
  13500 | PeopleSoft PS_TOKEN                              | Enterprise Application Software (EAS)
  11600 | 7-Zip                                            | Archives
  12500 | RAR3-hp                                          | Archives
  13000 | RAR5                                             | Archives
  13200 | AxCrypt                                          | Archives
  13300 | AxCrypt in-memory SHA1                           | Archives
  13600 | WinZip                                           | Archives
  14700 | iTunes backup < 10.0                             | Backup
  14800 | iTunes backup >= 10.0                            | Backup
   62XY | TrueCrypt                                        | Full-Disk Encryption (FDE)
     X  | 1 = PBKDF2-HMAC-RIPEMD160                        | Full-Disk Encryption (FDE)
     X  | 2 = PBKDF2-HMAC-SHA512                           | Full-Disk Encryption (FDE)
     X  | 3 = PBKDF2-HMAC-Whirlpool                        | Full-Disk Encryption (FDE)
     X  | 4 = PBKDF2-HMAC-RIPEMD160 + boot-mode            | Full-Disk Encryption (FDE)
      Y | 1 = XTS  512 bit pure AES                        | Full-Disk Encryption (FDE)
      Y | 1 = XTS  512 bit pure Serpent                    | Full-Disk Encryption (FDE)
      Y | 1 = XTS  512 bit pure Twofish                    | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit pure AES                        | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit pure Serpent                    | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit pure Twofish                    | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit cascaded AES-Twofish            | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit cascaded Serpent-AES            | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit cascaded Twofish-Serpent        | Full-Disk Encryption (FDE)
      Y | 3 = XTS 1536 bit all                             | Full-Disk Encryption (FDE)
   8800 | Android FDE <= 4.3                               | Full-Disk Encryption (FDE)
  12900 | Android FDE (Samsung DEK)                        | Full-Disk Encryption (FDE)
  12200 | eCryptfs                                         | Full-Disk Encryption (FDE)
  137XY | VeraCrypt                                        | Full-Disk Encryption (FDE)
     X  | 1 = PBKDF2-HMAC-RIPEMD160                        | Full-Disk Encryption (FDE)
     X  | 2 = PBKDF2-HMAC-SHA512                           | Full-Disk Encryption (FDE)
     X  | 3 = PBKDF2-HMAC-Whirlpool                        | Full-Disk Encryption (FDE)
     X  | 4 = PBKDF2-HMAC-RIPEMD160 + boot-mode            | Full-Disk Encryption (FDE)
     X  | 5 = PBKDF2-HMAC-SHA256                           | Full-Disk Encryption (FDE)
     X  | 6 = PBKDF2-HMAC-SHA256 + boot-mode               | Full-Disk Encryption (FDE)
      Y | 1 = XTS  512 bit pure AES                        | Full-Disk Encryption (FDE)
      Y | 1 = XTS  512 bit pure Serpent                    | Full-Disk Encryption (FDE)
      Y | 1 = XTS  512 bit pure Twofish                    | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit pure AES                        | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit pure Serpent                    | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit pure Twofish                    | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit cascaded AES-Twofish            | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit cascaded Serpent-AES            | Full-Disk Encryption (FDE)
      Y | 2 = XTS 1024 bit cascaded Twofish-Serpent        | Full-Disk Encryption (FDE)
      Y | 3 = XTS 1536 bit all                             | Full-Disk Encryption (FDE)
  14600 | LUKS                                             | Full-Disk Encryption (FDE)
   9700 | MS Office <= 2003 $0/$1, MD5 + RC4               | Documents
   9710 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #1  | Documents
   9720 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #2  | Documents
   9800 | MS Office <= 2003 $3/$4, SHA1 + RC4              | Documents
   9810 | MS Office <= 2003 $3, SHA1 + RC4, collider #1    | Documents
   9820 | MS Office <= 2003 $3, SHA1 + RC4, collider #2    | Documents
   9400 | MS Office 2007                                   | Documents
   9500 | MS Office 2010                                   | Documents
   9600 | MS Office 2013                                   | Documents
  10400 | PDF 1.1 - 1.3 (Acrobat 2 - 4)                    | Documents
  10410 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1       | Documents
  10420 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2       | Documents
  10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8)                    | Documents
  10600 | PDF 1.7 Level 3 (Acrobat 9)                      | Documents
  10700 | PDF 1.7 Level 8 (Acrobat 10 - 11)                | Documents
  16200 | Apple Secure Notes                               | Documents
   9000 | Password Safe v2                                 | Password Managers
   5200 | Password Safe v3                                 | Password Managers
   6800 | LastPass + LastPass sniffed                      | Password Managers
   6600 | 1Password, agilekeychain                         | Password Managers
   8200 | 1Password, cloudkeychain                         | Password Managers
  11300 | Bitcoin/Litecoin wallet.dat                      | Password Managers
  12700 | Blockchain, My Wallet                            | Password Managers
  15200 | Blockchain, My Wallet, V2                        | Password Managers
  16600 | Electrum Wallet (Salt-Type 1-3)                  | Password Managers
  13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)      | Password Managers
  15500 | JKS Java Key Store Private Keys (SHA1)           | Password Managers
  15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256              | Password Managers
  15700 | Ethereum Wallet, SCRYPT                          | Password Managers
  16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256     | Password Managers
  99999 | Plaintext                                        | Plaintext"

    # Get Hash Mode from User Input
    $HASH_MODE = Read-Host -Prompt 'Hash Mode [0]'
    # setup Hashcat flags
    $FLAGS = "--hash-type=$HASH_MODE --potfile-disable --outfile C:\CrackApps\Data\$COMPANYCODE\$COMPANYCODE.potfile"
    return $FLAGS
}

function importFile(){
    $INPUTFILE = Get-FileName $currentpath
    if(! $inputfile){
        Write-Host "No Input File Selected"
        break
    }
}

function getCompanyID(){
    # Get Company code 
    $COMPANYCODE = Read-Host -Prompt 'Company Code'

    # check to see if Company already has a folder. 
    if (!(Test-Path -Path "C:\CrackApps\Data\$$COMPANYCODE"  -PathType container)){
      Write-Host "Folder does not exist. Creating folder structure."
      New-Item -ItemType "directory" -Path "C:\CrackApps\Data\$COMPANYCODE"|out-null
      New-Item -ItemType "file" -Path "C:\CrackApps\Data\$COMPANYCODE\$COMPANYCODE.potfile"|out-null
      return $COMPANYCODE
    }
    else{
      Write-Host "Folder already exists.  Skipping folder creation."
    }
  
}

# Pre-Run Setup.  Check to see what Attacks are being run and do the user interaction before hand. 
function wordlistSetup(){
    Write-Host "No Further Action Required"
}

function rulesSetup(){
    Write-Host "Rules Setup"

    Write-Host "Which Dictionary?"
    $global:DICT = Get-FileName $currentpath
}

function combinatorSetup(){
    Write-Host "Combinator Setup"

    # which two Dictionaries to run against?
    Read-Host "1st Dictionary to combine?"
    $global:DICT_ONE = Get-FileName $currentpath
    Read-Host "2nd Dictionary to combine?"
    $global:DICT_TWO = Get-FileName $currentpath
}

function maskSetup(){
    Write-Host "Mask Setup"
}

function hybridSetup(){
    Write-Host "Hybrid Setup"
}

# Attack functions
function wordlistAttack(){
    Write-Host 'Running all ..\Dictionaries in current folder by smallest size to largest'
    Write-Host ""
    Get-ChildItem "../WordLists/" | Sort-Object length | ForEach-Object{
        # Define the per-wordlist action
        #Write-Host $_.FullName
        run $_.FullName
    }
}

function rulesAttack(){
    # dont run all the rules ... to many dupes etc ... 
    Write-Host "Running rules in the rules folder against $DICT"
    Read-Host -Prompt "Enter to Continue..."
    
    Get-ChildItem "./rules" | ForEach-Object{
        #Write-Host $_.FullName
        $arg1 = "-a 0 -r " + $_.FullName + " " + $DICT
        run $arg1
    }
}

function combinatorAttack(){
    Write-Host 'Running combinator attacks'
    Write-Host ""
    # which two Dictionaries to run against?
    $arg1 = "-a 1 " + $DICT_ONE + " " + $DICT_TWO
    run $arg1
}

function maskAttack(){
    Write-Host 'Running mask attacks'
    Write-Host ""
    $arg1 = "-a 3 ?l?l?l?l?l?l?d?d?"
    run $arg1
}

function hybridAttack(){
    Write-Host 'Running hybrid attacks'
    Write-Host ""
    $arg1 = "-a 6 -1 ?l?d?s?u $DICT_FILE_TINY ?1"
    run $arg1
}

function bruteforceAttack(){
    Write-Host 'Running brute-force attacks - This might take a while.'
    Write-Host ""
    $arg1 = "-a 3 -1 ?l?u?d?s ?l?l?l?l?l?l?l?l"
    run $arg1
}

function getAttackTypes(){
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form 
    $form.Text = "Attack Select"
    $form.Size = New-Object System.Drawing.Size(300,200) 
    $form.StartPosition = "CenterScreen"

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(75,120)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "OK"
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150,120)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20) 
    $label.Size = New-Object System.Drawing.Size(280,20) 
    $label.Text = "Which Attacks to Perform?"
    $form.Controls.Add($label) 

    $listBox = New-Object System.Windows.Forms.Listbox 
    $listBox.Location = New-Object System.Drawing.Point(10,40) 
    $listBox.Size = New-Object System.Drawing.Size(260,20) 

    $listBox.SelectionMode = "MultiExtended"

    # Add all Selections here. 
    [void] $listBox.Items.Add("Wordlist Attack")
    [void] $listBox.Items.Add("Rules Attack")
    [void] $listBox.Items.Add("Combinator Attack")
    [void] $listBox.Items.Add("Mask Attack")
    [void] $listBox.Items.Add("Hybrid Attack")

    $listBox.Height = 70
    $form.Controls.Add($listBox) 
    $form.Topmost = $True

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $x = $listBox.SelectedItems
        #$x
        return $x
    }
}


#### Script starts here  ########
# Check for files
$HASHCAT=fileCheck

# Get Company Code
$COMPANYCODE = getCompanyID

# # Get Input File
$INPUT_FILE = Get-FileName $currentpath

# # Choose the HashMode
$FLAGS = getHashMode($COMPANYCODE)

# # Choose Attack Types and Perform Setups for automation
$selectedAttacks = getAttackTypes
foreach($item in $selectedAttacks){
    switch -wildcard ($item){
        "Wordlist*" {wordlistSetup("Wordlist")}
        "Rules*" {rulesSetup("Rules")}
        "Combinator*" {combinatorSetup("Combinator")}
        "Mask*" {maskSetup("Mask")}
        "Hybrid*" {hybridSetup("Hybrid")}
    }
}

# Now launch the attacks.  
foreach($item in $selectedAttacks){
        switch -wildcard ($item){
        "Wordlist*" {wordlistAttack}
        "Rules*" {rulesAttack}
        "Combinator*" {combinatorAttack}
        "Mask*" {maskAttack}
        "Hybrid*" {hybridAttack}
    }
}
