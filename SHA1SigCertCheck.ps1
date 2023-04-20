PARAM ( [switch] $Cert, [switch] $EXE, [switch] $SYSTEM, [string]$Path)
#************************************************
# SHA1SigCertCheck.ps1
# Version 1.0
# Date: 11/9/2015
# Author: Tim Springston
# Description: This script will check a specified certificate file (.cer), the local System My store,
#  or a specified executubale for a SHA1 signature on the certificate.
#  SHA1 signed certificates are less secure and problematic. Microsoft has a planned SHA1 Windows 
#  deprecation strategy where they will no longer be usable by Windows after 
#  specified dates. More detail on this is available at http://aka.ms/sha1
#************************************************
cls
$cs = get-wmiobject -class win32_computersystem
$DomainRole = $cs.domainrole
$OSVersion = gwmi win32_operatingsystem
$ErrorActionPreference = 'SilentlyContinue'
function CheckCertforSHA1 ($Path ) { 
    $Certificate = New-object System.Security.Cryptography.X509Certificates.X509Certificate2($Path)
    Write-host "Checking certificate file at $Path for SHA1 signature and to see if it is a Server Authentication certificate."
	#Check for certificate being server auth.
	$ServerAuth = $false
	$SHA1 = $false
	if ($Certificate.Extensions -ne $null)
		{
		foreach ($Extension in $Certificate.Extensions)
			{
			if (($Extension.Oid.FriendlyName -like "Key Usage") -or ($Extension.Oid.FriendlyName -like "Enhanced Key Usage"))
				{if ((($Extension).Format(1)) -match "1.3.6.1.5.5.7.3.1"){$ServerAuth = $True}}
			}
		}
	#Check for SHA1 signature.
    if ($ServerAuth -eq $true)
		{
		if (($Certificate.SignatureAlgorithm.Value -eq '1.3.14.3.2.29') -or ($Certificate.SignatureAlgorithm.Value -eq '1.2.840.10040.4.3') `
		 -or ($Certificate.SignatureAlgorithm.Value -eq '1.2.840.10045.4.1') -or ($Certificate.SignatureAlgorithm.Value -eq '1.2.840.113549.1.1.5') `
		 -or ($Certificate.SignatureAlgorithm.Value -eq '1.3.14.3.2.13') -or ($Certificate.SignatureAlgorithm.Value -eq '1.3.14.3.2.27'))
        	{
			Write-Host "SHA1 signed Server Auth certificate found." -ForegroundColor Yellow
			$SHA1 = $true
			$CertObject = New-Object PSObject
			if ($Certificate.FriendlyName -gt 0){add-member -inputobject $CertObject -membertype noteproperty -name "Friendly Name" -value $Certificate.FriendlyName}
			if ($Certificate.SubjectName -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Subject Name" -value ($Certificate.SubjectName).Format(1)}
			if ($Certificate.Subject -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Subject" -value $Certificate.Subject}
			if ($Certificate.IssuerName -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Issuer" -value ($Certificate.IssuerName).Format(1)}
			if ($Certificate.SerialNumber -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Serial Number" -value $Certificate.SerialNumber}
			if ($Certificate.Thumbprint-ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Thumbprint" -value $Certificate.Thumbprint}
			add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Issued Time" -value $EXEResult.SignerCertificate.NotBefore
			add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Expiry Time" -value $EXEResult.SignerCertificate.NotAfter
			add-member -inputobject $CertObject -membertype noteproperty -name "Signature Algorithm" -value $Certificate.SignatureAlgorithm.FriendlyName
       		$CertObject | FL *
			}
		#Check the certificate chain for problematic certificates.
		$ChainObject = New-Object System.Security.Cryptography.X509Certificates.X509Chain($True)
		$ChainObject.ChainPolicy.RevocationFlag = "EntireChain"
		$ChainObject.ChainPolicy.VerificationFlags = "AllFlags"
		$ChainObject.ChainPolicy.RevocationMode = "Online"
		$ChainResult = $ChainObject.Build($Certificate)
		ForEach ($ParentCert in $ChainObject.ChainElements.Certificate)
			{
			if ((($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.29') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10040.4.3') `
				-or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10045.4.1') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.113549.1.1.5') `
				-or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.13') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.27')) -and `
				(!($ParentCert.Issuer -eq $ParentCert.Subject)))
				{
				Write-Host "A leaf or intermediate CA certificate in the specified certificate's path is signed with SHA1." -ForegroundColor Red -BackgroundColor Black
			   	$ParentCertObject = New-Object PSObject
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Type" -value "Leaf or Intermediate CA"
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Chain" -value "Code Signing Certificate"
				if ($ParentCert.FriendlyName -gt 0){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Friendly Name" -value $ParentCert.FriendlyName}
				if ($ParentCert.SubjectName -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject Name" -value ($ParentCert.SubjectName).Format(1)}
				if ($ParentCert.Subject -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject" -value $ParentCert.Subject}
				if ($ParentCert.IssuerName -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Issuer" -value ($ParentCert.IssuerName).Format(1)}
				if ($ParentCert.SerialNumber -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Serial Number" -value $ParentCert.SerialNumber}
				if ($ParentCert.Thumbprint -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Thumbprint" -value $ParentCert.Thumbprint}
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Issued Time" -value $ParentCert.NotBefore
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Expiry Time" -value $ParentCert.NotAfter
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Signature Algorithm" -value $ParentCert.SignatureAlgorithm.FriendlyName
				$ParentCertObject | FL *
				$SHA1 = $true
				}	
			}
			
			if ($SHA1 -eq $false)
				{Write-Host "SHA1 signed Server Auth certificate NOT found." -ForegroundColor Green}
        }
		else
			{Write-Host "This certificate is not a Server Auth certificate and SHA1 deprecation doesn't apply." -ForegroundColor Green}
		

}
function CheckEXESigforSHA1 ($Path ) { 
	$EXEResult = Get-AuthenticodeSignature -FilePath $Path
	$OSVersion = gwmi win32_operatingsystem
	[int]$BuildNumber = $OSVersion.BuildNumber
	$MarkoftheWeb = $false
	Try {$File = Get-Content -Path $Path -Stream "Zone.Identifier" -ErrorAction SilentlyContinue} #Check for Mark of the Web
		Catch { $_ } 
	if ($File -ne $null) {$MarkoftheWeb = $true}
	Write-Host "Checking the code signing and time stamping certificate for the executable $Path" -ForegroundColor Green
	$SHA1 = $false
	$Date = Get-Date "1/1/2016"
    #Check for SHA1 signature in signing certificate.
    if (($EXEResult.SignerCertificate.SignatureAlgorithm.value -eq '1.3.14.3.2.29') -or ($EXEResult.SignerCertificate.SignatureAlgorithm.value -eq '1.2.840.10040.4.3') `
	-or ($EXEResult.SignerCertificate.SignatureAlgorithm.value -eq '1.2.840.10045.4.1') -or ($EXEResult.SignerCertificate.SignatureAlgorithm.value -eq '1.2.840.113549.1.1.5') `
	-or ($EXEResult.SignerCertificate.SignatureAlgorithm.value -eq '1.3.14.3.2.13') -or ($EXEResult.SignerCertificate.SignatureAlgorithm.value -eq '1.3.14.3.2.27'))
        { 
	 	Write-Host "SHA1 code signing certificate found." -ForegroundColor Red -BackgroundColor Black
		if (($EXEResult.SignerCertificate.NotBefore -gt $Date) -and ($MarkoftheWeb))
			{
			Write-Host "This executable will was signed using a SHA1 certificate signature after 1/1/2016 and has the Mark of the Web security attribute. This executable is blocked on Windows 7 and later ." -ForegroundColor red
			$SHA1 = $true
			}
		if ($EXEResult.SignerCertificate.NotBefore -lt $Date)
			{
			Write-Host "This executable will not be deprecated from use in Windows until January 1, 2020.  On Windows 7 and above, untrusted on 1/1/2020 if valid before 1/1/2016." -ForegroundColor Yellow
			$SHA1 = $true
			}
        $CertObject = New-Object PSObject
		add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Type" -value "Code Signing Certificate"
		if ($EXEResult.SignerCertificate.FriendlyName -gt 0){add-member -inputobject $CertObject -membertype noteproperty -name "Friendly Name" -value $EXEResult.SignerCertificate.FriendlyName}
		if ($EXEResult.SignerCertificate.SubjectName -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Subject Name" -value ($EXEResult.SignerCertificate.SubjectName).Format(1)}
		if ($EXEResult.SignerCertificate.Subject -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Subject" -value $EXEResult.SignerCertificate.Subject}
		if ($EXEResult.SignerCertificate.IssuerName -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Issuer" -value ($EXEResult.SignerCertificate.IssuerName).Format(1)}
		if ($EXEResult.SignerCertificate.SerialNumber -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Serial Number" -value $EXEResult.SignerCertificate.SerialNumber}
		if ($EXEResult.SignerCertificate.Thumbprint -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Thumbprint" -value $EXEResult.SignerCertificate.Thumbprint}
		add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Issued Time" -value $EXEResult.SignerCertificate.NotBefore
		add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Expiry Time" -value $EXEResult.SignerCertificate.NotAfter
		add-member -inputobject $CertObject -membertype noteproperty -name "Signature Algorithm" -value $EXEResult.SignerCertificate.SignatureAlgorithm.FriendlyName
       	$CertObject | FL *
		$SHA1 = $true
		}
	#Check the code signing certificate chain for problematic certificates.
	$ChainObject = New-Object System.Security.Cryptography.X509Certificates.X509Chain($True)
	$ChainObject.ChainPolicy.RevocationFlag = "EntireChain"
	$ChainObject.ChainPolicy.VerificationFlags = "AllFlags"
	$ChainObject.ChainPolicy.RevocationMode = "Online"
	$ChainResult = $ChainObject.Build($EXEResult.SignerCertificate)
	ForEach ($ParentCert in $ChainObject.ChainElements.Certificate)
		{
		if ((($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.29') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10040.4.3') `
			-or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10045.4.1') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.113549.1.1.5') `
			-or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.13') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.27')) -and `
			(!($ParentCert.Issuer -eq $ParentCert.Subject)))
			{
			Write-Host "A leaf or intermediate CA certificate in the code signing certificate's path is signed with SHA1." -ForegroundColor Red -BackgroundColor Black
		   	$ParentCertObject = New-Object PSObject
			add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Type" -value "Leaf or Intermediate CA"
			add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Chain" -value "Code Signing Certificate"
			if ($ParentCert.FriendlyName -gt 0){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Friendly Name" -value $ParentCert.FriendlyName}
			if ($ParentCert.SubjectName -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject Name" -value ($ParentCert.SubjectName).Format(1)}
			if ($ParentCert.Subject -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject" -value $ParentCert.Subject}
			if ($ParentCert.IssuerName -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Issuer" -value ($ParentCert.IssuerName).Format(1)}
			if ($ParentCert.SerialNumber -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Serial Number" -value $ParentCert.SerialNumber}
			if ($ParentCert.Thumbprint -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Thumbprint" -value $ParentCert.Thumbprint}
			add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Issued Time" -value $ParentCert.NotBefore
			add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Expiry Time" -value $ParentCert.NotAfter
			add-member -inputobject $ParentCertObject -membertype noteproperty -name "Signature Algorithm" -value $ParentCert.SignatureAlgorithm.FriendlyName
   			$ParentCertObject | FL *
			$SHA1 = $true
			}
		}	
    If (($EXEResult.TimeStamperCertificate -ne $null)  -and ($MarkoftheWeb))
		{
		#Check for SHA1 signature in time stamping certificate.
		if (($EXEResult.TimeStamperCertificate.SignatureAlgorithm.value -eq '1.3.14.3.2.29') -or ($EXEResult.TimeStamperCertificate.SignatureAlgorithm.value -eq '1.2.840.10040.4.3') `
		-or ($EXEResult.TimeStamperCertificate.SignatureAlgorithm.value -eq '1.2.840.10045.4.1') -or ($EXEResult.TimeStamperCertificate.SignatureAlgorithm.value -eq '1.2.840.113549.1.1.5') `
		-or ($EXEResult.TimeStamperCertificate.SignatureAlgorithm.value -eq '1.3.14.3.2.13') -or ($EXEResult.TimeStamperCertificate.SignatureAlgorithm.value -eq '1.3.14.3.2.27'))
		    { 
		    Write-Host "SHA1 time stamping certificate found." -ForegroundColor Yellow
			if ($EXEResult.TimeStamperCertificate.NotBefore -gt $Date)
				{
				Write-Host "SHA1 time stamping certificate found on a signed executable which has Mark of the Web security set on it. Windows no longer trusts files with the Mark of the Web attribute that are timestamped with SHA-1 signature hash on Windows 10 and later systems." -ForegroundColor Yellow
				$SHA1 = $true
				}
		    $CertObject = New-Object PSObject
		   	add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Type" -value "Time Stamping Certificate"
			if ($EXEResult.TimeStamperCertificate.FriendlyName -gt 0){add-member -inputobject $CertObject -membertype noteproperty -name "Friendly Name" -value $EXEResult.TimeStamperCertificate.FriendlyName}
		    if ($EXEResult.TimeStamperCertificate.SubjectName  -gt 0){add-member -inputobject $CertObject -membertype noteproperty -name "Subject Name" -value ($EXEResult.TimeStamperCertificate.SubjectName).Format(1)}
		    if ($EXEResult.TimeStamperCertificate.Subject  -gt 0){add-member -inputobject $CertObject -membertype noteproperty -name "Subject" -value $EXEResult.TimeStamperCertificate.Subject}
		    if ($EXEResult.TimeStamperCertificate.IssuerName -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Issuer" -value ($EXEResult.TimeStamperCertificate.IssuerName).Format(1)}
		    if ($EXEResult.TimeStamperCertificate.SerialNumber -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Serial Number" -value $EXEResult.TimeStamperCertificate.SerialNumber}
		    if ($EXEResult.TimeStamperCertificate.Thumbprint -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Thumbprint" -value $EXEResult.TimeStamperCertificate.Thumbprint}
		    add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Issued Time" -value $EXEResult.TimeStamperCertificate.NotBefore
			add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Expiry Time" -value $EXEResult.TimeStamperCertificate.NotAfter
			add-member -inputobject $CertObject -membertype noteproperty -name "Signature Algorithm" -value $EXEResult.TimeStamperCertificate.SignatureAlgorithm.FriendlyName
		    $CertObject | FL *
		    $SHA1 = $true
		    }
		#Check the time stamping certificate chain for problematic certificates.
		$ChainObject = New-Object System.Security.Cryptography.X509Certificates.X509Chain($True)
		$ChainObject.ChainPolicy.RevocationFlag = "EntireChain"
		$ChainObject.ChainPolicy.VerificationFlags = "AllFlags"
		$ChainObject.ChainPolicy.RevocationMode = "Online"
		$ChainResult = $ChainObject.Build($EXEResult.TimeStamperCertificate)
		ForEach ($ParentCert in $ChainObject.ChainElements.Certificate)
			{
			if ((($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.29') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10040.4.3') `
				-or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10045.4.1') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.113549.1.1.5') `
				-or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.13') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.27')) -and `
				(!($ParentCert.Issuer -eq $ParentCert.Subject)))
				{
				Write-Host "A leaf or intermediate CA certificate in the time stamping certificate's path is signed with SHA1." -ForegroundColor Red -BackgroundColor Black
			   	$ParentCertObject = New-Object PSObject
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Chained Certificate Serial Number" -value $Certificate.SerialNumber
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Chained Certificate Thumbprint" -value $Certificate.Thumbprint
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Type" -value "Leaf or Intermediate CA"
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Chain" -value "Time Stamping Certificate"
				if ($ParentCert.FriendlyName -gt 0){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Friendly Name" -value $ParentCert.FriendlyName}
				if ($ParentCert.SubjectName  -gt 0){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject Name" -value ($ParentCert.SubjectName).Format(1)}
				if ($ParentCert.Subject  -gt 0){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject" -value $ParentCert.Subject}
				if ($ParentCert.IssuerName -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Issuer" -value ($ParentCert.IssuerName).Format(1)}
				if ($ParentCert.SerialNumber -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Serial Number" -value $ParentCert.SerialNumber}
				if ($ParentCert.Thumbprint -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Thumbprint" -value $ParentCert.Thumbprint}
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Issued Time" -value $ParentCert.NotBefore
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Expiry Time" -value $ParentCert.NotAfter
				add-member -inputobject $ParentCertObject -membertype noteproperty -name "Signature Algorithm" -value $ParentCert.SignatureAlgorithm.FriendlyName
				$ParentCertObject | FL *
				$SHA1 = $true
				}
			}	
	}
	if ($SHA1 -eq $false)
		{Write-Host "Neither code signing nor time stamping certificate was signed with SHA1." -ForegroundColor Green -BackgroundColor Black} 
}
function SHA1SIgCheckAllSystemCerts {
	$CS = get-wmiobject -class win32_computersystem
	$Hostname = $CS.Name + '.' + $CS.Domain
    $Results = $pwd.Path + "\" + $Hostname + "_SHA1ServerAuthSystemCerts.txt"	
	Get-Date | Out-File $Results -Encoding UTF8
    "Computer certificate My store checks for Server Auth certificates which are signed with SHA1 or that have leaf or intermediate CA certfiicates in their path which are SHA1 signed." | Out-File $Results -Encoding UTF8  -Append
	Write-Host "Checking the local computer's My certificate store for Server Authentication certificates which are signed with SHA1 signatures or which have leaf or intermediate CA certificates which are signed with SHA1." -ForegroundColor Green
	$MyStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
	$SHA1 = $false
	$MyStore.Open("ReadOnly")
	$CertsInStore = $MyStore.Certificates
	foreach ($Certificate in $CertsInStore)
		{
		if ($Certificate.Extensions -ne $null)
			{
			foreach ($Extension in $Certificate.Extensions)
				{
				if (($Extension.Oid.FriendlyName -like "Key Usage") -or ($Extension.Oid.FriendlyName -like "Enhanced Key Usage"))
					{if ($Extension.OID.Value -eq "1.3.6.1.5.5.7.3.1"){$ServerAuth = $True}}
					#{if ($Extension.OID.Value -ne "1.3.6.1.5.5.7.3.1"){$ServerAuth = $True}}	#Testing value			
				}

			if ($ServerAuth -eq $true) 
				{
			if (($Certificate.SignatureAlgorithm.Value -eq '1.3.14.3.2.29') -or ($Certificate.SignatureAlgorithm.Value -eq '1.2.840.10040.4.3') `
			 	-or ($Certificate.SignatureAlgorithm.Value -eq '1.2.840.10045.4.1') -or ($Certificate.SignatureAlgorithm.Value -eq '1.2.840.113549.1.1.5') `
			 	-or ($Certificate.SignatureAlgorithm.Value -eq '1.3.14.3.2.13') -or ($Certificate.SignatureAlgorithm.Value -eq '1.3.14.3.2.27'))
					{
		        	$CertObject = New-Object PSObject
					if ($Certificate.FriendlyName -gt 0){add-member -inputobject $CertObject -membertype noteproperty -name "Friendly Name" -value $Certificate.FriendlyName}
					if ($Certificate.SubjectName  -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Subject Name" -value ($Certificate.SubjectName).Format(1)}
					if ($Certificate.Subject  -gt 0){add-member -inputobject $CertObject -membertype noteproperty -name "Subject" -value $Certificate.Subject}
					if ($Certificate.IssuerName -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Issuer" -value ($Certificate.IssuerName).Format(1)}
					if ($Certificate.SerialNumber -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Serial Number" -value $Certificate.SerialNumber}
					if ($Certificate.Thumbprint -ne $null){add-member -inputobject $CertObject -membertype noteproperty -name "Thumbprint" -value $Certificate.Thumbprint}
					add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Issued Time" -value $Certificate.NotBefore
					add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Expiry Time" -value $Certificate.NotAfter
					add-member -inputobject $CertObject -membertype noteproperty -name "Signature Algorithm" -value $Certificate.SignatureAlgorithm.FriendlyName
		       		$CertObject | FL *
					$CertObject | Out-File $Results -Encoding UTF8  -Append
					$SHA1 = $true	
					$ChainObject = New-Object System.Security.Cryptography.X509Certificates.X509Chain($True)
					$ChainObject.ChainPolicy.RevocationFlag = "EntireChain"
					$ChainObject.ChainPolicy.VerificationFlags = "AllFlags"
					$ChainObject.ChainPolicy.RevocationMode = "Online"
					$ChainResult = $ChainObject.Build($Certificate)
					#Check the certfificates parents in chain for SHA1 signature.
					ForEach ($ParentCert in $ChainObject.ChainElements.Certificate)
						{
						if ((($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.29') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10040.4.3') `
						-or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.10045.4.1') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.2.840.113549.1.1.5') `
						-or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.13') -or ($ParentCert.SignatureAlgorithm.Value -eq '1.3.14.3.2.27')) -and `
						(!($ParentCert.Issuer -eq $ParentCert.Subject)))
								{
								Write-Host "SHA1 signed leaf or intermediate certificate found." -ForegroundColor Yellow
						   		$ParentCertObject = New-Object PSObject
								add-member -inputobject $ParentCertObject -membertype noteproperty -name "Chained Certificate Serial Number" -value $Certificate.SerialNumber
								add-member -inputobject $ParentCertObject -membertype noteproperty -name "Chained Certificate Thumbprint" -value $Certificate.Thumbprint
								add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Type" -value "Leaf or Intermediate CA"
								if ($ParentCert.FriendlyName -gt 0){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Friendly Name" -value $ParentCert.FriendlyName}
								if ($ParentCert.SubjectName  -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject Name" -value ($ParentCert.SubjectName).Format(1)}
								if ($ParentCert.Subject  -gt 0){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Subject" -value $ParentCert.Subject}
								if ($ParentCert.IssuerName -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Issuer" -value ($ParentCert.IssuerName).Format(1)}
								if ($ParentCert.SerialNumber -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Serial Number" -value $ParentCert.SerialNumber}
								if ($ParentCert.Thumbprint -ne $null){add-member -inputobject $ParentCertObject -membertype noteproperty -name "Thumbprint" -value $ParentCert.Thumbprint}
								add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Issued Time" -value $ParentCert.NotBefore
								add-member -inputobject $ParentCertObject -membertype noteproperty -name "Certificate Expiry Time" -value $ParentCert.NotAfter
								add-member -inputobject $ParentCertObject -membertype noteproperty -name "Signature Algorithm" -value $ParentCert.SignatureAlgorithm.FriendlyName
				   				$ParentCertObject | FL *
								$ParentCertObject | Out-File $Results -Encoding UTF8  -Append
								$SHA1 = $true
								} 

					}	
				}
			}

		}

	}
	if ($SHA1 -eq $false)
		{
		Write-Host " "
		Write-Host "No SHA1 signed Server Auth certs, or leaf or intermediate certs for them, were found." -ForegroundColor Green -BackgroundColor Black
		"No SHA1 signed Server Auth certs, or leaf or intermediate certs for them, were found." | Out-File $Results -Encoding UTF8  -Append
		}
}
#Script switch 
if (($Cert -and $EXE) -or ($Cert -and $System) -or ($EXE -and $System) -or ($EXE -and $Cert) -or ($EXE -and $System -and $Cert))
	{Write-host "Only one of the switches for FILE, SYSTEM or EXE may be done at a time. Please retry." -ForegroundColor red }
if (!($Cert -or $System -or $EXE))
	{Write-host "One of the switches for Certificate (CERT), EXE (executable) or SYSTEM (check all certificates in the computer store) must be set to true. Please retry." -ForegroundColor red }

if ($Cert) {
	if ($Path -eq $null) {Write-Host "A file path for the certificate to be checked must be provided in the -Path switch." -ForegroundColor Red}
		else {CheckCertforSHA1 $Path }
	}
if($EXE) {
	if ($Path -eq $null) {Write-Host "A file path for the executable to be checked must be provided in the -Path switch." -ForegroundColor Red}
		else	{CheckEXESigforSHA1 $Path}
	}
if($SYSTEM) {SHA1SIgCheckAllSystemCerts}

		




