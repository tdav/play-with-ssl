$dnsName = Read-Host 'Enter DnsName?'

$certificate = New-SelfSignedCertificate `
    -Subject $dnsName `
    -DnsName $dnsName `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotBefore (Get-Date) `
    -NotAfter (Get-Date).AddYears(5) `
    -FriendlyName "Asbt Certificate For Server Authorization" `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

$pasw = Read-Host 'Enter paswsword?'
$pfxPassword = ConvertTo-SecureString `
    -String $pasw `
    -Force `
    -AsPlainText
	
Export-PfxCertificate `
    -Cert $certificate `
    -FilePath $dnsName".pfx" `
    -Password $pfxPassword