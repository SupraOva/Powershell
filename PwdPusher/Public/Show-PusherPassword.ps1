function Show-PusherPassword {
    <#
    .SYNOPSIS
        Show generated password from New-PusherPassword.
    .PARAMETER SecurePassword
        Parameter to pass Secure Password
    .EXAMPLE 
        Show-PusherPassword -SecurePassword $SecPwd
        Show-PusherPassword $SecPwd
        sppwd $SecPwd
    #>

    [Alias("sppwd")]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString]$SecurePassword
    )
    
    return [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))

} #End function 