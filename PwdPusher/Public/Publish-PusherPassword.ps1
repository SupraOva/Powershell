function Publish-PusherPassword {
    <#
    .SYNOPSIS
        Pushes the password to public pwpush.com or a private instance of Password Pusher and retrieves the link.
    .PARAMETER Link
        Password to push. If no value is provided, random password will be generated.
        Should be specified as SecureString, anything else will be cast to String and force-converted to SecureString for processing.
        Using plain-text passwords should be avoided wherever possible (aliased as -p).
    .PARAMETER Days
        Number of days before the link expires. Default value is 7 days. Permitted range is dependent on service configuration, generally 1-90 days (aliased as -d).
    .PARAMETER Views
        Number of views before the link expires. Default value is 5 views. Permitted range is dependent on service configuration, generally 1-100 views (aliased as -v).
    .PARAMETER Server
        Specifies server/service to use in FQDN format, assumes https:// protocol prefix and default port 443 (aliased as -s).
    .PARAMETER KillSwitch
        Allows anyone accessing the link to delete it before it expires, False by default (aliased as -k).
    .PARAMETER FirstView
        Tells the server to use the "First view" experience (that's not counted towards maximum views).
        Due to a current bug/deficiency in pwpush the API ignores the switch if supplied in the REST call and the option is always on.
        It's emulated by using HTTP GET against the URL if the switch is not specified in the command (aliased as -f).
    .PARAMETER Wipe
        Wipe the password object from memory using Dispose() method after successful publishing, False by default (aliased as -k).
    .EXAMPLE 
        Pushes the password stored in [SecureString]$SecurePass to $Server with default settings.
          $SecurePass | Publish-PusherPassword -Server "localhost:5100"
    .EXAMPLE
        Pushes password "P@ssw0rd" to $Server, expiring after 3 days or 10 views.
        Will throw a warning about using plain-text password.
          Publish-PusherPassword -Password P@ssw0rd -Days 3 -Views 10
    #>

    [CmdletBinding()]
    [Alias("pppwd")]
    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)][Alias("p")][Security.SecureString]$Password,
        [Alias("d")][int]$Days=7,
        [Alias("v")][int]$Views=7,
        [Alias("s")][string]$Server,
        [Alias("k")][switch]$KillSwitch,
        [Alias("f")][switch]$FirstView,
        [Alias("w")][switch]$Wipe
    )

    # If the password is supplied as anything but SecureString, throw a warning and force-convert it
    if ($Password -isnot [securestring]) {
        Write-Host -ForegroundColor Yellow "You should use SecureString type to process passwords in scripts. Converting now..."
        [securestring]$Password = ConvertTo-SecureString ([string]$Password) -AsPlainText -Force
    }

    # Push the password, retrieve the response. Building the body on-the-fly to keep unsecured password not stored in a variable
    $Reply = Invoke-RestMethod -Method 'Post' -Uri "http://$Server/p.json" -ContentType "application/json" -Body ([pscustomobject]@{
        password = if ($KillSwitch) {[pscustomobject]@{
                payload = ConvertFrom-SecurePassword $Password
                expire_after_days = $Days
                expire_after_views = $Views
                deletable_by_viewer = $KillSwitch.IsPresent.ToString().ToLower()
                first_view = $FirstView.IsPresent.ToString().ToLower()
           }
        } else {
            [pscustomobject]@{
                payload = ConvertFrom-SecurePassword $Password
                expire_after_days = $Days
                expire_after_views = $Views
                first_view = $FirstView.IsPresent.ToString().ToLower()
            }
        }
    } | ConvertTo-Json)

    if ($Reply.url_token) {
        if ($Reply.first_view -gt $FirstView.IsPresent) {
            Invoke-RestMethod -Method 'Get' -Uri "https://$Server/p/$($Reply.url_token).json" | Out-Null
            Write-Host -ForegroundColor Yellow "The version of PasswordPusher you're using is outdated and doesn't properly support FirstView switch`n" +`
                                               "Please update to a build that includes pull request #112"
        }

        # Dispose of secure password object - note it's the original object, not a function-local copy
        if ($Wipe) {$Password.Dispose()}
        return "http://$Server/en/p/$($Reply.url_token)"
        
    } else {
        Write-Error "Unable to get URL from service"
    }
} #End function