Imports System.Text.RegularExpressions
Imports Microsoft.Win32

Public Class NavicatHelpers
    Public Shared Function AlignDown(x As Integer, alignment As Integer) As Integer
        Return (x \ alignment) * alignment
    End Function

    Public Shared Function AlignUp(x As Integer, alignment As Integer) As Integer
        Return AlignDown(x + (alignment - 1), alignment)
    End Function

    Public Shared Function BytesToHex(data As Byte()) As String
        Return BitConverter.ToString(data).Replace("-", "").ToUpperInvariant()
    End Function

    Public Shared Function HexToBytes(hex As String) As Byte()
        If hex Is Nothing Then Throw New ArgumentNullException(NameOf(hex))
        If (hex.Length Mod 2) <> 0 Then
            Throw New ArgumentException("Hex string must have an even length.")
        End If

        Dim result((hex.Length \ 2) - 1) As Byte
        For i As Integer = 0 To result.Length - 1
            result(i) = Convert.ToByte(hex.Substring(i * 2, 2), 16)
        Next
        Return result
    End Function
End Class