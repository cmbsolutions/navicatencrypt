Imports System.Security.Cryptography
Imports System.Text

''' <summary>
''' NavicatEncryptV2 will encrypt and decrypt the database passwords stored in the registry as Version 2 used by Navicat.
'''
''' This is a port to .net from the original Python3 code made by DoubleLabyrinth
''' Original repository https://github.com/DoubleLabyrinth/how-does-navicat-encrypt-password
''' 
''' You may use this code in any way as you see fit but give at least credits to the original creator
''' 
''' Ported by: CMBSolutions
''' </summary>
Public Class NavicatEncryptV2
    Implements IDisposable

    Private ReadOnly _key As Byte()
    Private ReadOnly _initialVector As Byte()

    Public Sub New()
        _key = Encoding.ASCII.GetBytes("libcckeylibcckey")
        _initialVector = Encoding.ASCII.GetBytes("libcciv libcciv ")
    End Sub

    Public Function Encrypt(s As String) As String
        Dim plaintext As Byte() = Encoding.ASCII.GetBytes(s)

        Using aes As Aes = Aes.Create()
            aes.Key = _key
            aes.IV = _initialVector
            aes.Mode = CipherMode.CBC
            aes.Padding = PaddingMode.PKCS7

            Using encryptor As ICryptoTransform = aes.CreateEncryptor()
                Dim ciphertext As Byte() = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length)
                Return NavicatHelpers.BytesToHex(ciphertext)
            End Using
        End Using
    End Function

    Public Function Decrypt(s As String) As String
        Dim ciphertext As Byte() = NavicatHelpers.HexToBytes(s)

        Using aes As Aes = Aes.Create()
            aes.Key = _key
            aes.IV = _initialVector
            aes.Mode = CipherMode.CBC
            aes.Padding = PaddingMode.PKCS7

            Using decryptor As ICryptoTransform = aes.CreateDecryptor()
                Dim plaintext As Byte() = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length)
                Return Encoding.ASCII.GetString(plaintext)
            End Using
        End Using
    End Function

#Region "IDisposable Support"
    Private disposedValue As Boolean ' To detect redundant calls

    ' IDisposable
    Protected Overridable Sub Dispose(disposing As Boolean)
        If Not disposedValue Then
            If disposing Then

            End If
        End If
        disposedValue = True
    End Sub

    Protected Overrides Sub Finalize()
        Dispose(False)
        MyBase.Finalize()
    End Sub

    Public Sub Dispose() Implements IDisposable.Dispose
        Dispose(True)
        GC.SuppressFinalize(Me)
    End Sub
#End Region
End Class
