Imports System.Security.Cryptography
Imports System.Text
Imports Org.BouncyCastle.Crypto.Engines
Imports Org.BouncyCastle.Crypto.Modes
Imports Org.BouncyCastle.Crypto.Parameters

''' <summary>
''' NavicatEncryptV3 will encrypt and decrypt the database passwords stored in the registry as Version 3 used by Navicat.
'''
''' This is a port to .net from the original Python3 code made by DoubleLabyrinth
''' Original repository https://github.com/DoubleLabyrinth/how-does-navicat-encrypt-password
''' 
''' You may use this code in any way as you see fit but give at least credits to the original creator
''' 
''' Ported by: CMBSolutions
''' </summary>
Public Class NavicatEncryptV3
    Implements IDisposable

    Private ReadOnly _key As Byte()

    Public Sub New()
        _key = DeriveV3KeyFromNavicatCred(FetchNavicatCred())
    End Sub

    Public Sub New(key As Byte())
        If key Is Nothing Then Throw New ArgumentNullException(NameOf(key))
        _key = CType(key.Clone(), Byte())
    End Sub

    Private Function Pad(data As Byte()) As Byte()
        Const blockSize As Integer = 16 ' AES block size in bytes

        Dim contentLength As Integer = data.Length
        Dim totalLength As Integer = NavicatHelpers.AlignUp(2 + contentLength, blockSize)
        Dim paddingLength As Integer = totalLength - (2 + contentLength)

        Dim result(totalLength - 1) As Byte

        ' Python: struct.pack("<H...", content_length, ...)
        Dim lenBytes As Byte() = BitConverter.GetBytes(CUShort(contentLength))
        If Not BitConverter.IsLittleEndian Then
            Array.Reverse(lenBytes)
        End If

        result(0) = lenBytes(0)
        result(1) = lenBytes(1)

        Buffer.BlockCopy(data, 0, result, 2, contentLength)

        If paddingLength > 0 Then
            Dim randomPadding(paddingLength - 1) As Byte
            Using rng As RandomNumberGenerator = RandomNumberGenerator.Create()
                rng.GetBytes(randomPadding)
            End Using
            Buffer.BlockCopy(randomPadding, 0, result, 2 + contentLength, paddingLength)
        End If

        Return result
    End Function

    Private Function Unpad(data As Byte()) As Byte()
        Const blockSize As Integer = 16 ' AES block size in bytes

        If data Is Nothing OrElse data.Length < 2 Then
            Throw New CryptographicException("Invalid padded data.")
        End If

        Dim lenBytes(1) As Byte
        lenBytes(0) = data(0)
        lenBytes(1) = data(1)

        If Not BitConverter.IsLittleEndian Then
            Array.Reverse(lenBytes)
        End If

        Dim contentLength As Integer = BitConverter.ToUInt16(lenBytes, 0)
        Dim totalLength As Integer = NavicatHelpers.AlignUp(2 + contentLength, blockSize)

        If data.Length < totalLength Then
            Throw New CryptographicException("Invalid padded data length.")
        End If

        Dim content(contentLength - 1) As Byte
        Buffer.BlockCopy(data, 2, content, 0, contentLength)
        Return content
    End Function

    Public Function Encrypt(s As String) As String
        Dim plaintext As Byte() = Encoding.ASCII.GetBytes(s)
        Dim padded As Byte() = Pad(plaintext)

        Dim nonce(11) As Byte ' 12-byte nonce
        Using rng As RandomNumberGenerator = RandomNumberGenerator.Create()
            rng.GetBytes(nonce)
        End Using

        Dim cipher As New GcmBlockCipher(New AesEngine())
        Dim parameters As New AeadParameters(New KeyParameter(_key), 128, nonce, Nothing)
        cipher.Init(True, parameters)

        Dim output(cipher.GetOutputSize(padded.Length) - 1) As Byte
        Dim outLen As Integer = cipher.ProcessBytes(padded, 0, padded.Length, output, 0)
        outLen += cipher.DoFinal(output, outLen)

        ' BouncyCastle GCM output = ciphertext || tag
        Dim result(nonce.Length + outLen - 1) As Byte
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length)
        Buffer.BlockCopy(output, 0, result, nonce.Length, outLen)

        Return NavicatHelpers.BytesToHex(result)
    End Function

    Public Function Decrypt(s As String) As String
        Dim data As Byte() = NavicatHelpers.HexToBytes(s)

        If data.Length < 12 + 16 Then
            Throw New CryptographicException("Invalid encrypted data.")
        End If

        Dim nonce(11) As Byte
        Buffer.BlockCopy(data, 0, nonce, 0, nonce.Length)

        Dim ciphertextAndTagLength As Integer = data.Length - nonce.Length
        Dim ciphertextAndTag(ciphertextAndTagLength - 1) As Byte
        Buffer.BlockCopy(data, nonce.Length, ciphertextAndTag, 0, ciphertextAndTagLength)

        Dim cipher As New GcmBlockCipher(New AesEngine())
        Dim parameters As New AeadParameters(New KeyParameter(_key), 128, nonce, Nothing)
        cipher.Init(False, parameters)

        Dim output(cipher.GetOutputSize(ciphertextAndTag.Length) - 1) As Byte
        Dim outLen As Integer = cipher.ProcessBytes(ciphertextAndTag, 0, ciphertextAndTag.Length, output, 0)
        outLen += cipher.DoFinal(output, outLen)

        If outLen <> output.Length Then
            Array.Resize(output, outLen)
        End If

        Dim plaintext As Byte() = Unpad(output)
        Return Encoding.ASCII.GetString(plaintext)
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
