Imports System.Runtime.InteropServices
Imports System.Text

Public Module NavicatCredHelper
    Private Const CRED_TYPE_GENERIC As Integer = 1

    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)>
    Private Structure CREDENTIAL
        Public Flags As Integer
        Public Type As Integer
        Public TargetName As String
        Public Comment As String
        Public LastWritten As Long
        Public CredentialBlobSize As Integer
        Public CredentialBlob As IntPtr
        Public Persist As Integer
        Public AttributeCount As Integer
        Public Attributes As IntPtr
        Public TargetAlias As String
        Public UserName As String
    End Structure

    <DllImport("advapi32.dll", SetLastError:=True, CharSet:=CharSet.Unicode)>
    Private Function CredRead(target As String, type As Integer, reservedFlag As Integer, ByRef credentialPtr As IntPtr) As Boolean
    End Function

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Sub CredFree(buffer As IntPtr)
    End Sub

    Public Function FetchNavicatCred() As Byte()
        Dim credPtr As IntPtr = IntPtr.Zero

        Try
            If Not CredRead("navicat_cred", CRED_TYPE_GENERIC, 0, credPtr) Then
                Return NavicatHelpers.HexToBytes("FF")
            End If
        Catch ex As Exception
            Return NavicatHelpers.HexToBytes("FE")
        End Try

        Try
            Dim cred As CREDENTIAL = CType(Marshal.PtrToStructure(credPtr, GetType(CREDENTIAL)), CREDENTIAL)

            Dim blob(cred.CredentialBlobSize - 1) As Byte
            Marshal.Copy(cred.CredentialBlob, blob, 0, blob.Length)

            Dim hexString As String = Encoding.ASCII.GetString(blob)
            Return NavicatHelpers.HexToBytes(hexString)
        Finally
            CredFree(credPtr)
        End Try
    End Function

    Public Function DeriveV3KeyFromNavicatCred(data As Byte()) As Byte()
        If data Is Nothing Then Throw New ArgumentNullException(NameOf(data))
        If data.Length < 29 Then Throw New ArgumentException("navicat_cred is shorter than expected.")

        Dim table(31) As Byte
        For i As Integer = 0 To 31
            table(i) = CByte(i + 1)
        Next

        Dim aes256Key As Byte() = CType(data.Clone(), Byte())
        aes256Key(25) = table(2)
        aes256Key(26) = table(0)
        aes256Key(27) = table(2)
        aes256Key(28) = table(5)

        Return aes256Key
    End Function
End Module