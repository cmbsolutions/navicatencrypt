Imports System.Text
Imports CMBSolutions
Imports Microsoft.VisualStudio.TestTools.UnitTesting

<TestClass()> Public Class NavicatEncryptTests

    <TestMethod()> Public Sub DecryptV3WithCredStore()
        Using nv3 As New NavicatEncryptV3
            Dim decoded As String = nv3.Decrypt("1D302BD06F9BD6D568B24A34E9D9E191C19182173BD2E4DC88B1FF1510E357D9521C32F137C2AAE3CD08D5AFA964DEE13059490D93E009B8571FC7CC")

            Assert.AreEqual("F1PBG23Ikd4E1esb", decoded)
        End Using

    End Sub

End Class