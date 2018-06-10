using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RGiesecke.DllExport;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;

namespace ClassLibraryWrapper
{
    
    public class Class1
    {

        //asta e functia buna de returnare a certificatului
        [DllExport("getCert", CallingConvention=CallingConvention.Cdecl)]
        static public IntPtr getCert(IntPtr username)
        {
            localhost.DSWS ws = new localhost.DSWS();
            string myUsername = Marshal.PtrToStringAnsi(username);
            byte[] result = ws.GetUserCertificate(myUsername);


            IntPtr final = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(byte)) * result.Count());
            Marshal.Copy(result, 0, final, result.Count());
            return final;
        }
         
        //return length of certificae
        [DllExport("getCertLength", CallingConvention=CallingConvention.Cdecl)]
        static public int getCertLength(IntPtr username)
        {
            localhost.DSWS ws = new localhost.DSWS();

            string myUsername = Marshal.PtrToStringAnsi(username);
            byte[] result = ws.GetUserCertificate(myUsername);
            return result.Count();

        }
        //sign data, returns the signature
        [DllExport("signData", CallingConvention = CallingConvention.Cdecl)]
        static public IntPtr signData(IntPtr username, IntPtr password, IntPtr data, int ulDataLen)
        {
            MessageBox.Show(ulDataLen.ToString());
            string myUsername = Marshal.PtrToStringAnsi(username);
            string myPassword = Marshal.PtrToStringAnsi(password);

            byte[] dataToSign = new byte[ulDataLen];
            Marshal.Copy(data, dataToSign, 0, ulDataLen);

            localhost.DSWS ws = new localhost.DSWS();
            byte[] response = ws.SignData(myUsername, myPassword, dataToSign);

            IntPtr signature = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(byte)) * response.Count());

            Marshal.Copy(response, 0, signature, response.Count());

            return signature;

        }


        //return the signature length (the number of bits of private key modulus
        [DllExport("getSignatureLen", CallingConvention = CallingConvention.Cdecl)]
        static public int getSignatureLen(IntPtr username, IntPtr password, IntPtr data, int ulDataLen)
        {
            localhost.DSWS ws = new localhost.DSWS();
            string myUsername = Marshal.PtrToStringAnsi(username);
            string myPassword = Marshal.PtrToStringAnsi(password);
            byte[] dataToSign = new byte[ulDataLen];
            Marshal.Copy(data, dataToSign, 0, ulDataLen);
            return ws.getSignaturelLen(myUsername, myPassword, dataToSign);
        }
      
    }
}
