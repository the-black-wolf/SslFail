using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SslFailServer
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            var stucker = new AutoResetEvent(false);
            var listener = new TcpListener(new IPEndPoint(IPAddress.Loopback, 10000));
            TcpClient server = null;
            SslStream serverStream = null;
            try
            {
                Console.WriteLine("server prepping certificate");
                var serverCert = new X509Certificate2("fullPKCert.pfx");

                //var s = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.ReadOnly);
                //var serverCert = s.Certificates[0];

                Console.WriteLine($"server listening (cert is {serverCert.Subject}, HasPK: {serverCert.HasPrivateKey})");
                listener.Start();

                server = listener.AcceptTcpClient();
                Console.WriteLine("server accepting connection and negotiating");
                serverStream = new SslStream(server.GetStream(), true,
                    (a1, a2, a3, a4) => true,
                    (a1, a2, a3, a4, a5) => serverCert, EncryptionPolicy.RequireEncryption);
                serverStream.AuthenticateAsServer(serverCert, false, SslProtocols.Tls12, false);
                stucker.Set();
                Console.WriteLine("server secured (details below)");
                Console.WriteLine("---");
                Helper.DisplaySecurityLevel(serverStream);
                Helper.DisplaySecurityServices(serverStream);
                Helper.DisplayCertificateInformation(serverStream);
                Helper.DisplayStreamProperties(serverStream);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception in Server: {e.Message} {e.InnerException?.Message}");
            }
            finally
            {
                // we deliberately want to be stuck here if not secure (we do not want the other side to fail on dropped connection)
                stucker.WaitOne();
                
                // if I do not do this, the client is hang (presumably until connection dies)
                // even then, the error is dropped connection and not a protocol mismatch, so there is no
                // way to course correct. 
                //ServerClient?.Close();  	

                serverStream?.Dispose();
                server?.Close();
                listener.Stop();
            }
        }

    }
}