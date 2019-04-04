using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SslFailClient
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            var stucker = new AutoResetEvent(false);
            var client = new TcpClient();
            SslStream clientStream = null;
            try
            {
                Console.WriteLine("client connecting");
                var endPoint = new IPEndPoint(IPAddress.Loopback, 10000);
                client.Connect(endPoint.Address, endPoint.Port);
                Console.WriteLine("client negotiating");
                clientStream = new SslStream(client.GetStream(), true,
                    (a1, a2, a3, a4) => true,
                    (a1, a2, a3, a4, a5) => null, EncryptionPolicy.RequireEncryption);
                clientStream.AuthenticateAsClient("localhost");
                stucker.Set();
                Console.WriteLine("client secured (details below)");
                Console.WriteLine("---");
                Helper.DisplaySecurityLevel(clientStream);
                Helper.DisplaySecurityServices(clientStream);
                Helper.DisplayCertificateInformation(clientStream);
                Helper.DisplayStreamProperties(clientStream);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception in client: {e.Message} {e.InnerException?.Message}");
            }
            finally
            {
                // we deliberately want to be stuck here if not secure (we do not want the other side to fail on dropped connection)
                stucker.WaitOne();

                clientStream?.Dispose();
                client.Close();
            }
        }
    }
}