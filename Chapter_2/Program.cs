using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Chapter_2
{
    class Program
    {
        static void Main(string[] args)
        {





            // For POST requests:
            // string[] requestLines = File.ReadAllLines(args[0]);
            // string[] parms = requestLines[requestLines.Length - 1].Split('&');
            // fuzzPostRequests(requestLines, parms);

            // For GET requests:
            // string url = args[0];
            // int index = url.IndexOf("?");
            // string[] parms = url.Remove(0, index+1).Split('&');
            // foreach(string parm in parms)
            // {
            //     fuzzGetRequests(url, parm);
            // }
        }

        private static void fuzzPostRequests(string[] requestLines, string[] parms) {
            string host = string.Empty;
            StringBuilder requestBuilder = new StringBuilder();

            foreach(string ln in requestLines)
            {
                if(ln.StartsWith("Host:"))
                {
                    host = ln.Split(' ')[1].Replace("\r", string.Empty);
                }
                requestBuilder.Append(ln + "\n");
            }
            string request = requestBuilder.ToString() + "\r\n";
            //Console.WriteLine(request);
            IPEndPoint rhost = new IPEndPoint(IPAddress.Parse(host), 80);
            foreach(string parm in parms)
            {
                using(Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.Connect(rhost);

                    // Replace param=val with param=val'
                    string val = parm.Split('=')[1];
                    string req = request.Replace("=" + val, "=" + val + "'");

                    // Send the request
                    byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                    sock.Send(reqBytes);

                    byte[] buf = new byte[sock.ReceiveBufferSize];

                    // Receive the response
                    sock.Receive(buf);
                    string response = Encoding.ASCII.GetString(buf);

                    // Check to see if the variable replacement causes a SQL error for any of the params:
                    if(response.Contains("error in your SQL syntax"))
                    {
                        Console.WriteLine("Parameter " + parm + " seems vulnerable \n to SQL injection with value: " + val + "'");
                    }
                }
            }

        }


        private static void fuzzGetRequests(string url, string parm)
        {
            //Console.WriteLine(parm);
                string xssUrl = url.Replace(parm, parm + "fd<xss>sa");
                string sqlUrl = url.Replace(parm, parm + "fd'sa");

                //Console.WriteLine(xssUrl);
                //Console.WriteLine(sqlUrl);

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(sqlUrl);
                request.Method = "GET";

                string sqlresp = string.Empty;
                using (StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream()))
                {
                    sqlresp = rdr.ReadToEnd();
                }

                request = (HttpWebRequest)WebRequest.Create(xssUrl);
                request.Method = "GET";
                string xssResp = string.Empty;

                using(StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream()))
                {
                    xssResp = rdr.ReadToEnd();
                }
                Console.WriteLine(xssResp);
                Console.WriteLine(sqlresp);
                if(xssResp.Contains("<xss>"))
                {
                    Console.WriteLine("Possible XSS point found in parameter: " + parm);
                }
                if(sqlresp.Contains("error in your SQL syntax"))
                {
                    Console.WriteLine("SQL injection point found in parameter: " + parm);
                }
        }
    }
}
