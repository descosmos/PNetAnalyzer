using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace PNetAnalyzer
{
    class Program
    {
        static void ProcessSession()
        {
            using (var session = new TraceEventSession("DescosmosSession", "MyEventData.etl"))
            {
                session.EnableProvider("Microsoft-Windows-TCPIP");
                System.Threading.Thread.Sleep(10000);
            }
        }

        static void ProcessComsumer()
        {
            using (var source = new ETWTraceEventSource("MyEventData.etl"))
            {
                var kernelParser = new KernelTraceEventParser(source);
                // Subscribe to a particular Kernel event
                kernelParser.ProcessStart += delegate (ProcessTraceData data) {
                    Console.WriteLine("Process {0} Command Line {1}",
                      data.ProcessName, data.CommandLine);
                };

                // Set up the callbacks
                /*
                source.Dynamic.All += delegate (TraceEvent data) {
                    Console.WriteLine("GOT EVENT {0}", data);
                    Console.WriteLine("\n");
                };
                */
                source.Process(); // Invoke callbacks for events in the source
            }
        }

        static void CaptureNetworkCommnunication()
        {
            var etwSession = new TraceEventSession("DescosmosTcpSession");
            etwSession.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

            var targetPid = 14496;

            etwSession.Source.Kernel.UdpIpSend += data =>
            {
                //Console.WriteLine(String.Format("ProcessId: {0} data.saddr: {1}", data.ProcessID, data.saddr.ToString()));
                if (data.ProcessID == targetPid)
                {
                    var rData = data.size;

                    Console.WriteLine(String.Format("<UdpIpSend> pid: {0}, daddr: {1}, rData: {2}", data.ProcessID, data.daddr, data.size));
                }
            };

            etwSession.Source.Kernel.UdpIpRecv += data =>
            {
                //Console.WriteLine(String.Format("ProcessId: {0} data.saddr: {1}", data.ProcessID, data.saddr.ToString()));
                if (data.ProcessID == targetPid)
                {
                    var rData = data.size;

                    Console.WriteLine(String.Format("<UdpIpRecv> pid: {0}, daddr: {1}, rData: {2}", data.ProcessID, data.daddr, data.size));
                }
            };

            etwSession.Source.Kernel.TcpIpSend += data =>
            {
                //Console.WriteLine(String.Format("ProcessId: {0} data.saddr: {1}", data.ProcessID, data.saddr.ToString()));
                if (data.ProcessID == targetPid)
                {
                    var rData = data.size;

                    Console.WriteLine(String.Format("<TcpIpSend> pid: {0}, daddr: {1}, rData: {2}", data.ProcessID, data.daddr, data.size));
                }
            };

            etwSession.Source.Kernel.TcpIpRecv += data =>
            {
                //Console.WriteLine(String.Format("ProcessId: {0} data.saddr: {1}", data.ProcessID, data.saddr.ToString()));
                if (data.ProcessID == targetPid)
                {
                    var rData = data.size;

                    Console.WriteLine(String.Format("<TcpIpRecv> pid: {0}, daddr: {1}, rData: {2}", data.ProcessID, data.daddr, data.size));
                }
            };

            etwSession.Source.Process();
        }

        static void Main(string[] args)
        {
            //ProcessSession();
            //ProcessComsumer();
            CaptureNetworkCommnunication();
        }
    }
}
