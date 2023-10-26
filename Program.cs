using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.VisualBasic;
using System.Drawing;

namespace PNetAnalyzer
{
    class Program
    {
        static void CaptureNetworkCommnunication()
        {
            var etwSession = new TraceEventSession("DescosmosTcpSession");
            etwSession.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            List<List<string>> one = new();
            List<List<string>> two = new();
            List<string> list1 = new List<string>(); // 创建 List<string>
            var targetPid = 8928;
            // var targetPid = 8928;

            Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            etwSession.Source.Kernel.TcpIpSend += data =>
            {

                if (data.ProcessID == targetPid)
                {
                    
                    /*Console.WriteLine(String.Format("名称: {0}, PID: {1}, 本地地址: {2}, 本地端口: {3}, 远程地址: {4}, 远程端口: {5},发送的数据包大小: {6},    {7}   {8}",
                        data.ProcessName,data.ProcessID,data.saddr,data.sport,data.daddr,data.dport, data.size,data.startime,data.endtime));*/
                    var time = DateTime.Now.ToString();
                    if (one.Count == 0)
                    {
                        list1.Add(data.daddr.ToString());  //IP   0
                        list1.Add(data.size.ToString());   //大小  1
                        list1.Add(time);                       //时间   2
                        list1.Add(data.ProcessName.ToString()); //名称
                        list1.Add(data.dport.ToString()); //远程端口
                        one.Add(new List<string>(list1));
                        list1.Clear();
                    }
                    else
                    {

                        if (time == one[one.Count-1][2])
                        {
                            list1.Add(data.daddr.ToString());  //IP   0
                            list1.Add(data.size.ToString());   //大小  1
                            list1.Add(time);                       //时间   2
                            list1.Add(data.ProcessName.ToString()); //名称
                            list1.Add(data.dport.ToString()); //远程端口
                            one.Add(new List<string>(list1));
                            list1.Clear();
                        }
                        else
                        {
                            
                            if (one.Count == 1 && two.Count == 0)
                            {
                                Console.WriteLine(String.Format("名称: {3}, 远程IP: {0}, 远程端口: {4}, 发送数据: {1}, 时间: {2}", one[0][0], one[0][1], one[0][2], one[0][3], one[0][4]));
                                one.Clear();
                                list1.Add(data.daddr.ToString());  //IP   0
                                list1.Add(data.size.ToString());   //大小  1
                                list1.Add(time);                       //时间   2
                                list1.Add(data.ProcessName.ToString()); //名称
                                list1.Add(data.dport.ToString()); //远程端口
                                one.Add(new List<string>(list1));
                                list1.Clear();
                            }
                            while (one.Count!=1)
                            {
                                var size = int.Parse(one[0][1]);
                                for (int i = 1; i < one.Count; i++)
                                {
                                    if (one[0][0] == one[i][0])
                                    {
                                        size += int.Parse(one[i][1]);
                                    }
                                    else
                                    {
                                        two.Add(one[i]);
                                    }
                                }
                                Console.WriteLine(String.Format("名称: {3}, 远程IP: {0}, 远程端口: {4}, 发送数据: {1}, 时间: {2}", one[0][0], size, one[0][2], one[0][3], one[0][4]));
                                one.Clear();
                                if (two.Count != 0)
                                {
                                    one.AddRange(two);
                                     two.Clear();
                                }
                                else
                                {
                                    list1.Add(data.daddr.ToString());  //IP   0
                                    list1.Add(data.size.ToString());   //大小  1
                                    list1.Add(time);                       //时间   2
                                    list1.Add(data.ProcessName.ToString()); //名称
                                    list1.Add(data.dport.ToString()); //远程端口
                                    one.Add(new List<string>(list1));
                                    list1.Clear();
                                    // Console.WriteLine(one[0][1]);
                                    break;
                                }
                            }
                        }

                    }
                }
            };
            /*etwSession.Source.Kernel.TcpIpRecv += data =>
            {

                if (data.ProcessID == targetPid)
                {
                    var rData = data.size;
                    *//* Console.WriteLine(String.Format("名称: {0}, PID: {1}, 本地地址: {2}, 本地端口: {3}, 远程地址: {4}, 远程端口: {5},接收的数据包大小: {6}",
                         data.ProcessName, data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, data.size));*//*
                    Console.WriteLine(String.Format("×远程: {0} , 时间: {1}, 接收的数据包大小: {2}", data.daddr, DateTime.Now, data.size));
                }
            };*/
            etwSession.Source.Process();
        }

        static void Main(string[] args)
        {
            CaptureNetworkCommnunication();
        }
    }
}
