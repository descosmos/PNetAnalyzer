using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetWorkTool
{
    public class TcpIpTool
    {



        [DllImport("Iphlpapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetPerTcpConnectionEStats(ref MIB_TCPROW Row, TCP_ESTATS_TYPE EstatsType,
            IntPtr Rw, uint RwVersion, uint RwSize, IntPtr Ros, uint RosVersion, uint RosSize, IntPtr Rod,
            uint RodVersion, uint RodSize);

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW
        {
            public MIB_TCP_STATE State;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] dwLocalAddr;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] dwLocalPort;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] dwRemoteAddr;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] dwRemotePort;
        }

        public enum TCP_ESTATS_TYPE
        {
            TcpConnectionEstatsSynOpts,
            TcpConnectionEstatsData,
            TcpConnectionEstatsSndCong,
            TcpConnectionEstatsPath,
            TcpConnectionEstatsSendBuff,
            TcpConnectionEstatsRec,
            TcpConnectionEstatsObsRec,
            TcpConnectionEstatsBandwidth,
            TcpConnectionEstatsFineRtt,
            TcpConnectionEstatsMaximum
        }
        public enum MIB_TCP_STATE
        {
            MIB_TCP_STATE_CLOSED = 1,
            MIB_TCP_STATE_LISTEN = 2,
            MIB_TCP_STATE_SYN_SENT = 3,
            MIB_TCP_STATE_SYN_RCVD = 4,
            MIB_TCP_STATE_ESTAB = 5,
            MIB_TCP_STATE_FIN_WAIT1 = 6,
            MIB_TCP_STATE_FIN_WAIT2 = 7,
            MIB_TCP_STATE_CLOSE_WAIT = 8,
            MIB_TCP_STATE_CLOSING = 9,
            MIB_TCP_STATE_LAST_ACK = 10,
            MIB_TCP_STATE_TIME_WAIT = 11,
            MIB_TCP_STATE_DELETE_TCB = 12,

            //
            // Extra TCP states not defined in the MIB
            //
            MIB_TCP_STATE_RESERVED = 100
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct TCP_ESTATS_PATH_RW_v0
        {
            byte EnableCollection;
        }
        public struct TCP_ESTATS_PATH_ROD_v0
        {
            public uint FastRetran;
            public uint Timeouts;
            public uint SubsequentTimeouts;
            public uint CurTimeoutCount;
            public uint AbruptTimeouts;
            public uint PktsRetrans;
            public uint BytesRetrans;
            public uint DupAcksIn;
            public uint SacksRcvd;
            public uint SackBlocksRcvd;
            public uint CongSignals;
            public uint PreCongSumCwnd;
            public uint PreCongSumRtt;
            public uint PostCongSumRtt;
            public uint PostCongCountRtt;
            public uint EcnSignals;
            public uint EceRcvd;
            public uint SendStall;
            public uint QuenchRcvd;
            public uint RetranThresh;
            public uint SndDupAckEpisodes;
            public uint SumBytesReordered;
            public uint NonRecovDa;
            public uint NonRecovDaEpisodes;
            public uint AckAfterFr;
            public uint DsackDups;
            public uint SampleRtt;
            public uint SmoothedRtt;
            public uint RttVar;
            public uint MaxRtt;
            public uint MinRtt;
            public uint SumRtt;
            public uint CountRtt;
            public uint CurRto;
            public uint MaxRto;
            public uint MinRto;
            public uint CurMss;
            public uint MaxMss;
            public uint MinMss;
            public uint SpuriousRtoDetections;
        }
        static string GetTcpConnectionEStats(string localAddr, string localPort, string remoteAddr, string remotePort)
        {
            MIB_TCPROW row = new MIB_TCPROW();
            row.State = MIB_TCP_STATE.MIB_TCP_STATE_ESTAB;

            //本地地址
            row.dwLocalAddr = IPAddress.Parse(localAddr).GetAddressBytes();


            //本地端口
            byte[] localPortBytes = BitConverter.GetBytes(int.Parse(localPort));
            row.dwLocalPort = new byte[] { localPortBytes[1], localPortBytes[0], 0, 0 };

            //远程地址
            row.dwRemoteAddr = IPAddress.Parse(remoteAddr).GetAddressBytes();


            //远程端口
            byte[] remotePortBytes = BitConverter.GetBytes(int.Parse(remotePort));
            row.dwRemotePort = new byte[] { remotePortBytes[1], remotePortBytes[0], 0, 0 };

            IntPtr pRw = IntPtr.Zero;
            IntPtr pRod = IntPtr.Zero;

            int nRwSize = Marshal.SizeOf<TCP_ESTATS_PATH_RW_v0>();
            pRw = Marshal.AllocHGlobal(nRwSize);
            int nRodSize = Marshal.SizeOf<TCP_ESTATS_PATH_ROD_v0>();
            pRod = Marshal.AllocHGlobal(nRodSize);
            var nRet = GetPerTcpConnectionEStats(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsPath,
                pRw, 0, (uint)nRwSize, IntPtr.Zero, 0, 0, pRod, 0, (uint)nRodSize);
            if (nRet != 1668)
            {
                var retRod = Marshal.PtrToStructure<TCP_ESTATS_PATH_ROD_v0>(pRod);
                // Console.WriteLine($"Remote IP address: {string.Join(".", row.dwRemoteAddr)}");
                // Console.WriteLine($"Remote port: {BitConverter.ToUInt16(row.dwRemotePort, 0)}");
                if (retRod.SampleRtt != 4294967295)
                {
                    if (retRod.SampleRtt > 100000)
                    {
                        return "-";
                    }
                    else
                    {
                        return retRod.SampleRtt.ToString();
                    }
                }
                else
                {
                    return "-";
                }

            }
            return "获取失败!";
        }
        private static void TcpIpSend(TraceEventSession etwSession, int targetPid)
        {
            Dictionary<string, List<string>> dict = new Dictionary<string, List<string>>();
            var recordTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //记录时间
            etwSession.Source.Kernel.TcpIpSend += data =>
            {
                if (data.ProcessID == targetPid)
                {

                    var currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //当前时间
                    // Console.WriteLine($"XXXXX名称: {data.ProcessName} , 本地地址: {data.saddr} , 本地端口: {data.sport} , 远程地址: {data.daddr}" +
                    //                   $" , 远程端口: {data.dport} , 发送数据包大小: {data.size} , 时间: {currentTime}");
                    if (dict.Count == 0)
                    {
                        recordTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //记录时间
                        dict.Add(data.sport.ToString(), new List<string>
                        {
                            data.ProcessName.ToString(), //名称
                            data.saddr.ToString(), //本地地址
                            data.daddr.ToString(), //远程地址
                            data.dport.ToString(), //远程端口
                            data.size.ToString(), //发送数据包大小
                        });
                    }
                    else
                    {
                        if (currentTime == recordTime)
                        {
                            if (!dict.ContainsKey(data.sport.ToString()))
                            {
                                dict.Add(data.sport.ToString(), new List<string>
                                {
                                    data.ProcessName.ToString(), //名称
                                    data.saddr.ToString(), //本地地址
                                    data.daddr.ToString(), //远程地址
                                    data.dport.ToString(), //远程端口
                                    data.size.ToString(), //发送数据包大小
                                });
                            }
                            else
                            {
                                dict[data.sport.ToString()][4] = (int.Parse(dict[data.sport.ToString()][4]) + data.size).ToString();
                            }
                        }
                        else
                        {
                            foreach (KeyValuePair<string, List<string>> entry in dict)
                            {
                                Console.WriteLine($"名称: {entry.Value[0]} , 本地地址: {entry.Value[1]} , 本地端口: {entry.Key} , 远程地址: {entry.Value[2]}" +
                                                  $" , 远程端口: {entry.Value[3]} , 发送数据包大小: {entry.Value[4]}" +
                                                  $" 延迟时间: {GetTcpConnectionEStats(entry.Value[1], entry.Key, entry.Value[2], entry.Value[3])} ms , 时间: {currentTime}");
                            }
                            recordTime = currentTime;
                            dict.Clear();
                            dict.Add(data.sport.ToString(), new List<string>
                            {
                                data.ProcessName.ToString(), //名称
                                data.saddr.ToString(), //本地地址
                                data.daddr.ToString(), //远程地址
                                data.dport.ToString(), //远程端口
                                data.size.ToString(), //发送数据包大小
                            });
                        }
                    }
                }
            };
        }


        private static void TcpIpRecv(TraceEventSession etwSession, int targetPid)
        {
            Dictionary<string, List<string>> dict = new Dictionary<string, List<string>>();
            var recordTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //记录时间
            etwSession.Source.Kernel.TcpIpRecv += data =>
            {
                if (data.ProcessID == targetPid)
                {

                    var currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //当前时间
                    // Console.WriteLine($"XXXXX名称: {data.ProcessName} , 本地地址: {data.saddr} , 本地端口: {data.sport} , 远程地址: {data.daddr}" +
                    //                   $" , 远程端口: {data.dport} , 发送数据包大小: {data.size} , 时间: {currentTime}");
                    if (dict.Count == 0)
                    {
                        recordTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //记录时间
                        dict.Add(data.sport.ToString(), new List<string>
                        {
                            data.ProcessName.ToString(), //名称
                            data.saddr.ToString(), //本地地址
                            data.daddr.ToString(), //远程地址
                            data.dport.ToString(), //远程端口
                            data.size.ToString(), //发送数据包大小
                        });
                    }
                    else
                    {
                        if (currentTime == recordTime)
                        {
                            if (!dict.ContainsKey(data.sport.ToString()))
                            {
                                dict.Add(data.sport.ToString(), new List<string>
                                {
                                    data.ProcessName.ToString(), //名称
                                    data.saddr.ToString(), //本地地址
                                    data.daddr.ToString(), //远程地址
                                    data.dport.ToString(), //远程端口
                                    data.size.ToString(), //发送数据包大小
                                });
                            }
                            else
                            {
                                dict[data.sport.ToString()][4] = (int.Parse(dict[data.sport.ToString()][4]) + data.size).ToString();
                            }
                        }
                        else
                        {
                            foreach (KeyValuePair<string, List<string>> entry in dict)
                            {
                                Console.WriteLine($"名称: {entry.Value[0]} , 本地地址: {entry.Value[1]} , 本地端口: {entry.Key} , 远程地址: {entry.Value[2]}" +
                                                  $" , 远程端口: {entry.Value[3]} , 接收数据包大小: {entry.Value[4]}" +
                                                  $" 延迟时间: {GetTcpConnectionEStats(entry.Value[1], entry.Key, entry.Value[2], entry.Value[3])} ms , 时间: {currentTime}");
                            }
                            recordTime = currentTime;
                            dict.Clear();
                            dict.Add(data.sport.ToString(), new List<string>
                            {
                                data.ProcessName.ToString(), //名称
                                data.saddr.ToString(), //本地地址
                                data.daddr.ToString(), //远程地址
                                data.dport.ToString(), //远程端口
                                data.size.ToString(), //发送数据包大小
                            });
                        }
                    }
                }
            };
        }




        public void TcpIpSendAndRecv(int targetPid)
        {
            var etwSession = new TraceEventSession("TcpIpSession");
            etwSession.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            TcpIpSend(etwSession, targetPid);
            TcpIpRecv(etwSession, targetPid);
            etwSession.Source.Process();
        }


    }
}
