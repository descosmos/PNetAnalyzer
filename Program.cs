using System;
using System.Globalization;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System.Net;
using System.Runtime.InteropServices;

namespace ETW {
    class Program
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
        public struct TCP_ESTATS_DATA_ROD_v0
        {
            public ulong SegsOut;
            public ulong SegsIn;
            public ulong SoftErrors;
            public ulong SndUna;
            public ulong SndNxt;
            public ulong SndMax;
            public ulong ThruBytesAcked;
            public ulong RcvNxt;
            public ulong ThruBytesReceived;
            public ulong RcvAckTotal;
            public ulong RcvAckTotalPerFlow;
            public ulong RcvBytesDuplicate;
            public ulong RcvBytesOutOfOrder;
            public ulong AoRetransmitted;
            public ulong SndProbe;
            public ulong RcvProbe;
            public ulong SegsOutPerSec;
            public ulong SegsInPerSec;
            public ulong SoftErrorsPerSec;
            public ulong SndUnaPerSec;
            public ulong SndNxtPerSec;
            public ulong SndMaxPerSec;
            public ulong ThruBytesAckedPerSec;
            public ulong RcvNxtPerSec;
            public ulong ThruBytesReceivedPerSec;
            public ulong RcvAckTotalPerSec;
            public ulong RcvAckTotalPerFlowPerSec;
            public ulong RcvBytesDuplicatePerSec;
            public ulong RcvBytesOutOfOrderPerSec;
            public ulong AoRetransmittedPerSec;
            public ulong SndProbePerSec;
            public ulong RcvProbePerSec;
        }

        static string GetTcpConnectionEStats(string localAddr,string localPort,string remoteAddr,string remotePort)
        {
            MIB_TCPROW row = new MIB_TCPROW();
            row.State = MIB_TCP_STATE.MIB_TCP_STATE_ESTAB;
            
            // row.dwLocalAddr = new byte[] { 10, 11, 146, 62 };
            row.dwLocalAddr = BitConverter.GetBytes(IPAddress.Parse(localAddr).Address);

            ushort port = 57664;
            byte[] portBytes = BitConverter.GetBytes(port);
            row.dwLocalPort = new byte[] { portBytes[1], portBytes[0], 0, 0 };
            
            
            // row.dwRemoteAddr = new byte[] { 119, 23, 45, 236 };
            row.dwRemoteAddr = BitConverter.GetBytes(IPAddress.Parse(remoteAddr).Address);
            
            ushort port2 = 443;
            byte[] portBytes2 = BitConverter.GetBytes(port2);
            row.dwRemotePort = new byte[] { portBytes2[1], portBytes2[0], 0, 0 };

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
                    return retRod.SampleRtt.ToString();
                }
                else
                {
                    return "-";
                }

            }
            return "获取失败!";
        }
        private static void TcpIpSend(TraceEventSession etwSession,int targetPid) {
            Dictionary<string, List<string>> dict = new Dictionary<string, List<string>>();
            var recordTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //记录时间
            etwSession.Source.Kernel.TcpIpSend += data =>
            {
                if (data.ProcessID == targetPid && data.sport == 49756)
                {
                    var currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //当前时间
                    if (dict.Count == 0)
                    {
                        recordTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); //记录时间
                        dict.Add(data.sport.ToString(),new List<string>
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
                                dict.Add(data.sport.ToString(),new List<string>
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
                                                  $" , 远程端口: {entry.Value[3]} , 发送数据包大小: {entry.Value[4]} ," +
                                                  $" 延迟时间: {GetTcpConnectionEStats(entry.Value[1],entry.Key,entry.Value[2],entry.Value[3])}");
                            }
                            recordTime = currentTime;
                            dict.Clear();
                            dict.Add(data.sport.ToString(),new List<string>
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
        
        private static void Main(string[] args) {
            var etwSession = new TraceEventSession("TcpIpSession");
            etwSession.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            var targetPid = 3196;
            TcpIpSend(etwSession,targetPid);
            etwSession.Source.Process();
        }
        
        
        
        
        
        
        
        
    }
}
