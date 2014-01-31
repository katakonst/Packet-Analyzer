using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Threading;
using System.Net.Sockets;
using System.IO;
using System.Net;

namespace WindowsFormsApplication2
{
    class capture
    {
        public void ipCapt(BackgroundWorker bc, CheckBox ck, string ip,Button But)
        {
            try
            {
                transfer PacketData = new transfer();
                Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                IPEndPoint ipend = new IPEndPoint(IPAddress.Parse(ip), 0);

                sock.Bind(ipend);
                sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                byte[] syorcval = new byte[4] { 1, 0, 0, 0 };
                byte[] dataLength = new byte[4] { 1, 1, 1, 1 };
                sock.IOControl(IOControlCode.ReceiveAll, syorcval, dataLength);
                byte[] data = new byte[65000];
                sock.Receive(data);
                MemoryStream buffer = new MemoryStream(data);
                BinaryReader read = new BinaryReader(buffer);
                byte c = 0;
                byte s = read.ReadByte();
                c = s;
                c <<= 4;
                c >>= 4;
                s >>= 4;
                PacketData.version = s.ToString();
                PacketData.headerLength = c.ToString();
                byte DcspEscn = read.ReadByte();
                PacketData.DSCP = ((DcspEscn >> 2) << 2).ToString();
                PacketData.ESCN = (DcspEscn << 6).ToString();
                ushort length = (ushort)IPAddress.NetworkToHostOrder(read.ReadInt16());
                PacketData.totalLength = length.ToString();
                PacketData.Identification = ((ushort)IPAddress.NetworkToHostOrder(read.ReadInt16())).ToString();
                ushort flag = (ushort)IPAddress.NetworkToHostOrder(read.ReadInt16());
                int df = flag >> 13;
                //int mf = flagoff & (1 << 2) ;
                if (df == 2)
                    PacketData.fragmentation = "NO";
                else if (df == 8)
                    PacketData.fragmentation = "YES";
                else
                    PacketData.fragmentation = "0-Reserved";
                int off = flag << 3;
                off >>= 3;
                PacketData.offset = off.ToString();
                PacketData.TTL = read.ReadByte().ToString();
                string prot = read.ReadByte().ToString();
                if (prot == "6")
                    PacketData.protocol = "TCP";
                else if (prot == "17")
                    PacketData.protocol = "UDP";
                else
                    PacketData.protocol = "other";
                int checksumIp = IPAddress.NetworkToHostOrder(read.ReadInt16());
                string checksumIps = BitConverter.ToString(BitConverter.GetBytes(checksumIp));
                checksumIps = checksumIps.Replace("-", "");
                PacketData.checksum = checksumIps;
                IPAddress a = new IPAddress((uint)read.ReadInt32());

                IPAddress d = new IPAddress((uint)read.ReadInt32());
                if (ck.Checked)
                {
                    try
                    {
                        PacketData.SourceDns = Dns.GetHostEntry(a.ToString()).HostName;
                    }
                    catch
                    {

                        PacketData.SourceDns = a.ToString();
                    }
                    try
                    {
                        PacketData.DestDns = Dns.GetHostEntry(d.ToString()).HostName;
                    }
                    catch
                    {
                        PacketData.DestDns = d.ToString();
                    }
                }

                PacketData.source = a.ToString();
                PacketData.destination = d.ToString();

                PacketData.srcPort = (((ushort)IPAddress.NetworkToHostOrder(read.ReadInt16())).ToString());
                PacketData.destPort = (((ushort)IPAddress.NetworkToHostOrder(read.ReadInt16())).ToString());
                if (PacketData.protocol == "TCP")
                {
                    PacketData.seqNumber = (((uint)IPAddress.NetworkToHostOrder(read.ReadInt32())).ToString());
                    PacketData.ackNumber = (((uint)IPAddress.NetworkToHostOrder(read.ReadInt32())).ToString());
                    //ushort offflag = (ushort)IPAddress.NetworkToHostOrder(read.ReadInt16());
                    byte offtcp = read.ReadByte();
                    PacketData.tcpOffData = (offtcp >> 4).ToString();
                    byte flagtcp = read.ReadByte();
                    PacketData.ns = ((offtcp & (1 << 7)) != 0).ToString();
                    PacketData.cwr = ((flagtcp & (1 << 0)) != 0).ToString();
                    PacketData.ece = ((flagtcp & (1 << 1)) != 0).ToString();
                    PacketData.urg = ((flagtcp & (1 << 2)) != 0).ToString();
                    PacketData.ack = ((flagtcp & (1 << 3)) != 0).ToString();
                    PacketData.psh = ((flagtcp & (1 << 4)) != 0).ToString();
                    PacketData.rst = ((flagtcp & (1 << 5)) != 0).ToString();
                    PacketData.syn = ((flagtcp & (1 << 6)) != 0).ToString();
                    PacketData.fin = ((flagtcp & (1 << 7)) != 0).ToString();
                    PacketData.WindowSize = ((ushort)IPAddress.NetworkToHostOrder(read.ReadInt16())).ToString();
                    int checksumTcp = IPAddress.NetworkToHostOrder(read.ReadInt16());
                    string checksumTcpString = BitConverter.ToString(BitConverter.GetBytes(checksumTcp));
                    checksumTcpString = checksumTcpString.Replace("-", "");
                    PacketData.TcpChecksum = checksumTcpString;
                    if (PacketData.urg == "true")
                        PacketData.urg = ((uint)IPAddress.NetworkToHostOrder(read.ReadInt32())).ToString();
                    read.ReadBytes(2);
                }
                else if (PacketData.protocol == "UDP")
                {

                    PacketData.udpLength = ((ushort)IPAddress.NetworkToHostOrder(read.ReadInt16())).ToString();
                    int checksumUdp = IPAddress.NetworkToHostOrder(read.ReadInt16());
                    string checksumUdps = BitConverter.ToString(BitConverter.GetBytes(checksumUdp));
                    checksumUdps = checksumUdps.Replace("-", "");
                    PacketData.udpChecksum = checksumUdps;
                }
              
                byte[] datas = new byte[10024];
                if (PacketData.protocol == "UDP")
                {
                    datas = read.ReadBytes(length - 28);
                    datas.Reverse();

                }
                else if (PacketData.protocol == "TCP")
                {
                    datas = read.ReadBytes(length - 40);
                    datas.Reverse();
                }

                
                PacketData.data = Encoding.ASCII.GetString(datas);
                bc.ReportProgress(0, PacketData);
                Thread.Sleep(60);
            }
            catch
            {
                MessageBox.Show("Error \r\nTry another interface");
                bc.CancelAsync();
                But.Invoke((MethodInvoker)(() => But.Text ="Start")); 
                return;

            }
        }
    
    }
}
