using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;


namespace WindowsFormsApplication2
{
    public partial class Sniffer : Form
    {
        List <transfer> PacketData = new List<transfer>();
         public int nr;
        public Sniffer()
        {
            InitializeComponent();
            backgroundWorker1.WorkerReportsProgress = true;
            backgroundWorker1.ProgressChanged += new ProgressChangedEventHandler(backgroundWorker1_ProgressChanged);
            listBox1.MouseDoubleClick += new MouseEventHandler(listBox1_MouseDoubleClick);
            backgroundWorker1.WorkerSupportsCancellation = true;
            backgroundWorker2.WorkerReportsProgress = true;
            backgroundWorker2.ProgressChanged += new ProgressChangedEventHandler(backgroundWorker2_ProgressChanged);
            backgroundWorker2.WorkerSupportsCancellation = true;

        }



        private void button1_Click(object sender, EventArgs e)
        {
            if (backgroundWorker1.IsBusy != true)
            {

                backgroundWorker1.RunWorkerAsync();
                button1.Text = "Stop";

            }

            else if (backgroundWorker1.WorkerSupportsCancellation == true)
            {
                backgroundWorker1.CancelAsync();
                button1.Text = "Start";

            }
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            capture capt = new capture();
            BackgroundWorker worker = sender as BackgroundWorker;
            while (true)
            {
                if (worker.CancellationPending == true)
                {
                    e.Cancel = true;
                    break;

                }
                 string s="";
                 MethodInvoker combo = new MethodInvoker(() =>
    {
        s = comboBox1.Text;
    });
                 comboBox1.Invoke(combo);

                capt.ipCapt(backgroundWorker1,checkBox2,s,button1);
            }

        }

        public void backgroundWorker1_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            transfer Packet = (transfer)e.UserState;
            string display;
            if(checkBox2.Checked)
                display = string.Format("{0,10:D} :  {1,10:D}{2,10:D}{3,10:D}{4,10:D}{5,10:D}", Packet.SourceDns, Packet.DestDns, Packet.protocol, Packet.srcPort, Packet.destPort,Packet.totalLength);
            else
                display = string.Format("{0,10:D}  : {1,10:D}{2,10:D}{3,10:D}{4,10:D}{5,10:D}", Packet.source, Packet.destination, Packet.protocol, Packet.srcPort, Packet.destPort,Packet.totalLength);
            listBox1.Items.Add(display);
            int nr;
            int.TryParse(listBox1.Items.Count.ToString(), out nr);
            PacketData.Add(Packet);
        }
        void listBox1_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            int nrItem = this.listBox1.IndexFromPoint(e.Location);
            textBox1.Text = "";
            
           
          
            if (checkBox1.Checked == true)
            {
                if (!backgroundWorker2.IsBusy)
                    backgroundWorker2.RunWorkerAsync(nrItem);
            }

            else if (listBox1.SelectedItem != null)
            {
                textBox1.Text = "Version: "
                + PacketData[nrItem].version +
                "\r\n Header length: "
                + PacketData[nrItem].headerLength +
                "\r\n DSCP : " + PacketData[nrItem].DSCP +
                "\r\n ESCP :" + PacketData[nrItem].ESCN +
                "\r\n Total Length :" + PacketData[nrItem].totalLength +
                 "\r\n Identification :" + PacketData[nrItem].Identification +
                 "\r\n Fragmentation :" + PacketData[nrItem].fragmentation +
                 "\r\n Offset: " + PacketData[nrItem].offset +
                 "\r\n TTL :" + PacketData[nrItem].TTL +
                 "\r\n Protocol :" + PacketData[nrItem].protocol +
                 "\r\n Checksum :" + PacketData[nrItem].checksum +
                 "\r\n Source :" + PacketData[nrItem].source +
                 "\r\n Destination: " + PacketData[nrItem].destination;
               
                if (PacketData[nrItem].protocol == "TCP")
                {
                    textBox1.Text = textBox1.Text + "\r\n\r\n TCP Header :" +
                        "\r\n Source Port :" + PacketData[nrItem].srcPort +
                        "\r\n  Dest. Port :" + PacketData[nrItem].destPort +
                        "\r\n Seq number :" + PacketData[nrItem].seqNumber +
                        "\r\n Ack number  :" + PacketData[nrItem].ackNumber +
                        "\r\n Data offset :" + PacketData[nrItem].tcpOffData +
                        "\r\n NS :" + PacketData[nrItem].ns +
                        "\r\n CWR :" + PacketData[nrItem].cwr +
                        "\r\n ECE :" + PacketData[nrItem].ece +
                        "\r\n URG :" + PacketData[nrItem].urg +
                        "\r\n ACK :" + PacketData[nrItem].ack +
                        "\r\n PSH :" + PacketData[nrItem].psh +
                        "\r\n RST :" + PacketData[nrItem].rst +
                        "\r\n SYN :" + PacketData[nrItem].syn +
                        "\r\n FIN :" + PacketData[nrItem].fin +
                        "\r\n Windows size :" + PacketData[nrItem].WindowSize +
                        "\r\n Checksum :" + PacketData[nrItem].TcpChecksum;
                    
                }
                else if (PacketData[nrItem].protocol == "UDP")
                {
                    textBox1.Text = textBox1.Text + "\r\n\r\n UDP Header :" +
                         "\r\n Source Port :" + PacketData[nrItem].srcPort +
                        "\r\n  Dest. Port :" + PacketData[nrItem].destPort +
                        "\r\n Length :" + PacketData[nrItem].udpLength +
                        "\r\n Checksum :" + PacketData[nrItem].udpChecksum;

                }
                textBox1.Text = textBox1.Text + "\r\n Data: " + PacketData[nrItem].data;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Form2 frm = new Form2();
            frm.Show();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            listBox1.Items.Clear();
            nr = 0;
            PacketData.Clear();

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            IPHostEntry host;
            host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList)
            {
                comboBox1.Items.Add(ip.ToString());
                   
                
            }
        }

        private void backgroundWorker2_DoWork(object sender, DoWorkEventArgs e)
        {
            int nrItem = (int)e.Argument;


            try
            {
                PacketData[nrItem].SourceDns = Dns.GetHostEntry(PacketData[nrItem].source).HostName;
            }
            catch
            {
                PacketData[nrItem].SourceDns = PacketData[nrItem].source;

            }
            try
            {
                PacketData[nrItem].DestDns = Dns.GetHostEntry(PacketData[nrItem].destination).HostName;
            }
            catch
            {
                PacketData[nrItem].DestDns = PacketData[nrItem].destination;
            }
            backgroundWorker2.ReportProgress(nrItem);

          

            }
              public void backgroundWorker2_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
                  int nrItem=(int)e.ProgressPercentage;
            

            if (listBox1.SelectedItem != null &&PacketData[nrItem].totalLength!="40")
            {
               
                textBox1.Text = "Version: "
                + PacketData[nrItem].version +
                "\r\n Header length: "
                + PacketData[nrItem].headerLength +
                "\r\n Total Length :" + PacketData[nrItem].totalLength +
                 "\r\n Identification :" + PacketData[nrItem].Identification +
                 "\r\n Fragmentation :" + PacketData[nrItem].fragmentation +
                  "\r\n Offset :"+PacketData[nrItem].offset +
                 "\r\n TTL :" + PacketData[nrItem].TTL +
                 "\r\n Protocol :" + PacketData[nrItem].protocol +
                 "\r\n Checksum :" + PacketData[nrItem].checksum +
                 "\r\n Source :" + PacketData[nrItem].SourceDns +
                 "\r\n Destination: " + PacketData[nrItem].DestDns;
           
                if (PacketData[nrItem].protocol == "TCP")
                {
                    textBox1.Text = textBox1.Text + "\r\n\r\n TCP Header :" +
                        "\r\n Source Port :" + PacketData[nrItem].srcPort +
                        "\r\n  Dest. Port :" + PacketData[nrItem].destPort +
                        "\r\n Seq number :" + PacketData[nrItem].seqNumber +
                        "\r\n Ack number  :" + PacketData[nrItem].ackNumber +
                        "\r\n Data offset :" + PacketData[nrItem].tcpOffData +
                        "\r\n NS :" + PacketData[nrItem].ns +
                        "\r\n CWR :" + PacketData[nrItem].cwr +
                        "\r\n ECE :" + PacketData[nrItem].ece +
                        "\r\n URG :" + PacketData[nrItem].urg +
                        "\r\n ACK :" + PacketData[nrItem].ack +
                        "\r\n PSH :" + PacketData[nrItem].psh +
                        "\r\n RST :" + PacketData[nrItem].rst +
                        "\r\n SYN :" + PacketData[nrItem].syn +
                        "\r\n FIN :" + PacketData[nrItem].fin +
                        "\r\n Windows size :" + PacketData[nrItem].WindowSize +
                        "\r\n Checksum :" + PacketData[nrItem].TcpChecksum;
                }
                else if (PacketData[nrItem].protocol == "UDP")
                {
                    textBox1.Text = textBox1.Text + "\r\n\r\n UDP Header :" +
                         "\r\n Source Port :" + PacketData[nrItem].srcPort +
                        "\r\n  Dest. Port :" + PacketData[nrItem].destPort +
                        "\r\n Length :" + PacketData[nrItem].udpLength +
                        "\r\n Checksum :" + PacketData[nrItem].udpChecksum;

                }
                textBox1.Text = textBox1.Text + "\r\n Data: " + PacketData[nrItem].data;

        }
        }

              

             

             
    }
}


    

       
      


