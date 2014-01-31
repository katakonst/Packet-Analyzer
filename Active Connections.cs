using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net.NetworkInformation;
using System.Net;

namespace WindowsFormsApplication2
{
    public partial class Form2 : Form
    {
        public Form2()
        {
            InitializeComponent();
            backgroundWorker1.WorkerReportsProgress = true;
            backgroundWorker1.ProgressChanged += new ProgressChangedEventHandler(backgroundWorker1_ProgressChanged);
            backgroundWorker1.WorkerSupportsCancellation = true;
        }

      

        private void button1_Click(object sender, EventArgs e)
        {
          
             if(backgroundWorker1.IsBusy!=true)
            {
                textBox1.Text = "";
                backgroundWorker1.RunWorkerAsync();
            }
            
            else if (backgroundWorker1.WorkerSupportsCancellation == true)
            {
               textBox1.Text = "";
                backgroundWorker1.CancelAsync();
                button1.Enabled = false;
              
                
            }
           
        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            IPGlobalProperties ipGlobal = IPGlobalProperties.GetIPGlobalProperties();
           
            //int i = 0;
            BackgroundWorker back = (BackgroundWorker)sender;
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] tcp = properties.GetActiveTcpConnections();
           //TcpConnectionInformation tcp=new TcpConnectionInformation();

           
                tcp = ipGlobal.GetActiveTcpConnections();
              
                foreach (TcpConnectionInformation i in tcp)
                {
                  
                    if (checkBox1.Checked == true)
                    {
                        transfer tr = new transfer();

                        string[] ipRemote = i.RemoteEndPoint.ToString().Split(':');

                        string[] ipLocal = i.LocalEndPoint.ToString().Split(':');
                    
                        try
                        {
                            ipRemote[0] = Dns.GetHostEntry(ipRemote[0]).HostName;
                            tr.DestDns = ipRemote[0] + ":" + ipRemote[1];

                        }
                        catch
                        {
                            tr.DestDns = ipRemote[0] + ":" + ipRemote[1];
                        }
                        try
                        {
                            ipLocal[0] = Dns.GetHostEntry(ipLocal[0]).HostName;
                            tr.SourceDns = ipLocal[0] + ":" + ipLocal[1];
                        }
                        catch
                        {
                            tr.SourceDns = ipLocal[0] + ":" + ipLocal[1];
                        }
                        
                        tr.state = i.State.ToString();
                        back.ReportProgress(0, tr);
                       
                    }


                    else
                    {
                        back.ReportProgress(0, i);
                    }
                    if (back.CancellationPending == true)
                    {
                        back.ReportProgress(1);
                        e.Cancel = true;
                        break;

                    }
                   
                }
           
              
            }
         

        private void Form2_Load(object sender, EventArgs e)
        {

        }
        public void backgroundWorker1_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            
            string con;
            if (e.ProgressPercentage == 1)
                button1.Enabled = true;
            
            if (checkBox1.Checked==true)
            {
                try
                {
                    transfer tr = (transfer)e.UserState;
                    con = tr.SourceDns + "     " + tr.DestDns + " " + tr.state + "\r\n";
                    textBox1.Text = textBox1.Text + con;
                }
                catch
                {
                    textBox1.Text = " ";
                }

            }
            else
            {
                try
                {
                    TcpConnectionInformation tcp = (TcpConnectionInformation)e.UserState;
                    con = tcp.LocalEndPoint + " : " +"  "+ tcp.RemoteEndPoint + "     " + tcp.State + "\r\n";
                    textBox1.Text = textBox1.Text + con;
                }
                catch
                {
                    textBox1.Text = " ";
                }
            }
            
          
        }

        private void button2_Click(object sender, EventArgs e)
        {
            textBox1.Text = " ";
        }
    }
}