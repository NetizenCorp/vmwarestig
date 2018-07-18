import os
import subprocess

from stig_report import stig_report

class esxi_stig(object):

    def __init__(self):
        self.powershell = None
        self.output = None
        self.vcenter = None
        self.esxi_server = None
        self.esxi_username = None
        self.esxi_password = None
        self.vcenter_log = None

    def esxi_connect(self):
        COMMAND_LINE = 'powershell'
        self.powershell = subprocess.Popen(COMMAND_LINE, shell=True,
                                           stdin=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdout=subprocess.PIPE)
        self.output = self.powershell.stdout.readline()

        self.powershell.stdin.write('Set-Location "C:\Program Files (x86)\VMware\Infrastructure\PowerCLI\Scripts"\r\n')
        self.powershell.stdin.write('.\Initialize-PowerCLIEnvironment.ps1\r\n')
        self.powershell.stdin.flush()
        self.powershell.stdin.write("Connect-VIServer " + self.esxi_server + " -Port 443 " +
                                    "-User " + self.esxi_username + " -Password '" + self.esxi_password + "'\r\n")
        self.powershell.stdin.flush()
        self.powershell.stdin.write("Write-Output '########'\n\r")
        self.powershell.stdin.flush()
        self.vcenter_log = open('esxi_stig_output.txt','w')

    def esxi_command(self, command):
        self.powershell.stdin.write(command)
        self.powershell.stdin.flush()

    def esxi_close(self):
        self.output = self.powershell.stdout.readline()
        out = self.powershell.communicate()[0]
        return(out)

    def esxi_run(self):

        #e = esxi_stig()
        #e.esxi_server = "10.0.2.5"
        #e.esxi_username = "root"
        #e.esxi_password = "Free$411"

        s = stig_report()

        self.esxi_connect()
        
        vuln_num = 'V-63147'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63173'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name DCUI.Access'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63175'
        cat_num = 'CAT III'
        passed_command = ('$vmhost = Get-VMHost | Get-View;' +
                          '$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager;' +
                          '$lockdown.QueryLockdownExceptions()')
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #1
        vuln_num = 'V-63177'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63179'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63181'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63183'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63185'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #2
        vuln_num = 'V-63187'
        vuln_num = 'V-63189'
        vuln_num = 'V-63191'
        vuln_num = 'V-63193'
        vuln_num = 'V-63195'
        vuln_num = 'V-63197'
        vuln_num = 'V-63199'
        vuln_num = 'V-63201'
        vuln_num = 'V-63203'
        vuln_num = 'V-63205'
        vuln_num = 'V-63207'
        vuln_num = 'V-63209'
        vuln_num = 'V-63211'
        vuln_num = 'V-63213'
        vuln_num = 'V-63215'
        vuln_num = 'V-63217'
        vuln_num = 'V-63219'
        vuln_num = 'V-63221'
        vuln_num = 'V-63223'
        vuln_num = 'V-63225'
        vuln_num = 'V-63227'
        vuln_num = 'V-63229'
        #needs to ssh into esxi

        vuln_num = 'V-63231'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63233'
        vuln_num = 'V-63235'
        #needs to ssh into esxi

        vuln_num = 'V-63237'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63239'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63241'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63243'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63245'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, @{N="HostProfile";E={$_ | Get-VMHostProfile}}, @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")


        vuln_num = 'V-63247'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63251'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63251'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63255'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63257'
        cat_num = 'CAT III'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.system.coredump.partition.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63257'
        cat_num = 'CAT III'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.system.coredump.network.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")


        vuln_num = 'V-63259'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63261'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostNTPServer'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #3

        vuln_num = 'V-63261'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63263'
        cat_num = 'CAT I'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.software.acceptance.get()"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63275'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHostSnmp | Select *'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63277'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63279'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63281'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostFirewallException | Where {$_.Enabled -eq $true} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63283'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHostFirewallDefaultPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63283'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63287'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualSwitch | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #4

        vuln_num = 'V-63287'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63289'
        cat_num = 'CAT I'
        passed_command = 'Get-VirtualSwitch | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63289'
        cat_num = 'CAT I'
        passed_command = 'Get-VirtualPortGroup | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63291'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualSwitch | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63291'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63293'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63295'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Select Name, VLanId'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63297'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Select Name, VLanID'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        #e.esxi_server = "10.0.2.5"
        #e.esxi_username = "root"
        #e.esxi_password = "Free$411"

        self.esxi_connect()
        #5

        vuln_num = 'V-63299'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Select Name, VLanID'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63465'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63477'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63485'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63501'
        #needs to ssh into esxi

        vuln_num = 'V-63509'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #6

        vuln_num = 'V-63531'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63605'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63757'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63769'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63773'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63775'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #7

        vuln_num = 'V-63777'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63779'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostNTPServer'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63779'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63823'
        cat_num = 'CAT I'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.software.acceptance.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63833'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63867'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63885'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63893'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63895'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63897'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #8


        vuln_num = 'V-63901'
        cat_num = 'CAT I'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.software.acceptance.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63903'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63905'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63907'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63909'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        #e.esxi_server = "10.0.2.5"
        #e.esxi_username = "root"
        #e.esxi_password = "Free$411"

        self.esxi_connect()


        #9

        vuln_num = 'V-63911'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63915'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63915'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #10

        vuln_num = 'V-63921'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63923'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        '''
        vuln_num = 'V-73135'
        cat_num = 'CAT III'
        passed_command = 'If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){Write-Host "VSAN Enabled Cluster found"Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match "vsan"}}else{Write-Host "VSAN is not enabled, this finding is not applicable"}'
        e.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")
        '''



        #print e.esxi_close()


        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""
        #s.close_report()
        self.vcenter_log.close() 
