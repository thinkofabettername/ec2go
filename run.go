package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func runUsage() {
	fmt.Println(`Usage: ec2go run -i <instance type> -r <region>`)
}

func getUserData() string {
	//fmt.Println("!!userdata!!")
	//fmt.Printf("%v\n", cargs)
	if cargs.distros[0] == "windows" {
		return base64.StdEncoding.EncodeToString([]byte(`<powershell>

echo $null > C:\userdata_start_canary.txt
echo $null > C:\Users\Administrator\Desktop\userdata_start_canary.txt

# open ssh port first as connection refused has a linear try again time
# whereas timeout have an exponential backoff.
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}

netsh advfirewall firewall add rule name="Open Port 22" dir=in action=allow protocol=TCP localport=22

# install ssh
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

#start ssh - this needs to be fone before editing the config as the default config is generated on first start
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

$sshd_configfile = 'C:\ProgramData\ssh\sshd_config'
$content = Get-Content $sshd_configfile 
$regex = '^(\s*Match Group Administrator)'
$content = $content -replace $regex, '#${1}'

$regex = '^(\s*AuthorizedKeysFile.*administrators_authorized_keys.*)'
$content = $content -replace $regex, '#${1}'
echo $content | Set-Content $sshd_configfile

Restart-Service sshd

# used io.file because UTF-8 is required by sshd
$token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri http://169.254.169.254/latest/api/token
$key = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
mkdir "C:\Users\Administrator\.ssh\"
[IO.File]::WriteAllLines("C:\Users\Administrator\.ssh\authorized_keys",$key)

icacls.exe "C:\Users\Administrator\.ssh\authorized_keys" /inheritance:r /grant "Administrator:F" /grant "SYSTEM:F"

echo $null > C:\userdata_end_canary.txt
echo $null > C:\Users\Administrator\Desktop\userdata_end_canary.txt
</powershell>
			`))
	}

	return base64.StdEncoding.EncodeToString([]byte(`#!/bin/bash
function die {
        sleep 21600 ; poweroff
}
die &
echo export TERM=xterm >> /root/.bashrc
echo export TERM=xterm >> /home/admin/.bashrc
echo export EDITOR='vim' >> /root/.bashrc
echo export EDITOR='vim' >> /home/admin/.bashrc

BASHRC="ZnVuY3Rpb24gaXBjaGVjayB7CgljdXJsIGNoZWNraXAuYW1hem9uYXdzLmNvbSAyPiAvZGV2L251bGwKfQoKZnVuY3Rpb24gd2hvaXNjaGVjayB7Cgl3aG9pcyAkKGlwY2hlY2spCn0KCmZ1bmN0aW9uIGltZHMgewoJVE9LRU49JChjdXJsIC1YIFBVVCAiaHR0cDovLzE2OS4yNTQuMTY5LjI1NC9sYXRlc3QvYXBpL3Rva2VuIiAtSCAiWC1hd3MtZWMyLW1ldGFkYXRhLXRva2VuLXR0bC1zZWNvbmRzOiAyMTYwMCIgMj4gL2Rldi9udWxsKQoJY3VybCAtSCAiWC1hd3MtZWMyLW1ldGFkYXRhLXRva2VuOiAkVE9LRU4iIGh0dHA6Ly8xNjkuMjU0LjE2OS4yNTQvJDEgMj4gL2Rldi9udWxsCgllY2hvICIiCn0KCmZ1bmN0aW9uIHVzZXJkYXRhIHsKCWltZHMgbGF0ZXN0L3VzZXItZGF0YQp9CgpmdW5jdGlvbiBpbnN0YW5jZWlkIHsKCWltZHMgbGF0ZXN0L21ldGEtZGF0YS9pbnN0YW5jZS1pZAp9Cg==" 
echo $BASHRC | base64 -d >> /home/admin/.bashrc
echo $BASHRC | base64 -d >> /root/.bashrc

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y iptables
apt-get install -y iperf3
apt-get install -y net-tools
apt-get install -y tcpdump
apt-get install -y htop
apt-get install -y whois
apt-get install -y bind9-dnsutils
apt-get install -y tmux
apt-get install -y netcat-traditional
touch /root/userdata_finished
touch /home/admin/userdata_finished
`))

}

func validateRun(cargs cliArgs) bool {
	if len(cargs.rampages) > 0 {
		fmt.Println("rampages cannot be used with run")
		return false
	}
	return true
}

func runModule(cargs cliArgs) {
	keyName := "ec2go"
	var sgName string = "ec2go"
	distro := "debian"
	var launchinstance bool = true
	var instanceType string
	if len(cargs.instanceTypes) == 1 {
		instanceType = cargs.instanceTypes[0]
	} else {
		if getArch() == "x86_64" {
			instanceType = "t3.micro"
		} else {
			instanceType = "t4g.micro"
		}
	}

	if len(cargs.distros) > 1 {
		log.Fatal("Only 1 distribution can be selected")
	} else if len(cargs.distros) == 1 {
		distro = cargs.distros[0]
	}

	// may revert later delete me?
	//if distro != "windows" {
	//	keyName = "default-key"
	//} else {
	//	keyName = "ec2go"
	//}

	ami := ""

	if distro == "debian" {
		if len(cargs.versions) == 0 {
			ami = getDebianId("12")
		} else {
			ami = getDebianId(cargs.versions[0])
		}
	} else if distro == "core" {
		if len(cargs.versions) == 0 {
			ami = getWindowsCoreId("2022")
		} else {
			ami = getWindowsCoreId(cargs.versions[0])
		}
	} else if distro == "windows" {
		if len(cargs.versions) == 0 {
			ami = getWindowsId("2022")
		} else {
			ami = getWindowsId(cargs.versions[0])
		}
	}
	if launchinstance {
		createSecurityGroup(sgName)
		uploadKey(keyName)
		imageid := ami
		instanceId := runInstance(imageid, keyName, getSecurityGroupId(sgName), instanceType)
		if len(cargs.admin_roles) > 0 {
			fmt.Println("sleeping for 5 seconds to allow instance to reach running state before attaching instance profile.")
			time.Sleep(time.Second * 5)
		}
		connectToInstance(instanceId)
		println(instanceId)
	}
}

func getWindowsCoreId(version string) string {
	fmt.Println(version)
	if version == "" {
		version = "2022"
	}
	searchString := "Windows_Server-" + version + "-English-Core-Base*"
	//    "Name": "Windows_Server-2016-English-Full-Base-2024.12.13",
	//    "Name": "Windows_Server-2022-English-Full-Base-2024.12.13",
	fmt.Println("search string = ", searchString)

	images, err := client.DescribeImages(context.TODO(), &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{searchString},
			},
			{
				Name:   aws.String("architecture"),
				Values: []string{"x86_64"},
			},
			//{
			//	Name:   aws.String("description"),
			//	Values: []string{"Microsoft Windows Server " + version + " Full Locale English AMI provided by Amazon"},
			//},
		},
		IncludeDeprecated: boolPointer(true),
	})

	if err != nil {
		log.Fatal(err)
	}

	sort.Slice(images.Images, func(i, j int) bool {
		return *images.Images[i].CreationDate > *images.Images[j].CreationDate
	})
	return *images.Images[0].ImageId
}

func getWindowsId(version string) string {
	fmt.Println(version)
	if version == "" {
		version = "2022"
	}
	searchString := "Windows_Server-" + version + "-English-Full-Base*"
	//    "Name": "Windows_Server-2016-English-Full-Base-2024.12.13",
	//    "Name": "Windows_Server-2022-English-Full-Base-2024.12.13",
	fmt.Println("search string = ", searchString)

	images, err := client.DescribeImages(context.TODO(), &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{searchString},
			},
			{
				Name:   aws.String("architecture"),
				Values: []string{getArch()},
			},
			//{
			//	Name:   aws.String("description"),
			//	Values: []string{"Microsoft Windows Server " + version + " Full Locale English AMI provided by Amazon"},
			//},
		},
		IncludeDeprecated: boolPointer(true),
	})

	if err != nil {
		log.Fatal(err)
	}

	sort.Slice(images.Images, func(i, j int) bool {
		return *images.Images[i].CreationDate > *images.Images[j].CreationDate
	})
	return *images.Images[0].ImageId
}

func getArch() string {
	arch := ""
	if len(cargs.arch) == 0 {
		arch = "x86_64"
	} else if cargs.arch[0] == "x86_64" || cargs.arch[0] == "x86" {
		arch = "x86_64"
	} else if cargs.arch[0] == "arm" || cargs.arch[0] == "arm64" {
		arch = "arm64"
	} else {
		log.Fatal("incorrect architecure")
		return "DOH"
	}
	return arch
}

func getDebianId(version string) string {
	searchString := ""
	if getArch() == "x86_64" {
		searchString = fmt.Sprintf("debian-%s-%s*", version, "amd64")
	} else {
		searchString = fmt.Sprintf("debian-%s-%s*", version, getArch())
	}
	//fmt.Println("search string = ", searchString)
	images, err := client.DescribeImages(context.TODO(), &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{searchString},
			},
			{
				Name:   aws.String("architecture"),
				Values: []string{getArch()},
			},
		},
		IncludeDeprecated: boolPointer(true),
	})

	if err != nil {
		log.Fatal(err)
	}

	sort.Slice(images.Images, func(i, j int) bool {
		return *images.Images[i].CreationDate > *images.Images[j].CreationDate
	})

	imageIndex := 0
	imageFound := false
	for i := 0; i < len(*&images.Images); i++ {
		if *&images.Images[i].ProductCodes == nil {
			//reg := fmt.Sprintf("^debian-%s-%s-\\d", version, getArch())
			reg := ""
			if getArch() == "x86_64" {
				reg = fmt.Sprintf("debian-%s-%s-\\d", version, "amd64")
			} else {
				reg = fmt.Sprintf("debian-%s-%s-\\d", version, getArch())
			}

			imagename := **&images.Images[i].Name
			//fmt.Println("image name regex = ", reg)
			match, _ := regexp.Match(reg,
				[]byte(**&images.Images[i].Name),
			)
			if match {
				fmt.Println("search = '", reg, "' string = '", **&images.Images[i].Name, "'")
				fmt.Println("MATCHED !!!!!")
				imageIndex = i
				imageFound = true
				break
			} else {
				fmt.Println("reg = ", reg)
				fmt.Println("imagename = ", imagename)
			}
		}
	}
	if !imageFound {
		log.Fatalln("No valid image found")
	}
	fmt.Println("Debian image index = ", imageIndex)
	return *images.Images[imageIndex].ImageId
}

func runInstance(ami string, keyName string, sgid string, instanceType string) string {
	fmt.Println("Launching instance with ami", ami)
	if cargs.distros[0] == "core" {
		cargs.distros[0] = "windows"
	}

	tagspec := types.TagSpecification{
		ResourceType: "instance",
		Tags: []types.Tag{
			{
				Key:   aws.String("purpose"),
				Value: aws.String("qec2"),
			},
			{
				Key:   aws.String("distribution"),
				Value: aws.String(cargs.distros[0]),
			},
			{
				Key:   aws.String("ec2go"),
				Value: aws.String("ec2go"),
			},
		},
	}

	//if tagspec.Tags[1].Value == "core" {
	//	tagspec.Tags[1].Value == "windows"
	//}

	userdata := getUserData()

	fmt.Println("time to runinstance = ", time.Now().Unix()-starttime)
	output, err := client.RunInstances(
		context.TODO(),
		&ec2.RunInstancesInput{
			ImageId:           aws.String(ami),
			InstanceType:      types.InstanceType(instanceType),
			MaxCount:          aws.Int32(1),
			MinCount:          aws.Int32(1),
			TagSpecifications: []types.TagSpecification{tagspec},
			KeyName:           aws.String(keyName),
			SecurityGroupIds:  []string{sgid},
			UserData:          &userdata,
			//	InstanceMarketOptions: &types.InstanceMarketOptionsRequest{
			//	MarketType: "on-demand",
			//},
		},
	)

	if err != nil {
		log.Fatal(err)
	}

	return *output.Instances[0].InstanceId
}

func uploadKey(keyName string) {
	keyFile := "/.ssh/ec2go.pub"
	if len(cargs.distros) > 0 {
		if cargs.distros[0] == "windows" {
			keyFile = "/.ssh/ec2go.pub"
		}
	}
	if !checkForDefaultKey(keyName) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("could not obtain home directory", err)
		}
		contents, err := os.ReadFile(homeDir + keyFile)
		if err != nil {
			log.Fatal("error reading users public ssh key. Key name", keyName, err, "\nTo Generate a key run \"ssh-keygen -t rsa -m pem -f ~/.ssh/ec2go\"")
		}
		_, importErr := client.ImportKeyPair(context.TODO(), &ec2.ImportKeyPairInput{
			KeyName:           aws.String(keyName),
			PublicKeyMaterial: contents,
		})
		if importErr != nil {
			log.Fatal("error uploading users public ssh key", importErr)
		}
	}
}
