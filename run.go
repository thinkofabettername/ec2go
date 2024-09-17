package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"log"
	"sort"
)

func runUsage() {
	fmt.Println(`Usage: ec2go run -i <instance type> -r <region>`)
}

func getUserData() string {
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
	keyName := ""
	var sgName string = "ec2go"
	distro := "debian"
	var launchinstance bool = true
	var instanceType string
	if len(cargs.instanceTypes) == 1 {
		instanceType = cargs.instanceTypes[0]
	} else {
		instanceType = "t3.micro"
	}

	if len(cargs.distros) > 1 {
		log.Fatal("Only 1 distribution can be selected")
	} else if len(cargs.distros) == 1 {
		distro = cargs.distros[0]
	}

	if distro != "windows" {
		keyName = "default-key"
	} else {
		keyName = "ec2go"
	}

	ami := ""

	if distro == "debian" {
		ami = getDebianId("12")
	} else if distro == "windows" || distro == "winderz" {
		ami = getWindowsId("2022")
		fmt.Println(ami)
	}
	if launchinstance {
		createSecurityGroup(sgName)
		uploadKey(keyName)
		imageid := ami
		instanceId := runInstance(imageid, keyName, getSecurityGroupId(sgName), instanceType)
		connectToInstance(instanceId)
		println(instanceId)
	}
}

func getWindowsId(version string) string {
	fmt.Println(version)
	if version == "" {
		version = "2022"
	}
	searchString := "Windows_Server-" + version + "-English-Full-Base*"

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
			{
				Name:   aws.String("description"),
				Values: []string{"Microsoft Windows Server " + version + " Full Locale English AMI provided by Amazon"},
			},
			//{
			//	Name:   aws.String("ImageLocation"),
			//	Values: []string{"amazon*"},
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

func getDebianId(version string) string {
	images, err := client.DescribeImages(context.TODO(), &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{fmt.Sprintf("*debian-%s-amd64*", version)},
			},
			{
				Name:   aws.String("architecture"),
				Values: []string{"x86_64"},
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

	return *images.Images[0].ImageId
}
