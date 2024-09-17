package main

// test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws/smithy-go"
)

// globals
var client *ec2.Client
var tagKey string = "ec2go"
var cargs cliArgs
var starttime = time.Now().Unix()

var validModules []string = []string{
	"run",
	"terminate",
	"list",
	"connect",
}

type ec2goListInstancesInterface struct {
	silent bool
}

type cliArgs struct {
	modules       []string
	rampages      []string
	instanceTypes []string
	regions       []string
	helps         []string
	distros       []string
}

func main() {

	cargs = handleArgs()

	if len(cargs.regions) == 1 {
		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cargs.regions[0]))
		if err != nil {
			log.Fatal(err)
		}
		client = ec2.NewFromConfig(cfg)

	} else {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		client = ec2.NewFromConfig(cfg)
	}

	if cargs.modules[0] == "run" {
		runModule(cargs)
	} else if cargs.modules[0] == "connect" {
		connectModule()
	} else if cargs.modules[0] == "terminate" {
		terminateModule()
	} else if cargs.modules[0] == "list" {
		listModule()
	}
}

func validateRun(cargs cliArgs) bool {
	if len(cargs.rampages) > 0 {
		fmt.Println("rampages cannot be used with run")
		return false
	}
	return true
}

func validateArgs(cargs cliArgs) bool {
	if len(cargs.modules) == 0 {
		fmt.Println("At least 1 module should be selected.")
		return false
	}
	if len(cargs.modules) != 1 {
		fmt.Println("Only 1 module should be selected.")
		return false
	}
	if len(cargs.rampages) > 1 {
		fmt.Println("Only 1 rampage type should be selected.")
		return false
	}
	if len(cargs.regions) > 1 {
		fmt.Println("Only 1 region type should be selected.")
		return false
	}
	if len(cargs.instanceTypes) > 1 {
		fmt.Println("Only 1 instance type should be selected.")
		return false
	}

	if cargs.modules[0] == "run" {
		if !validateRun(cargs) {
			return false
		}
	} else if cargs.modules[0] == "terminate" {
		if !validateTerminate(cargs) {
			return false
		}
	}

	return true
}

func handleArgs() cliArgs {
	var cargs cliArgs
	args := os.Args[:]

	if len(os.Args) == 1 {
		cargs.modules = append(cargs.modules, "run")
	} else if stringIn(args[1], validModules) {
		cargs.modules = append(cargs.modules, args[1])
		args = args[2:]
	} else {
		log.Println("Invalid module")
	}

	for {
		if len(args) <= 0 {
			break
		}
		if stringIn(args[0], validModules) {
			cargs.modules = append(cargs.modules, args[0])
		} else if args[0] == "-d" {
			if len(args) < 2 {
				log.Fatalln("Argument must be specified after -d")
			}
			cargs.distros = append(cargs.distros, args[1])
			args = args[1:]
			fmt.Println("setting distribution")
		} else if args[0] == "-i" {
			if len(args) < 2 {
				log.Fatalln("Argument must be specified after -i")
			}
			cargs.instanceTypes = append(cargs.instanceTypes, args[1])
			args = args[1:]
			fmt.Println("setting instance type")
		} else if args[0] == "-r" {
			if len(args) < 2 {
				log.Fatalln("Argument must be specified after -r")
			}
			cargs.regions = append(cargs.regions, args[1])
			args = args[1:]
			fmt.Println("setting region")
		} else if stringIn(args[0], []string{"--rampage", "--RAMPAGE"}) {
			cargs.rampages = append(cargs.rampages, args[0])
		} else if stringIn(args[0], []string{"-h", "--help"}) {

		}
		args = args[1:]
	}
	if len(cargs.modules) > 1 {
		fmt.Println("More than one module selected")
		mainUsage()
	}

	if !validateArgs(cargs) {
		fmt.Println("Invalid arguments")
		mainUsage()
		os.Exit(1)
	}

	if len(cargs.distros) == 0 {
		cargs.distros = append(cargs.distros, "debian")
	}

	return cargs
}

func connectModule() {
	instances := listInstances()
	var instanceid int
	scanned, err := fmt.Scan(&instanceid)
	if scanned != 1 || err != nil || instanceid < 0 || instanceid > len(instances.Reservations) {
		log.Fatal("incorrect instance selection. Please enter id (0...n) of instance")
	}
	connectInstanceId := instances.Reservations[instanceid].Instances[0].InstanceId

	connectToInstance(*connectInstanceId)

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

func mainUsage() {
	fmt.Print("Usage: ec2go <module>\nmodules:\n")
	for _, m := range validModules {
		fmt.Println("    ", m)
	}
	fmt.Print("\n")
}

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

func waitForSocket(host string, port string) {

	for i := 0; i < 120; i++ {
		tcpServer, err := net.ResolveTCPAddr("tcp", host+":"+port)

		if err != nil {
			fmt.Println(err)
		}

		conn, err := net.DialTCP("tcp", nil, tcpServer)
		if err != nil {
			fmt.Println("dial error ", err)
			fmt.Println(host, port)
			time.Sleep(time.Duration(time.Second * 1))
			continue
		}
		conn.Close()
		break
	}
}

func encryptPass(pass string) string {
	cmd := exec.Command("remmina", "--encrypt-password")
	var out bytes.Buffer
	var in bytes.Buffer = *bytes.NewBuffer([]byte(pass))
	var error bytes.Buffer

	cmd.Stdin = &in
	cmd.Stdout = &out
	cmd.Stderr = &error
	cmd.Run()

	regex := "(?m)^Encrypted password: (.*$)"
	re := regexp.MustCompile(regex)
	match := re.Find([]byte(out.String()))
	return strings.Replace(string(match), "Encrypted password: ", "", 10)
}

func getWindowsPassword(instanceId string) string {
	fmt.Println("getting windows password")

	var passwordData *ec2.GetPasswordDataOutput
	var err error
	var attempts = 26
	var password string
	sleeptime := 10

	for attempts > 0 {
		passwordData, err = client.GetPasswordData(context.TODO(), &ec2.GetPasswordDataInput{
			InstanceId: aws.String(instanceId),
		})
		if err != nil {
			log.Fatal("coult not retrieve password data", err)
		}

		if *passwordData.PasswordData != "" {
			password = *passwordData.PasswordData
			break
		}
		time.Sleep(time.Duration(sleeptime) * time.Second)
		attempts--
		fmt.Println("This can take some time sleeping for ", sleeptime, " seconds")
	}

	cmd := exec.Command("openssl", "pkeyutl", "-decrypt", "-inkey", getHome()+"/.ssh/ec2go")
	var out bytes.Buffer
	var in bytes.Buffer
	var error bytes.Buffer
	in = *bytes.NewBuffer([]byte(password))
	passdata, err := base64.StdEncoding.DecodeString(password)
	in = *bytes.NewBuffer(passdata)

	cmd.Stdout = &out
	cmd.Stdin = &in
	cmd.Stderr = &error
	err = cmd.Run()
	if err != nil {
		fmt.Println("error is", error.String())
		log.Fatal(err)
	}

	return out.String()
}

func connectToInstance(instanceId string) {
	time.Sleep(time.Duration(time.Second * 5))
	port := "22"
	instance, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceId},
	})

	if err != nil {
		log.Fatalln(err)
	}

	ip := *instance.Reservations[0].Instances[0].PublicIpAddress

	instanceOs := "linux"

	//	fmt.Println("tags = ", *&instance.Reservations[0].Instances[0].Tags)
	for _, t := range *&instance.Reservations[0].Instances[0].Tags {
		fmt.Printf("t.key = %s, t.val = %s\n\n", *t.Key, *t.Value)
		if *t.Key == "distribution" {
			if *t.Value == "windows" {
				fmt.Println("\n\n!!! setting intsance os to windows ")
				instanceOs = "windows"
				port = "3389"
			}
		}
	}

	var winpass string
	fmt.Println("!!!instance os!!!", instanceOs)
	if instanceOs == "windows" {
		winpass = encryptPass(getWindowsPassword(instanceId))
		fmt.Println("winpass = ", winpass)

		fmt.Println("remmina", "-c", "rdp://administrator:'"+winpass+"'@"+ip)

		cmd := exec.Command("remmina", "-c", "rdp://administrator:"+winpass+"@"+ip+"")

		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Println("Attemtping to connect with remmina")
		cmd.Run()
	}
	fmt.Println("IP Address = ", ip)

	if instanceOs == "linux" {
		waitForSocket(ip, port)
		cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", "-l", "admin", ip)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run() // add error checking

		if err != nil {
			log.Fatalln("!! ssh exited with non zero status !!")
		}
	}
}

func boolPointer(b bool) *bool {
	return &b
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

func getSecurityGroupId(sgName string) string {
	sgOutput, err := client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
		GroupNames: []string{sgName},
	})

	var sgid string = ""
	var ae smithy.APIError
	if errors.As(err, &ae) {
		if ae.ErrorCode() == "InvalidGroup.NotFound" {
			fmt.Println("securitygroup not found")
			createSGOutput, err := client.CreateSecurityGroup(context.TODO(), &ec2.CreateSecurityGroupInput{
				GroupName:   aws.String(sgName),
				Description: aws.String(sgName),
			})
			if err != nil {
				log.Fatal(err)
			}
			sgid = *createSGOutput.GroupId
		}
	}

	if sgid == "" {
		sgid = *sgOutput.SecurityGroups[0].GroupId
	}
	return sgid
}

func createSecurityGroup(sgName string) {
	var sgid string = getSecurityGroupId(sgName)

	sgrOutput, err := client.DescribeSecurityGroupRules(context.TODO(), &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{sgid},
			},
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	var tcpPorts = [5]int32{22, 8080, 8000, 5201, 3389}
	for _, portNum := range tcpPorts {
		ruleFound := false
		for _, securityGroupRule := range sgrOutput.SecurityGroupRules {
			if *securityGroupRule.ToPort == portNum && *securityGroupRule.FromPort == portNum {
				ruleFound = true
			}
		}

		if ruleFound {
			continue
		}

		fmt.Println("creating rule for port ", portNum)
		output, err := client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:    aws.String(sgid),
			IpProtocol: aws.String("TCP"),
			FromPort:   &portNum,
			ToPort:     &portNum,
			CidrIp:     aws.String("0.0.0.0/0"),
		})

		if err != nil {
			log.Fatal(err)
		}

		print(*output.Return)
	}

	var pingRuleFound bool = false
	for _, rule := range sgrOutput.SecurityGroupRules {
		if *rule.FromPort == int32(8) && *rule.ToPort == int32(-1) && *rule.IpProtocol == "icmp" && *rule.CidrIpv4 == "0.0.0.0/0" {
			pingRuleFound = true
			break
		}
	}

	if !pingRuleFound {
		fp := int32(8)
		tp := int32(-1)
		pingOutput, err := client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: &sgid,
			IpPermissions: []types.IpPermission{
				types.IpPermission{
					IpProtocol: aws.String("icmp"),
					FromPort:   &fp,
					ToPort:     &tp,
					IpRanges: []types.IpRange{
						types.IpRange{
							CidrIp:      aws.String("0.0.0.0/0"),
							Description: aws.String("icmp ping"),
						},
					},
				},
			},
		})
		if err != nil {
			log.Fatal(err)
		}
		print(pingOutput.SecurityGroupRules)
	}
}

func checkForDefaultKey(keyName string) bool {
	result, err := client.DescribeKeyPairs(context.TODO(), &ec2.DescribeKeyPairsInput{
		KeyNames: []string{keyName},
	})
	if err != nil {
		fmt.Printf("Can't describe %s, uploading users public key", keyName)
		return false
	}

	if len(result.KeyPairs) > 0 {
		return true
	} else {
		log.Fatal("Key pairs length == 0 this should never happen. manual review of keys suggested")
		return false
	}
}

func uploadKey(keyName string) {
	keyFile := "/.ssh/id_rsa.pub"
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

func runInstance(ami string, keyName string, sgid string, instanceType string) string {
	fmt.Println("Launching instance with ami", ami)
	fmt.Println("cargs = ", cargs)

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

	userdata := getUserData()

	fmt.Println("time to runinstance = %d", time.Now().Unix()-starttime)
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
			InstanceMarketOptions: &types.InstanceMarketOptionsRequest{
				MarketType: "spot",
			},
		},
	)

	if err != nil {
		log.Fatal(err)
	}

	return *output.Instances[0].InstanceId
}
