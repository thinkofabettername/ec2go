package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
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
}

func stringIn(needle string, haystack []string) bool {
	for _, h := range haystack {
		if needle == h {
			return true
		}
	}
	return false
}

func main() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	client = ec2.NewFromConfig(cfg)

	cargs := handleArgs()
	if cargs.modules[0] == "run" {
		runModule()
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

func validateTerminate(cargs cliArgs) bool {
	if len(cargs.instanceTypes) > 0 {
		fmt.Println("-i should only be used with run module")
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

func terminateInstances(instances []string) {
	result, err := client.TerminateInstances(context.TODO(), &ec2.TerminateInstancesInput{InstanceIds: instances})

	if err != nil {
		log.Fatal("terminating instances error:\n", err)
	}

	for _, instance := range result.TerminatingInstances {
		fmt.Printf("Terminating instance %s\n", *instance.InstanceId)

	}
}

func terminateModule() {
	var instances *ec2.DescribeInstancesOutput
	ec2rampage := false
	rampage := false
	if len(os.Args) == 2 {
		fmt.Printf("Please select an instance to terminate")
		instances = listInstances(ec2goListInstancesInterface{silent: false})
		var instanceToTerminate int
		fmt.Scan(&instanceToTerminate)
		fmt.Println("\"Terminating\" instance ", *instances.Reservations[instanceToTerminate].Instances[0].InstanceId)
		terminateInstances([]string{*instances.Reservations[instanceToTerminate].Instances[0].InstanceId})
	} else if len(os.Args) == 3 {
		if os.Args[2] == "--rampage" {
			fmt.Print("!!! RAMPAGE !!! - all instances (tagged with ec2go) will be terminated\n")
			instances = listInstances(ec2goListInstancesInterface{silent: true})
			ec2rampage = true
		}
		if os.Args[2] == "--RAMPAGE" {
			fmt.Print("!!! RAMPAGE !!! - all instances will be terminated\n")
			instances = listInstances(ec2goListInstancesInterface{silent: true})
			rampage = true
		}
	} else {
		log.Fatal("Error terminate modules takes no arguments or one of --rampage or --RAMPAGE")
	}

	var terminationList []string = make([]string, 0)

	if rampage {
		for _, instance := range instances.Reservations {
			if instance.Instances[0].State.Name == "running" {
				terminationList = append(terminationList, *instance.Instances[0].InstanceId)
			}
		}
	}

	if ec2rampage {
		for _, instance := range instances.Reservations {
			if instance.Instances[0].State.Name == "running" {
				isEc2go := false
				for _, t := range instance.Instances[0].Tags {
					if *t.Key == "ec2go" {
						isEc2go = true
					}
				}
				if isEc2go {
					terminationList = append(terminationList, *instance.Instances[0].InstanceId)
				}
			}
		}

	}
	if ec2rampage || rampage {
		if len(terminationList) > 0 {
			terminateInstances(terminationList)
		} else {
			fmt.Println("No instances to terminate... rampage was short")
		}
	}
}

func listInstances(options ...ec2goListInstancesInterface) *ec2.DescribeInstancesOutput {
	silent := false
	for _, o := range options {
		if o.silent {
			silent = true
		}
	}

	reservations, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	instances := make([]string, 0)
	if err != nil {
		log.Fatalln(err)
	}

	if silent == false {
		fmt.Printf("%-2s) - %-19s %-21s %-14s %s\n", "ID", "INSTANCE ID", "AMI", "STATE", "TAGGED AS EC2GO")
		for i, instance := range reservations.Reservations {
			isEc2go := "No"
			instances = append(instances, *instance.Instances[0].InstanceId)

			for _, t := range instance.Instances[0].Tags {
				if *t.Key == "ec2go" {
					isEc2go = "Yes"
				}
			}

			fmt.Printf("%2d) - %s %s %-14s %s\n",
				i,
				*instance.Instances[0].InstanceId,
				*instance.Instances[0].ImageId,
				*&instance.Instances[0].State.Name,
				isEc2go,
			)
		}
	}
	return reservations
}

func listModule() {
	listInstances()
}

func runModule() {
	keyname := "default-key"
	var sgName string = "ec2go"

	var launchinstance bool = true

	if launchinstance {
		createSecurityGroup(sgName)
		uploadKey(keyname)
		imageid := getDebianId("12")
		instanceId := runInstance(imageid, keyname, getSecurityGroupId(sgName))
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

func connectToInstance(instanceId string) {
	time.Sleep(time.Duration(time.Second * 5))
	instance, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceId},
	})

	if err != nil {
		log.Fatalln(err)
	}

	ip := *instance.Reservations[0].Instances[0].PublicIpAddress
	fmt.Println("IP Address = ", ip)

	waitForSocket(ip, "22")
	cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", "-l", "admin", ip)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run() // add error checking

	if err != nil {
		log.Fatalln("ssh failed")
	}
}

func boolPointer(b bool) *bool {
	return &b
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

	var tcpPorts = [4]int32{22, 8080, 8000, 5201}
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
	if !checkForDefaultKey(keyName) {
		contents, err := os.ReadFile("/home/michael/.ssh/id_rsa.pub")
		if err != nil {
			log.Fatal("error reading users public ssh key", err)
		}

		output, importErr := client.ImportKeyPair(context.TODO(), &ec2.ImportKeyPairInput{
			KeyName:           aws.String(keyName),
			PublicKeyMaterial: contents,
		})

		if importErr != nil {
			log.Fatal("error uploading users public ssh key", importErr)
		}
		fmt.Print(output)
	}
}

func runInstance(ami string, keyName string, sgid string) string {
	fmt.Println("Launching instance with ami", ami)

	tagspec := types.TagSpecification{
		ResourceType: "instance",
		Tags: []types.Tag{
			{
				Key:   aws.String("purpose"),
				Value: aws.String("qec2"),
			},
			{
				Key:   aws.String("distribution"),
				Value: aws.String("debian"),
			},
			{
				Key:   aws.String("ec2go"),
				Value: aws.String("ec2go"),
			},
		},
	}

	userdata := getUserData()

	output, err := client.RunInstances(
		context.TODO(),
		&ec2.RunInstancesInput{
			ImageId:           aws.String(ami),
			InstanceType:      "t3.micro",
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
