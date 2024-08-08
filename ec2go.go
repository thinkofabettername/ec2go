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
	//"github.com/aws/aws-sdk-go-v2/internal/configsources"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws/smithy-go"
)

// globals
func main() {
	keyname := "default-key"
	var sgName string = "ec2go"

	var launchinstance bool = true

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	client := ec2.NewFromConfig(cfg)

	if launchinstance {
		createSecurityGroup(sgName, client)
		uploadKey(keyname, client)
		imageid := getDebianId(client, "12")
		instanceId := runInstance(imageid, keyname, getSecurityGroupId(sgName, client), client)
		connectToInstance(instanceId, client)
		println(instanceId)
	}
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

func connectToInstance(instanceId string, client *ec2.Client) {
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

	cmd := exec.Command("ssh", "-l", "admin", ip)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run() // add error checking

	if err != nil {
		log.Fatalln("ssh failed")
	}
	fmt.Println("After SSH")
}

func boolPointer(b bool) *bool {
	return &b
}

func getDebianId(client *ec2.Client, version string) string {
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

func getSecurityGroupId(sgName string, client *ec2.Client) string {
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

func createSecurityGroup(sgName string, client *ec2.Client) {
	var sgid string = getSecurityGroupId(sgName, client)

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

func checkForDefaultKey(keyName string, client *ec2.Client) bool {
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

func uploadKey(keyName string, client *ec2.Client) {
	if !checkForDefaultKey(keyName, client) {
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

func runInstance(ami string, keyName string, sgid string, client *ec2.Client) string {
	fmt.Println("Launching instance with ami ", ami)

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
