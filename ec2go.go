package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws/smithy-go"
)

// globals
var userdata = base64.StdEncoding.EncodeToString([]byte(
	`#!/bin/bash
	apt-get update 
	apt-get install vim tmux -y`))

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
		runInstance(imageid, keyname, getSecurityGroupId(sgName, client), client)
	}
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

	for _, i := range images.Images {
		fmt.Printf("%s %s %s\n", *i.CreationDate, *i.ImageId, *i.Name)
	}

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

func runInstance(ami string, keyName string, sgid string, client *ec2.Client) {
	//cfg, err := config.LoadDefaultConfig(context.TODO())
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
	fmt.Println(output)
}
