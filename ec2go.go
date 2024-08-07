package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws/smithy-go"
)

func main() {
	keyname := "default-key"
	var sgName string = "ec2go"

	var launchinstance bool = false

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	client := ec2.NewFromConfig(cfg)

	if launchinstance {
		createSecurityGroup(sgName, client)
		uploadKey(keyname, client)
		runInstance("ami-00902d02d7a700776", keyname, client)
	}
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

func runInstance(ami string, keyName string, client *ec2.Client) {
	//cfg, err := config.LoadDefaultConfig(context.TODO())
	tagspec := types.TagSpecification{
		ResourceType: "instance",
		Tags: []types.Tag{
			{
				Key:   aws.String("purpose"),
				Value: aws.String("qec2"),
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
		},
	)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(output)
}
