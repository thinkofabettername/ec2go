package main

import (

	//"github.com/aws/aws-sdk-go-v2/aws"
	//"github.com/aws/aws-sdk-go-v2/config"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"log"
	//"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	//"github.com/aws/smithy-go"
)

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
		//fmt.Printf("%-2s) - %-19s %-21s  %-20s %-14s %s\n",
		fmt.Printf("%-2s) - %-19s %-11s  %-21s %-14s %-14s %-15s %s\n",
			"ID", "INSTANCE ID", "IP", "AMI", "STATE", "TAGGED AS EC2GO", "OS", "LAUNCH TIME")
		for i, instance := range reservations.Reservations {
			if instance.Instances[0].State.Name == "terminated" {
				continue
			}
			os := ""
			for _, t := range instance.Instances[0].Tags {
				if *t.Key == "distribution" {
					os = *t.Value
				}
			}

			isEc2go := "No"
			instances = append(instances, *instance.Instances[0].InstanceId)

			for _, t := range instance.Instances[0].Tags {
				if *t.Key == "ec2go" {
					isEc2go = "Yes"
				}
			}

			//publicIp := *&instance.Instances[0].PublicIpAddress
			var publicIp string
			if instance.Instances[0].PublicIpAddress != nil {
				publicIp = *instance.Instances[0].PublicIpAddress
			}

			//fmt.Println("publicip ", publicIp)

			fmt.Printf("%2d) - %s %12s %-13s %-14s %-15s %-15s %s\n",
				i,
				*instance.Instances[0].InstanceId,
				publicIp,
				*instance.Instances[0].ImageId,
				*&instance.Instances[0].State.Name,
				isEc2go,
				os,
				*&instance.Instances[0].LaunchTime,
			)
		}
	}
	return reservations
}

func listModule() {
	listInstances()
}
