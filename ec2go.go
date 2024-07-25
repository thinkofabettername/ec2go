package main

import (
	"context"
	"fmt"

	//"github.com/aws/aws-sdk-go-v2/aws"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func main() {
	runInstance("ami-00902d02d7a700776")
}

func runInstance(ami string) {
	//cfg, err := config.LoadDefaultConfig(context.TODO())
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	client := ec2.NewFromConfig(cfg)

	tagspec := types.TagSpecification{
		ResourceType: "instance",
		Tags: []types.Tag{
			types.Tag{
				Key:   aws.String("purpose"),
				Value: aws.String("qec2"),
			},
		},
	}

	output, err := client.RunInstances(
		context.TODO(),
		&ec2.RunInstancesInput{
			ImageId:           aws.String(ami),
			InstanceType:      "t2.micro",
			MaxCount:          aws.Int32(1),
			MinCount:          aws.Int32(1),
			TagSpecifications: []types.TagSpecification{tagspec},
		},
	)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(output)
}
