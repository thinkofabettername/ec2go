package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func main() {
	var launchinstance bool = true
	fmt.Println("hi")
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	client := ec2.NewFromConfig(cfg)

	upload_key("default-key", client)
	if launchinstance {
		runInstance("ami-00902d02d7a700776", client)
	}
}

func check_for_default_key(keyName string, client *ec2.Client) bool {
	result, err := client.DescribeKeyPairs(context.TODO(), &ec2.DescribeKeyPairsInput{
		KeyNames: []string{"default-key"},
	})
	if err != nil {
		fmt.Println("Can't describe default-key, uploading users public key")
		return false
	}

	if len(result.KeyPairs) > 0 {
		return true
	} else {
		log.Fatal("Key pairs length == 0 this should never happen. manual review of keys suggested")
		return false
	}
}

func upload_key(keyName string, client *ec2.Client) {
	if !check_for_default_key(keyName, client) {
		contents, err := os.ReadFile("/home/michael/.ssh/id_rsa.pub")
		if err != nil {
			log.Fatal("error reading users public ssh key", err)
		}

		output, importErr := client.ImportKeyPair(context.TODO(), &ec2.ImportKeyPairInput{
			KeyName:           aws.String("default-key"),
			PublicKeyMaterial: contents,
		})

		if importErr != nil {
			log.Fatal("error uploading users public ssh key", importErr)
		}
		fmt.Print(output)
	}
}

func runInstance(ami string, client *ec2.Client) {
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
			InstanceType:      "t2.micro",
			MaxCount:          aws.Int32(1),
			MinCount:          aws.Int32(1),
			TagSpecifications: []types.TagSpecification{tagspec},
			KeyName:           aws.String("default-key"),
		},
	)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(output)
}
